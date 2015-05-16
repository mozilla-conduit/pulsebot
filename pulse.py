# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import re
import requests
import threading
import time
import traceback
import willie
from collections import defaultdict
from Queue import Queue, Empty
from pulsebot import pulse

# TODO: Remove debugging messages to owner.

REVLINK_RE = re.compile('/rev/[^/]*$')


# Stolen from pylib/mozautomation/mozautomation/commitparser.py from
# https://hg.mozilla.org/hgcustom/version-control-tools
BUG_RE = re.compile(
    r'''# bug followed by any sequence of numbers, or
        # a standalone sequence of numbers
         (
           (?:
             bug |
             b= |
             # a sequence of 5+ numbers preceded by whitespace
             (?=\b\#?\d{5,}) |
             # numbers at the very beginning
             ^(?=\d)
           )
           (?:\s*\#?)(\d+)(?=\b)
         )''', re.I | re.X)


def parse_bugs(s):
    bugs = [int(m[1]) for m in BUG_RE.findall(s)]
    return [bug for bug in bugs if bug < 100000000]


BACKOUT_RE = re.compile(r'^back(?:ed)? ?out', re.I)


class BugzillaError(Exception):
    pass


class Bugzilla(object):
    def __init__(self, server, login, password):
        self._server = server.rstrip('/')
        self._login = login
        self._password = password
        self._session = requests.Session()

    def get_token(self):
        try:
            r = self._session.get('%s/rest/login' % self._server, params={
                'login': self._login,
                'password': self._password
            })
            r.raise_for_status()
            r = r.json()
            return r['token']
        except:
            raise BugzillaError()

    def get_fields(self, bug, fields):
        bug_url = '%s/rest/bug/%d?include_fields=%s' % (
            self._server,
            bug,
            '+'.join(fields),
        )
        try:
            r = requests.get(bug_url)
            r.raise_for_status()
            bug_data = r.json()
        except:
            raise BugzillaError()

        if 'error' in bug_data:
            raise BugzillaError()

        return bug_data.get('bugs', [{}])[0]

    def get_comments(self, bug):
        bug_url = '%s/rest/bug/%d/comment?include_fields=text' % (
            self._server, bug)

        try:
            r = requests.get(bug_url)
            r.raise_for_status()
            bug_data = r.json()
        except:
            raise BugzillaError()

        if 'error' in bug_data:
            raise BugzillaError()

        comments = (bug_data['bugs'].get('%d' % bug, {})
                    .get('comments', []))
        return [c.get('text', '') for c in comments]

    def post_comment(self, bug, comment):
        if 'token' not in self._session.params:
            self._session.params['token'] = self.get_token()

        try:
            post_url = '%s/rest/bug/%d/comment' % (self._server, bug)
            r = self._session.post(post_url, data={
                'comment': comment,
            })
            r.raise_for_status()
        except:
            # If token expired, try again with a new one
            if r.status_code == 401:
                del self._session.params['token']
                self.post_comment(bug, comment)
            else:
                raise BugzillaError()

    def update_bug(self, bug, **kwargs):
        if 'token' not in self._session.params:
            self._session.params['token'] = self.get_token()

        try:
            post_url = '%s/rest/bug/%d' % (self._server, bug)
            r = self._session.put(
                post_url, data=json.dumps(kwargs),
                headers={'Content-Type': 'application/json'})
            r.raise_for_status()
        except:
            # If token expired, try again with a new one
            if r.status_code == 401:
                del self._session.params['token']
                self.update_bug(bug, **kwargs)
            else:
                raise BugzillaError()


class PulseListener(object):
    instance = None

    def __init__(self, bot):
        self.config = defaultdict(set)
        self.max_checkins = 10
        self.applabel = None
        self.shutting_down = False
        self.bot = bot

        if not bot.config.has_option('pulse', 'user'):
            raise Exception('Missing configuration: pulse.user')

        if not bot.config.has_option('pulse', 'password'):
            raise Exception('Missing configuration: pulse.password')

        if (bot.config.has_option('bugzilla', 'server')
                and bot.config.has_option('bugzilla', 'password')
                and bot.config.has_option('bugzilla', 'user')):
            server = bot.config.bugzilla.server
            if not server.lower().startswith('https://'):
                raise Exception('bugzilla.server must be a HTTPS url')

            self.bugzilla = Bugzilla(server,
                                     bot.config.bugzilla.user,
                                     bot.config.bugzilla.password)
        else:
            self.bugzilla = None

        if bot.config.has_option('bugzilla', 'pulse'):
            self.bugzilla_branches = bot.config.bugzilla.get_list('pulse')

        self.pulse = pulse.PulseListener(
            bot.config.pulse.user,
            bot.config.pulse.password,
            bot.config.pulse.applabel
            if bot.config.has_option('pulse', 'applabel') else None
        )

        if bot.config.has_option('pulse', 'channels'):
            for chan in bot.config.pulse.get_list('channels'):
                confchan = chan[1:] if chan[0] == '#' else conf
                if bot.config.has_option('pulse', confchan):
                    for branch in bot.config.pulse.get_list(confchan):
                        self.config[branch].add(chan)

        if bot.config.has_option('pulse', 'max_checkins'):
            self.max_checkins = bot.config.pulse.max_checkins

        if self.config:
            self.bugzilla_queue = Queue(42)
            self.reporter_thread = threading.Thread(target=self.change_reporter)
            self.bugzilla_thread = threading.Thread(target=self.bugzilla_reporter)
            self.reporter_thread.start()
            self.bugzilla_thread.start()

    def change_reporter(self):
        for rev, branch, revlink, data in self.pulse:
            repo = REVLINK_RE.sub('', revlink)
            pushes_url = '%s/json-pushes?full=1&changeset=%s' \
                % (repo, rev)
            messages = []
            urls_for_bugs = defaultdict(list)
            try:
                r = requests.get(pushes_url)
                if r.status_code == 500:
                    # If we got an error 500, try again once.
                    r = requests.get(pushes_url)
                if r.status_code != 200:
                    r.raise_for_status()

                data = r.json()

                for d in data.values():
                    changesets = d['changesets']
                    group_changesets = len(changesets) > self.max_checkins
                    if group_changesets:
                        short_rev = rev[:12]
                        messages.append('%s/pushloghtml?changeset=%s'
                            ' - %d changesets'
                            % (repo, short_rev, len(changesets)))

                    for cs in changesets:
                        short_node = cs['node'][:12]
                        revlink = '%s/rev/%s' \
                            % (repo, short_node)
                        desc = cs['desc'].splitlines()[0].strip()

                        if self.bugzilla and branch in self.bugzilla_branches:
                            bugs = parse_bugs(desc)
                            if bugs:
                                urls_for_bugs[bugs[0]].append((
                                    revlink,
                                    bool(BACKOUT_RE.match(desc)),
                                ))

                        if not group_changesets:
                            author = cs['author']
                            author = author.split(' <')[0].strip()
                            message = "%s - %s - %s" % (revlink, author, desc)
                            messages.append("%s - %s - %s"
                                % (revlink, author, desc))
            except:
                self.bot.msg(self.bot.config.owner,
                    "Failure on %s:" % pushes_url)
                for line in traceback.format_exc().splitlines():
                    self.bot.msg(self.bot.config.owner, line)
                self.bot.msg(self.bot.config.owner,
                    "Message data was: %s" % data, 10)
                continue

            for msg in messages:
                for chan in self.config.get(branch, set()) | \
                        self.config.get('*', set()):
                    self.bot.msg(chan, "Check-in: %s" % msg)

            for bug, urls in urls_for_bugs.iteritems():
                self.bugzilla_queue.put((bug, urls))

    def bugzilla_reporter(self):
        delayed_comments = []
        def get_one():
            if delayed_comments:
                when, bug, urls = delayed_comments[0]
                if when <= time.time():
                    delayed_comments.pop(0)
                    return bug, urls, True
            try:
                bug, urls = self.bugzilla_queue.get(timeout=1)
                return bug, urls, False
            except Empty:
                return None, None, None

        while not self.shutting_down:
            bug, urls, delayed = get_one()
            if bug is None:
                continue

            try:
                comments = '\n'.join(self.bugzilla.get_comments(bug))
            except BugzillaError:
                # Don't do anything on errors, such as "You are not authorized
                # to access bug #xxxxx".
                continue

            urls_to_write = []
            backouts = set()
            for url, is_backout in urls:
                # Only write about a changeset if it's never been mentioned
                # at all. This makes us not emit changesets that e.g. land
                # on mozilla-inbound when they were mentioned when landing
                # on mozilla-central.
                if url[-12:] not in comments:
                    urls_to_write.append(url)
                if is_backout:
                    backouts.add(url)

            if urls_to_write:
                def comment():
                    if all(url in backouts for url in urls_to_write):
                        yield 'Backout:'
                        for url in urls_to_write:
                            yield url
                    else:
                        for url in urls_to_write:
                            if url in backouts:
                                yield '%s (backout)' % url
                            else:
                                yield url

                try:
                    fields = ('whiteboard', 'keywords')
                    values = self.bugzilla.get_fields(bug, fields)
                    # Delay comments for backouts and checkin-needed in
                    # whiteboard
                    delay_comment = (
                        not delayed
                        and (all(url in backouts for url in urls_to_write)
                             or 'checkin-needed' in values.get('whiteboard', ''))
                    )
                    if delay_comment:
                        delayed_comments.append((time.time() + 600, bug, urls))
                    else:
                        message = '\n'.join(comment())
                        kwargs = {}
                        if 'checkin-needed' in values.get('keywords', {}):
                            kwargs['keywords'] = {
                                'remove': ['checkin-needed']
                            }
                        if kwargs:
                            kwargs['comment'] = {'body': message}
                            self.bugzilla.update_bug(bug, **kwargs)
                        else:
                            self.bugzilla.post_comment(bug, message)
                except:
                    self.bot.msg(self.bot.config.owner,
                        "Failed to send comment to bug %d" % bug)

    def shutdown(self):
        self.shutting_down = True
        self.pulse.shutdown()
        self.reporter_thread.join()
        self.bugzilla_thread.join()


def setup(bot):
    PulseListener.instance = PulseListener(bot)


def shutdown(bot):
    if PulseListener.instance:
        PulseListener.instance.shutdown()
        PulseListener.instance = None
