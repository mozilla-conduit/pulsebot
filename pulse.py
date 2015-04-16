# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import re
import requests
import socket
import threading
import traceback
import willie
from collections import defaultdict
from kombu import Exchange
from mozillapulse import consumers
from Queue import Queue, Empty

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
           (?:\s*\#?)(\d+)
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
                post_comment(bug, comment)
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

        self.auth = {
            'user': bot.config.pulse.user,
            'password': bot.config.pulse.password,
        }

        if bot.config.has_option('pulse', 'channels'):
            for chan in bot.config.pulse.get_list('channels'):
                confchan = chan[1:] if chan[0] == '#' else conf
                if bot.config.has_option('pulse', confchan):
                    for branch in bot.config.pulse.get_list(confchan):
                        self.config[branch].add(chan)

        if bot.config.has_option('pulse', 'max_checkins'):
            self.max_checkins = bot.config.pulse.max_checkins

        if not bot.config.has_option('pulse', 'applabel'):
            bot.config.add_section('pulse')
            # Let's generate a unique label for the script
            try:
                import uuid
                bot.config.pulse.applabel = 'pulsebot-%s' % uuid.uuid4()
            except:
                from datetime import datetime
                bot.config.pulse.applabel = 'pulsebot-%s' % datetime.now()

        self.applabel = bot.config.pulse.applabel

        if self.config:
            self.queue = Queue(42)
            self.reporter_thread = threading.Thread(target=self.change_reporter)
            self.listener_thread = threading.Thread(target=self.pulse_listener)
            self.reporter_thread.start()
            self.listener_thread.start()


    def change_reporter(self):
        while not self.shutting_down:
            try:
                rev, branch, revlink, data = self.queue.get(timeout=1)
            except Empty:
                continue

            repo = REVLINK_RE.sub('', revlink)
            pushes_url = '%s/json-pushes?full=1&changeset=%s' \
                % (repo, rev)
            messages = []
            urls_for_bugs = defaultdict(list)
            backouts = set()
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
                                urls_for_bugs[bugs[0]].append(revlink)
                            if BACKOUT_RE.match(desc):
                                backouts.add(revlink)

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
                try:
                    comments = '\n'.join(self.bugzilla.get_comments(bug))
                except BugzillaError:
                    # Don't do anything on errors, such as "You are not authorized
                    # to access bug #xxxxx".
                    continue

                urls_to_write = []
                for url in urls:
                    # url[5:] is a rough approximation of stripping its scheme.
                    # In practice, it's enough for the comment checking.
                    if url[5:] not in comments:
                        urls_to_write.append(url)

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
                        self.bugzilla.post_comment(bug, '\n'.join(comment()))
                    except:
                        self.bot.msg(self.bot.config.owner,
                            "Failed to send comment to bug %d" % bug)


    def pulse_listener(self):
        def got_message(data, message):
            message.ack()

            # Sanity checks
            payload = data.get('payload')
            if not payload:
                return

            change = payload.get('change')
            if not change:
                return

            revlink = change.get('revlink')
            if not revlink:
                return

            branch = change.get('branch')
            if not branch:
                return

            rev = change.get('rev')
            if not rev:
                return

            try:
                properties = { a: b for a, b, c in
                    change.get('properties', []) }
            except:
                properties = {}

            change['files'] = ['...']
            try:
                if 'polled_moz_revision' in properties or \
                        'polled_comm_revision' in properties or \
                        'releng' not in data.get('_meta', {}) \
                            .get('master_name', ''):
                    self.bot.msg(self.bot.config.owner, "Ignored %s" % revlink)
                    self.bot.msg(self.bot.config.owner,
                        "Message data was: %s" % data, 10)
                    return
            except:
                for line in traceback.format_exc().splitlines():
                    self.bot.msg(self.bot.config.owner, line)

            self.queue.put((rev, branch, revlink, data))

        while not self.shutting_down:
            # Connect to pulse
            pulse = consumers.BuildConsumer(applabel=self.applabel, **self.auth)

            # Tell pulse that you want to listen for all messages ('#' is
            # everything) and give a function to call every time there is a
            # message
            pulse.configure(topic=['change.#'], callback=got_message)

            # Manually do the work of pulse.listen() so as to be able to cleanly
            # get out of it if necessary.
            exchange = Exchange(pulse.exchange, type='topic')
            queue = pulse._create_queue(exchange, pulse.topic[0])
            consumer = pulse.connection.Consumer(queue, auto_declare=False,
                callbacks=[pulse.callback])
            consumer.queues[0].queue_declare()
            # Bind to the first key.
            consumer.queues[0].queue_bind()

            with consumer:
                while not self.shutting_down:
                    try:
                        pulse.connection.drain_events(timeout=1)
                    except socket.timeout:
                        pass
                    except Exception as e:
                        # If we failed for some other reason than the timeout,
                        # cleanup and create a new connection.
                        break

            pulse.disconnect()


    def shutdown(self):
        self.shutting_down = True
        self.reporter_thread.join()
        self.listener_thread.join()


def setup(bot):
    PulseListener.instance = PulseListener(bot)


def shutdown(bot):
    if PulseListener.instance:
        PulseListener.instance.shutdown()
        PulseListener.instance = None
