# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import re
import requests
import threading
import time
import traceback
from collections import (
    defaultdict,
    OrderedDict,
)
from Queue import Queue, Empty
from pulsebot.bugzilla import (
    Bugzilla,
    BugzillaError,
)

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


class PulseDispatcher(object):
    instance = None

    def __init__(self, msg, config, pulse):
        self.msg = msg
        self.config = config
        self.pulse = pulse
        self.dispatch = defaultdict(set)
        self.max_checkins = 10
        self.shutting_down = False

        if (config.parser.has_option('bugzilla', 'server')
                and config.parser.has_option('bugzilla', 'password')
                and config.parser.has_option('bugzilla', 'user')):
            server = config.bugzilla.server
            if not server.lower().startswith('https://'):
                raise Exception('bugzilla.server must be a HTTPS url')

            self.bugzilla = Bugzilla(server,
                                     config.bugzilla.user,
                                     config.bugzilla.password)
        else:
            self.bugzilla = None

        if config.parser.has_option('bugzilla', 'pulse'):
            self.bugzilla_branches = config.bugzilla.get_list('pulse')

        if config.parser.has_option('pulse', 'channels'):
            for chan in config.pulse.get_list('channels'):
                confchan = chan[1:] if chan[0] == '#' else chan
                if config.parser.has_option('pulse', confchan):
                    for branch in config.pulse.get_list(confchan):
                        self.dispatch[branch].add(chan)

        if config.parser.has_option('pulse', 'max_checkins'):
            self.max_checkins = config.pulse.max_checkins

        if self.dispatch:
            self.bugzilla_queue = Queue(42)
            self.reporter_thread = threading.Thread(target=self.change_reporter)
            self.bugzilla_thread = threading.Thread(target=self.bugzilla_reporter)
            self.reporter_thread.start()
            self.bugzilla_thread.start()

    def change_reporter(self):
        for message in self.pulse:
            self._change_reporter(message)

    def _change_reporter(self, pulse_message):
        # Sanity checks
        try:
            payload = pulse_message.get('payload', {})
            repo = payload.get('repo_url')
            pushes = payload.get('pushlog_pushes')
            meta = pulse_message.get('_meta', {})
            branch = meta.get('routing_key')
            if not (repo and pushes and branch):
                return
        except Exception as e:
            return

        for push in pushes:
            push_url = push.get('push_full_json_url')
            if not push_url:
                continue

            base_url, params = push_url.split('?')
            params = OrderedDict(p.split('=', 1) for p in params.split('&'))
            params = '&'.join('%s=%s' % (k, v)
                              for k, v in params.iteritems()
                              if k not in ('version', 'full'))

            messages = []
            urls_for_bugs = defaultdict(list)
            try:
                r = requests.get(push_url)
                if r.status_code == 500:
                    # If we got an error 500, try again once.
                    r = requests.get(push_url)
                if r.status_code != 200:
                    r.raise_for_status()

                data = r.json()

                for d in data.get('pushes', {}).values():
                    changesets = d['changesets']
                    group_changesets = len(changesets) > self.max_checkins
                    if group_changesets:
                        group = ('%s/pushloghtml?%s - %d changesets'
                                 % (repo, params, len(changesets)))
                        group_bugs = []

                    for cs in changesets:
                        short_node = cs['node'][:12]
                        revlink = '%s/rev/%s' \
                            % (repo, short_node)
                        desc = cs['desc'].splitlines()[0].strip()

                        for_bugzilla = (self.bugzilla and
                                        branch in self.bugzilla_branches)
                        if for_bugzilla or group_changesets:
                            bugs = parse_bugs(desc)
                        if for_bugzilla and bugs:
                            urls_for_bugs[bugs[0]].append((
                                revlink,
                                bool(BACKOUT_RE.match(desc)),
                            ))

                        if not group_changesets:
                            author = cs['author']
                            author = author.split(' <')[0].strip()
                            messages.append("%s - %s - %s"
                                % (revlink, author, desc))
                        elif bugs and bugs[0] not in group_bugs:
                            group_bugs.append(bugs[0])

                    if group_changesets:
                        # Kind of gross, but so is all the above
                        if 'merge' in desc or 'Merge' in desc:
                            group += ' - %s' % desc
                        elif group_bugs:
                            group += ' (bug%s %s%s)' % (
                                's' if len(group_bugs) > 1 else '',
                                ', '.join(str(b) for b in group_bugs[:5]),
                                ' and %d other bugs' % (len(group_bugs) - 5)
                                if len(group_bugs) > 5 else ''
                            )
                        messages.append(group)
            except:
                logger = logging.getLogger('pulsebot.dispatch')
                logger.error("Failure on %s", push_url)
                for line in traceback.format_exc().splitlines():
                    logger.debug(line)
                logger.debug("Message data was: %r", pulse_message)
                continue

            for msg in messages:
                for chan in self.dispatch.get(branch, set()) | \
                        self.dispatch.get('*', set()):
                    self.msg(chan, chan, "Check-in: %s" % msg)

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

        while True:
            bug, urls, delayed = get_one()
            if bug is None:
                if self.shutting_down:
                    break
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
                    logging.getLogger('pulsebot.buzilla').error(
                        "Failed to send comment to bug %d", bug)

    def shutdown(self):
        self.reporter_thread.join()
        self.shutting_down = True
        self.bugzilla_thread.join()
