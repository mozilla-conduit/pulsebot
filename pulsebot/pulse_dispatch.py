# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import re
import requests
import threading
import time
import traceback
from collections import defaultdict
from Queue import Queue, Empty
from pulsebot.bugzilla import (
    Bugzilla,
    BugzillaError,
)

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
        for data in self.pulse:
            # Sanity checks
            try:
                payload = data.get('payload', {})
                change = payload.get('change', {})
                revlink = change.get('revlink')
                branch = change.get('branch')
                rev = change.get('rev')
                if not (revlink and branch and rev):
                    continue
            except Exception as e:
                continue
            try:
                properties = {
                    a: b for a, b, c in change.get('properties', ())
                }
            except:
                properties = {}

            change['files'] = ['...']
            if ('polled_moz_revision' in properties or
                    'polled_comm_revision' in properties or
                    'releng' not in data.get('_meta', {})
                    .get('master_name', '')):
                continue

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
                            messages.append("%s - %s - %s"
                                % (revlink, author, desc))
            except:
                self.msg(self.config.core.owner, self.config.core.owner,
                    "Failure on %s:" % pushes_url)
                for line in traceback.format_exc().splitlines():
                    self.msg(self.config.core.owner, self.config.core.owner,
                        line)
                self.msg(self.config.core.owner, self.config.core.owner,
                    "Message data was: %s" % data, 10)
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
                    self.msg(self.config.core.owner, self.config.core.owner,
                        "Failed to send comment to bug %d" % bug)

    def shutdown(self):
        self.reporter_thread.join()
        self.shutting_down = True
        self.bugzilla_thread.join()
