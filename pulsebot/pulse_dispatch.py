# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import re
import requests
import sys
import threading
import time
import traceback
import urlparse
import unittest
from collections import (
    defaultdict,
    OrderedDict,
)
from Queue import Queue, Empty
from pulsebot.bugzilla import (
    Bugzilla,
    BugzillaError,
)
from pulsebot.pulse_hgpushes import PulseHgPushes

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

    def __init__(self, msg, config):
        self.msg = msg
        self.config = config
        self.hgpushes = PulseHgPushes(config)
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
        for push in self.hgpushes:
            url = urlparse.urlparse(push['pushlog'])
            branch = os.path.dirname(url.path).strip('/')

            for msg in self.create_messages(push, self.max_checkins):
                for chan in self.dispatch.get(branch, set()) | \
                        self.dispatch.get('*', set()):
                    self.msg(chan, chan, "Check-in: %s" % msg)

            if self.bugzilla and branch in self.bugzilla_branches:
                for bug, info in self.munge_for_bugzilla(push):
                    self.bugzilla_queue.put((bug, info))

    @staticmethod
    def create_messages(push, max_checkins=sys.maxsize, max_bugs=5):
        max_bugs = max(1, max_bugs)
        changesets = push['changesets']
        group = ''
        group_bugs = []

        # Kind of gross
        last_desc = changesets[-1]['desc'] if changesets else ''
        merge = 'merge' in last_desc or 'Merge' in last_desc

        group_changesets = merge or len(changesets) > max_checkins

        if not merge:
            for cs in changesets:
                revlink = cs['revlink']
                desc = cs['desc']

                if group_changesets:
                    bugs = parse_bugs(desc)
                    if bugs and bugs[0] not in group_bugs:
                        group_bugs.append(bugs[0])
                else:
                    author = cs['author']
                    yield "%s - %s - %s" % (revlink, author, desc)

        if group_changesets:
            group = '%s - %d changesets' % (push['pushlog'], len(changesets))

        if merge:
            group += ' - %s' % last_desc

        if group:
            if group_bugs and not merge:
                group += ' (bug%s %s%s)' % (
                    's' if len(group_bugs) > 1 else '',
                    ', '.join(str(b) for b in group_bugs[:max_bugs]),
                    ' and %d other bug%s' % (
                        len(group_bugs) - max_bugs,
                        's' if len(group_bugs) > max_bugs + 1 else ''
                    ) if len(group_bugs) > max_bugs else ''
                )
            yield group

    @staticmethod
    def munge_for_bugzilla(push):
        info_for_bugs = defaultdict(list)

        for cs in push['changesets']:
            bugs = parse_bugs(cs['desc'])
            if bugs:
                info_for_bugs[bugs[0]].append((
                    cs['revlink'],
                    bool(BACKOUT_RE.match(cs['desc'])),
                ))

        for bug, info in info_for_bugs.iteritems():
            yield bug, info

    def bugzilla_reporter(self):
        delayed_comments = []
        def get_one():
            if delayed_comments:
                when, bug, info = delayed_comments[0]
                if when <= time.time():
                    delayed_comments.pop(0)
                    return bug, info, True
            try:
                bug, info = self.bugzilla_queue.get(timeout=1)
                return bug, info, False
            except Empty:
                return None, None, None

        while True:
            bug, info, delayed = get_one()
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
            for url, is_backout in info:
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
                        delayed_comments.append((time.time() + 600, bug, info))
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
        self.hgpushes.shutdown()
        self.reporter_thread.join()
        self.shutting_down = True
        self.bugzilla_thread.join()


class TestPulseDispatcher(unittest.TestCase):
    CHANGESETS = [{
        'author': "Ann O'nymous",
        'revlink': 'https://server/repo/rev/1234567890ab',
        'desc': 'Bug 42 - Changed something',
    }, {
        'author': "Ann O'nymous",
        'revlink': 'https://server/repo/rev/234567890abc',
        'desc': 'Fixup for bug 42 - Changed something else',
    }, {
        'author': 'Anon Ymous',
        'revlink': 'https://server/repo/rev/34567890abcd',
        'desc': 'Bug 43 - Lorem ipsum',
    }, {
        'author': 'Anon Ymous',
        'revlink': 'https://server/repo/rev/4567890abcde',
        'desc': 'Bug 43 - dolor sit amet',
    }, {
        'author': 'Anon Ymous',
        'revlink': 'https://server/repo/rev/567890abcdef',
        'desc': 'Bug 43 - consectetur adipiscing elit',
    }, {
        'author': 'Random Bystander',
        'revlink': 'https://server/repo/rev/67890abcdef0',
        'desc': 'Bug 44 - Ut enim ad minim veniam',
    }, {
        'author': 'Other Bystander',
        'revlink': 'https://server/repo/rev/7890abcdef01',
        'desc': 'Bug 45 - Excepteur sint occaecat cupidatat non proident',
    }, {
        'author': 'Sheriff',
        'revlink': 'https://server/repo/rev/890abcdef012',
        'desc': 'Merge branch into repo',
    }]

    def test_create_messages(self):
        push = {
            'pushlog': 'https://server/repo/pushloghtml?startID=1&endID=2',
            'changesets': self.CHANGESETS[:1],
        }
        result = [
            "https://server/repo/rev/1234567890ab - Ann O'nymous - "
            'Bug 42 - Changed something',
        ]
        self.assertEquals(list(PulseDispatcher.create_messages(push)), result)

        push['changesets'].append(self.CHANGESETS[1])
        result.append(
            "https://server/repo/rev/234567890abc - Ann O'nymous - "
            'Fixup for bug 42 - Changed something else',
        )
        self.assertEquals(list(PulseDispatcher.create_messages(push)), result)

        push['changesets'].extend(self.CHANGESETS[2:5])
        result.extend((
            'https://server/repo/rev/34567890abcd - Anon Ymous - '
            'Bug 43 - Lorem ipsum',
            'https://server/repo/rev/4567890abcde - Anon Ymous - '
            'Bug 43 - dolor sit amet',
            'https://server/repo/rev/567890abcdef - Anon Ymous - '
            'Bug 43 - consectetur adipiscing elit',
        ))
        self.assertEquals(list(PulseDispatcher.create_messages(push)), result)

        self.assertEquals(list(PulseDispatcher.create_messages(push, 5)), result)

        push['changesets'].append(self.CHANGESETS[5])
        self.assertEquals(list(PulseDispatcher.create_messages(push, 5)), [
            'https://server/repo/pushloghtml?startID=1&endID=2 - 6 changesets '
            '(bugs 42, 43, 44)'
        ])
        self.assertEquals(list(PulseDispatcher.create_messages(push, 5, 1)), [
            'https://server/repo/pushloghtml?startID=1&endID=2 - 6 changesets '
            '(bugs 42 and 2 other bugs)'
        ])
        self.assertEquals(list(PulseDispatcher.create_messages(push, 5, 2)), [
            'https://server/repo/pushloghtml?startID=1&endID=2 - 6 changesets '
            '(bugs 42, 43 and 1 other bug)'
        ])

        push['changesets'].append(self.CHANGESETS[6])
        self.assertEquals(list(PulseDispatcher.create_messages(push, 5)), [
            'https://server/repo/pushloghtml?startID=1&endID=2 - 7 changesets '
            '(bugs 42, 43, 44, 45)'
        ])
        self.assertEquals(list(PulseDispatcher.create_messages(push, 5, 1)), [
            'https://server/repo/pushloghtml?startID=1&endID=2 - 7 changesets '
            '(bugs 42 and 3 other bugs)'
        ])
        self.assertEquals(list(PulseDispatcher.create_messages(push, 5, 2)), [
            'https://server/repo/pushloghtml?startID=1&endID=2 - 7 changesets '
            '(bugs 42, 43 and 2 other bugs)'
        ])

        push['changesets'].append(self.CHANGESETS[7])
        self.assertEquals(list(PulseDispatcher.create_messages(push, 5)), [
            'https://server/repo/pushloghtml?startID=1&endID=2 - 8 changesets '
            '- Merge branch into repo'
        ])
        # Merges are always grouped
        self.assertEquals(list(PulseDispatcher.create_messages(push)), [
            'https://server/repo/pushloghtml?startID=1&endID=2 - 8 changesets '
            '- Merge branch into repo'
        ])

    def test_munge_for_bugzilla(self):
        push = {
            'pushlog': 'https://server/repo/pushloghtml?startID=1&endID=2',
            'changesets': self.CHANGESETS[:1],
        }
        result = {
            42: [('https://server/repo/rev/1234567890ab', False)],
        }
        self.assertEquals(dict(PulseDispatcher.munge_for_bugzilla(push)), result)

        push['changesets'].append(self.CHANGESETS[1])
        result[42].append(('https://server/repo/rev/234567890abc', False))
        self.assertEquals(dict(PulseDispatcher.munge_for_bugzilla(push)), result)

        push['changesets'].extend(self.CHANGESETS[2:5])
        result[43] = [
            ('https://server/repo/rev/34567890abcd', False),
            ('https://server/repo/rev/4567890abcde', False),
            ('https://server/repo/rev/567890abcdef', False),
        ]
        self.assertEquals(dict(PulseDispatcher.munge_for_bugzilla(push)), result)

        push['changesets'].append({
            'author': 'Sheriff',
            'revlink': 'https://server/repo/rev/90abcdef0123',
            'desc': 'Backout bug 41 for bustage',
        })
        result[41] = [
            ('https://server/repo/rev/90abcdef0123', True),
        ]
        self.assertEquals(dict(PulseDispatcher.munge_for_bugzilla(push)), result)
