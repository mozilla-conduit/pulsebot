# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import re
import sys
import threading
import time
import urlparse
import unittest
from collections import (
    defaultdict,
)
from Queue import Queue, Empty
from pulsebot.bugzilla import (
    Bugzilla,
    BugzillaError,
)
from pulsebot.pulse_hgpushes import PulseHgPushes
from pulsebot.config import DispatchConfig

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


class BugInfo(object):
    def __init__(self, bug, pusher):
        self.bug = bug
        self.pusher = pusher
        self.leave_open = False
        self.changesets = []

    def add_changeset(self, cs):
        self.changesets.append({
            'revlink': cs['revlink'],
            'desc': cs['desc'],
            'is_backout': bool(BACKOUT_RE.match(cs['desc'])),
        })

    def __iter__(self):
        return iter(self.changesets)


class PulseDispatcher(object):
    instance = None

    def __init__(self, msg, config):
        self.msg = msg
        self.config = config
        self.hgpushes = PulseHgPushes(config)
        self.max_checkins = 10
        self.shutting_down = False
        self.backout_delay = 600

        if (config.parser.has_option('bugzilla', 'server') and
                config.parser.has_option('bugzilla', 'api_key')):
            self.bugzilla = Bugzilla(config.bugzilla.server,
                                     config.bugzilla.api_key)

        if config.parser.has_option('pulse', 'max_checkins'):
            self.max_checkins = config.pulse.max_checkins

        if self.config.dispatch or self.config.bugzilla_branches:
            self.reporter_thread = threading.Thread(
                target=self.change_reporter)
            self.reporter_thread.start()

        if self.config.bugzilla_branches:
            self.bugzilla_queue = Queue(42)
            self.bugzilla_thread = threading.Thread(
                target=self.bugzilla_reporter)
            self.bugzilla_thread.start()

    def change_reporter(self):
        for push in self.hgpushes:
            self.report_one_push(push)

    def report_one_push(self, push):
        url = urlparse.urlparse(push['pushlog'])
        branch = os.path.dirname(url.path).strip('/')

        channels = self.config.dispatch.get(branch)

        if channels:
            for msg in self.create_messages(push, self.max_checkins):
                for chan in channels:
                    self.msg(chan, chan, "Check-in: %s" % msg)

        if branch in self.config.bugzilla_branches:
            for info in self.munge_for_bugzilla(push):
                if branch in self.config.bugzilla_leave_open:
                    info.leave_open = True
                self.bugzilla_queue.put(info)

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
        info_for_bugs = {}

        for cs in push['changesets']:
            if cs.get('source-repo', '').startswith('https://github.com/'):
                continue
            bugs = parse_bugs(cs['desc'])
            if bugs:
                if bugs[0] not in info_for_bugs:
                    info_for_bugs[bugs[0]] = BugInfo(bugs[0], push['user'])
                info_for_bugs[bugs[0]].add_changeset(cs)

        for info in info_for_bugs.itervalues():
            yield info

    @staticmethod
    def bugzilla_summary(cs):
        yield cs['revlink']

        desc = cs['desc']
        matches = [m for m in BUG_RE.finditer(desc)
                   if int(m.group(2)) < 100000000]

        match = matches[0]
        if match.start() == 0:
            desc = desc[match.end():].lstrip(' \t-,.:')
        else:
            backout = BACKOUT_RE.match(desc)
            if backout and not desc[backout.end():match.start()].strip():
                desc = desc[:backout.end()] + desc[match.end():]
            elif (desc[match.start() - 1] == '(' and
                  desc[match.end():match.end() + 1] == ')'):
                desc = (desc[:match.start() - 1].rstrip() + ' ' +
                        desc[match.end() + 1:].lstrip())

        yield desc

    def bugzilla_reporter(self):
        delayed_comments = []

        def get_one():
            if delayed_comments:
                when, info = delayed_comments[0]
                if when <= time.time():
                    delayed_comments.pop(0)
                    return info, True
            try:
                info = self.bugzilla_queue.get(timeout=1)
                return info, False
            except Empty:
                return None, None

        while True:
            info, delayed = get_one()
            if info is None:
                if self.shutting_down:
                    break
                continue

            try:
                comments = '\n'.join(self.bugzilla.get_comments(info.bug))
            except BugzillaError:
                # Don't do anything on errors, such as "You are not authorized
                # to access bug #xxxxx".
                continue

            cs_to_write = []
            for cs_info in info:
                url = cs_info['revlink']
                # Only write about a changeset if it's never been mentioned
                # at all. This makes us not emit changesets that e.g. land
                # on mozilla-inbound when they were mentioned when landing
                # on mozilla-central.
                if url[-12:] not in comments:
                    cs_to_write.append(cs_info)

            if cs_to_write:
                is_backout = all(cs['is_backout'] for cs in cs_to_write)

                def comment():
                    if is_backout:
                        if info.pusher:
                            yield 'Backout by %s:' % info.pusher
                        else:
                            yield 'Backout:'
                    elif info.pusher:
                        yield 'Pushed by %s:' % info.pusher
                    for cs in cs_to_write:
                        for line in self.bugzilla_summary(cs):
                            yield line

                try:
                    fields = ('whiteboard', 'keywords')
                    values = self.bugzilla.get_fields(info.bug, fields)
                    # Delay comments for backouts and checkin-needed in
                    # whiteboard
                    delay_comment = (
                        not delayed and
                        (is_backout or
                         'checkin-needed' in values.get('whiteboard', ''))
                    )
                    if delay_comment:
                        delayed_comments.append(
                            (time.time() + self.backout_delay, info))
                    else:
                        message = '\n'.join(comment())
                        kwargs = {}
                        if 'checkin-needed' in values.get('keywords', {}):
                            kwargs['keywords'] = {
                                'remove': ['checkin-needed']
                            }
                        # TODO: reopen closed bugs on backout
                        if ('leave-open' not in values.get('keywords', {}) and
                                not is_backout and not info.leave_open):
                            kwargs['status'] = 'RESOLVED'
                            kwargs['resolution'] = 'FIXED'
                        if kwargs:
                            kwargs['comment'] = {'body': message}
                            self.bugzilla.update_bug(info.bug, **kwargs)
                        else:
                            self.bugzilla.post_comment(info.bug, message)
                except:
                    logging.getLogger('pulsebot.buzilla').error(
                        "Failed to send comment to bug %d", info.bug)

    def shutdown(self):
        self.hgpushes.shutdown()
        if self.config.dispatch or self.config.bugzilla_branches:
            self.reporter_thread.join()
        self.shutting_down = True
        if self.config.bugzilla_branches:
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

        self.assertEquals(list(PulseDispatcher.create_messages(push, 5)),
                          result)

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
        def munge(push):
            return {
                info.bug: list(info)
                for info in PulseDispatcher.munge_for_bugzilla(push)
            }

        push = {
            'pushlog': 'https://server/repo/pushloghtml?startID=1&endID=2',
            'user': 'foo@bar.com',
            'changesets': self.CHANGESETS[:1],
        }
        result = {
            42: [{'revlink': 'https://server/repo/rev/1234567890ab',
                  'desc': 'Bug 42 - Changed something',
                  'is_backout': False}],
        }
        self.assertEquals(munge(push), result)

        push['changesets'].append(self.CHANGESETS[1])
        result[42].append({'revlink': 'https://server/repo/rev/234567890abc',
                           'desc': 'Fixup for bug 42 - Changed something else',
                           'is_backout': False})
        self.assertEquals(munge(push), result)

        push['changesets'].extend(self.CHANGESETS[2:5])
        result[43] = [
            {'revlink': 'https://server/repo/rev/34567890abcd',
             'desc': 'Bug 43 - Lorem ipsum',
             'is_backout': False},
            {'revlink': 'https://server/repo/rev/4567890abcde',
             'desc': 'Bug 43 - dolor sit amet',
             'is_backout': False},
            {'revlink': 'https://server/repo/rev/567890abcdef',
             'desc': 'Bug 43 - consectetur adipiscing elit',
             'is_backout': False},
        ]
        self.assertEquals(munge(push), result)

        push['changesets'].append({
            'author': 'Sheriff',
            'revlink': 'https://server/repo/rev/90abcdef0123',
            'desc': 'Backout bug 41 for bustage',
        })
        result[41] = [
            {'revlink': 'https://server/repo/rev/90abcdef0123',
             'desc': 'Backout bug 41 for bustage',
             'is_backout': True},
        ]
        self.assertEquals(munge(push), result)

    def test_bugzilla_reporter(self):
        class TestBugzilla(object):
            def __init__(self):
                self.comments = defaultdict(list)
                self.fields = defaultdict(dict)
                self.data = defaultdict(dict)

            def get_comments(self, bug):
                return self.comments.get(bug, [])

            def get_fields(self, bug, fields):
                result = {}
                for field in fields:
                    data = self.fields.get(bug, {}).get(field)
                    if data:
                        result[field] = data
                return result

            def post_comment(self, bug, message):
                self.comments[bug].append(message)

            def update_bug(self, bug, **kwargs):
                # TODO: Handle keywords and whiteboard and add a test for the
                # checkin-needed removal.
                for k, v in kwargs.iteritems():
                    if k == 'comment':
                        self.post_comment(bug, v['body'])
                    else:
                        self.data[bug][k] = v

            def clear(self):
                self.__init__()

        bz = TestBugzilla()

        class TestPulseDispatcher(PulseDispatcher):
            def __init__(self):
                self.shutting_down = False
                self.backout_delay = 0
                self.bugzilla = bz
                self.bugzilla_queue = Queue(42)
                self.bugzilla_thread = threading.Thread(
                    target=self.bugzilla_reporter)
                self.bugzilla_thread.start()

            def shutdown(self):
                self.shutting_down = True
                self.bugzilla_thread.join()

        def do_push(push, leave_open=False):
            dispatcher = TestPulseDispatcher()
            try:
                for info in dispatcher.munge_for_bugzilla(push):
                    if leave_open:
                        info.leave_open = leave_open
                    dispatcher.bugzilla_queue.put(info)
            finally:
                dispatcher.bugzilla_queue.put(None)
                dispatcher.shutdown()

        push = {
            'pushlog': 'https://server/repo/pushloghtml?startID=1&endID=2',
            'user': 'foo@bar.com',
            'changesets': self.CHANGESETS[:1],
        }
        comments = {
            42: ['Pushed by foo@bar.com:\n'
                 'https://server/repo/rev/1234567890ab\n'
                 'Changed something'],
        }
        do_push(push)
        self.assertEquals(bz.comments, comments)

        bz.clear()
        push['changesets'].append(self.CHANGESETS[1])
        comments[42][0] += (
            '\n'
            'https://server/repo/rev/234567890abc\n'
            'Fixup for bug 42 - Changed something else')
        do_push(push)
        self.assertEquals(bz.comments, comments)

        bz.clear()
        push['changesets'].extend(self.CHANGESETS[2:5])
        comments[43] = [
            'Pushed by foo@bar.com:\n'
            'https://server/repo/rev/34567890abcd\n'
            'Lorem ipsum\n'
            'https://server/repo/rev/4567890abcde\n'
            'dolor sit amet\n'
            'https://server/repo/rev/567890abcdef\n'
            'consectetur adipiscing elit'
        ]
        do_push(push)
        self.assertEquals(bz.comments, comments)

        push['changesets'].append({
            'author': 'Sheriff',
            'revlink': 'https://server/repo/rev/90abcdef0123',
            'desc': 'Backout bug 41 for bustage',
        })
        comments[41] = [
            'Backout by foo@bar.com:\n'
            'https://server/repo/rev/90abcdef0123\n'
            'Backout for bustage',
        ]
        do_push(push)
        self.assertEquals(bz.comments, comments)

        bz.clear()
        # If there is already a comment for the landed changeset, don't
        # add one ourselves.
        bz.post_comment(42, 'Landed: https://server/repo/rev/1234567890ab')
        comments = {42: bz.get_comments(42)}
        push['changesets'] = self.CHANGESETS[:1]
        do_push(push)
        self.assertEquals(bz.comments, comments)

        push['changesets'].append(self.CHANGESETS[1])
        comments[42].append(
            'https://server/repo/rev/234567890abc\n'
            'Fixup for bug 42 - Changed something else')
        do_push(push)
        self.assertEquals(bz.comments, comments)

        # Bug status should be updated
        bz.clear()
        do_push(push)
        self.assertEquals(bz.data, {42: {
            'status': 'RESOLVED',
            'resolution': 'FIXED',
        }})

        bz.clear()
        do_push(push, leave_open=True)
        self.assertEquals(bz.data, {})

        bz.clear()
        bz.fields[42] = {'keywords': {'leave-open'}}
        do_push(push)
        self.assertEquals(bz.data, {})

    def test_bugzilla_summary(self):
        def summary_equals(desc, summary):
            self.assertEquals(list(PulseDispatcher.bugzilla_summary({
                'revlink': 'https://server/repo/rev/1234567890ab',
                'desc': desc,
            })), [
                'https://server/repo/rev/1234567890ab',
                summary,
            ])

        summary_equals(
            'Bug 42 - Changed something',
            'Changed something',
        )

        summary_equals(
            'Bug 42: Changed something',
            'Changed something',
        )

        summary_equals(
            'Bug 42. Changed something',
            'Changed something',
        )

        summary_equals(
            'Bug 42 (part 1) - Changed something',
            '(part 1) - Changed something',
        )

        summary_equals(
            'Bug 42, part 1 - Changed something',
            'part 1 - Changed something',
        )

        summary_equals(
            'Fixup for bug 42 - Changed something else',
            'Fixup for bug 42 - Changed something else',
        )

        summary_equals(
            'Backout bug 41 for bustage',
            'Backout for bustage',
        )

        summary_equals(
            'Backed out changeset 234567890abc (bug 41) for bustage',
            'Backed out changeset 234567890abc for bustage',
        )

    def test_dispatch(self):
        class Dummy(object):
            pass

        class TestPulseDispatcher(PulseDispatcher):
            def __init__(self, bugzilla_branches, dispatch, push):
                self.max_checkins = 10
                bugzilla_branches, bugzilla_leave_open = bugzilla_branches
                self.config = Dummy()
                self.config.bugzilla_branches = bugzilla_branches
                self.config.bugzilla_leave_open = bugzilla_leave_open
                self.config.dispatch = dispatch
                self.hgpushes = [push]
                self.irc = []
                self.bugzilla = []
                self.change_reporter()

            def msg(self, *args):
                self.irc.append(args)

            @property
            def bugzilla_queue(self):
                class FakeQueue(object):
                    @staticmethod
                    def put(info):
                        self.bugzilla.append(info.__dict__)

                return FakeQueue()

        def push(repo):
            return {
                'pushlog': 'https://server/%s/pushloghtml?startID=1&endID=2'
                % repo,
                'user': 'foo@bar.com',
                'changesets': [{
                    'author': "Ann O'nymous",
                    'revlink': 'https://server/%s/rev/1234567890ab' % repo,
                    'desc': 'Bug 42 - Changed something',
                }],
            }

        bugzilla_branches = ['repoa', 'repob'], {}
        dispatch = DispatchConfig({
            'repob': {'#chan1', '#chan2'},
            'repoc': {'#chan2', '#chan3'},
        })
        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('repo'))
        self.assertEquals(test.irc, [])
        self.assertEquals(test.bugzilla, [])

        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('repoa'))
        self.assertEquals(test.irc, [])
        self.assertEquals(test.bugzilla, [{
            'bug': 42,
            'pusher': 'foo@bar.com',
            'leave_open': False,
            'changesets': [{
                'desc': 'Bug 42 - Changed something',
                'is_backout': False,
                'revlink': 'https://server/repoa/rev/1234567890ab',
            }]
        }])

        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('repob'))
        self.assertEquals(sorted(test.irc), [
            ('#chan1', '#chan1',
             "Check-in: https://server/repob/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
            ('#chan2', '#chan2',
             "Check-in: https://server/repob/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
        ])
        self.assertEquals(test.bugzilla, [{
            'bug': 42,
            'pusher': 'foo@bar.com',
            'leave_open': False,
            'changesets': [{
                'desc': 'Bug 42 - Changed something',
                'is_backout': False,
                'revlink': 'https://server/repob/rev/1234567890ab',
            }]
        }])

        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('repoc'))
        self.assertEquals(sorted(test.irc), [
            ('#chan2', '#chan2',
             "Check-in: https://server/repoc/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
            ('#chan3', '#chan3',
             "Check-in: https://server/repoc/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
        ])
        self.assertEquals(test.bugzilla, [])

        dispatch.add('repo*', '#chan4')
        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('foo'))
        self.assertEquals(sorted(test.irc), [])

        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('repo'))
        self.assertEquals(sorted(test.irc), [
            ('#chan4', '#chan4',
             "Check-in: https://server/repo/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
        ])

        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('repob'))
        self.assertEquals(sorted(test.irc), [
            ('#chan1', '#chan1',
             "Check-in: https://server/repob/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
            ('#chan2', '#chan2',
             "Check-in: https://server/repob/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
            ('#chan4', '#chan4',
             "Check-in: https://server/repob/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
        ])

        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('repod'))
        self.assertEquals(sorted(test.irc), [
            ('#chan4', '#chan4',
             "Check-in: https://server/repod/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
        ])

        dispatch.add('*', '#chan5')
        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('foo'))
        self.assertEquals(sorted(test.irc), [
            ('#chan5', '#chan5',
             "Check-in: https://server/foo/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
        ])

        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('repo'))
        self.assertEquals(sorted(test.irc), [
            ('#chan4', '#chan4',
             "Check-in: https://server/repo/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
            ('#chan5', '#chan5',
             "Check-in: https://server/repo/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
        ])

        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('repob'))
        self.assertEquals(sorted(test.irc), [
            ('#chan1', '#chan1',
             "Check-in: https://server/repob/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
            ('#chan2', '#chan2',
             "Check-in: https://server/repob/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
            ('#chan4', '#chan4',
             "Check-in: https://server/repob/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
            ('#chan5', '#chan5',
             "Check-in: https://server/repob/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
        ])

        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('repod'))
        self.assertEquals(sorted(test.irc), [
            ('#chan4', '#chan4',
             "Check-in: https://server/repod/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
            ('#chan5', '#chan5',
             "Check-in: https://server/repod/rev/1234567890ab - "
             "Ann O'nymous - Bug 42 - Changed something"),
        ])

        bugzilla_branches = DispatchConfig()
        bugzilla_branches.add('repo*')
        bugzilla_branches = bugzilla_branches, {}
        dispatch = DispatchConfig()
        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('repo'))
        self.assertEquals(test.irc, [])
        self.assertEquals(test.bugzilla, [{
            'bug': 42,
            'pusher': 'foo@bar.com',
            'leave_open': False,
            'changesets': [{
                'desc': 'Bug 42 - Changed something',
                'is_backout': False,
                'revlink': 'https://server/repo/rev/1234567890ab',
            }]
        }])

        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('repoa'))
        self.assertEquals(test.irc, [])
        self.assertEquals(test.bugzilla, [{
            'bug': 42,
            'pusher': 'foo@bar.com',
            'leave_open': False,
            'changesets': [{
                'desc': 'Bug 42 - Changed something',
                'is_backout': False,
                'revlink': 'https://server/repoa/rev/1234567890ab',
            }]
        }])

        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('foo'))
        self.assertEquals(test.irc, [])
        self.assertEquals(test.bugzilla, [])

        bugzilla_branches = DispatchConfig()
        bugzilla_branches.add('repo*')
        bugzilla_branches = bugzilla_branches, {'repoa'}
        dispatch = DispatchConfig()
        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('repo'))
        self.assertEquals(test.irc, [])
        self.assertEquals(test.bugzilla, [{
            'bug': 42,
            'pusher': 'foo@bar.com',
            'leave_open': False,
            'changesets': [{
                'desc': 'Bug 42 - Changed something',
                'is_backout': False,
                'revlink': 'https://server/repo/rev/1234567890ab',
            }]
        }])

        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('repoa'))
        self.assertEquals(test.irc, [])
        self.assertEquals(test.bugzilla, [{
            'bug': 42,
            'pusher': 'foo@bar.com',
            'leave_open': True,
            'changesets': [{
                'desc': 'Bug 42 - Changed something',
                'is_backout': False,
                'revlink': 'https://server/repoa/rev/1234567890ab',
            }]
        }])

        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('foo'))
        self.assertEquals(test.irc, [])
        self.assertEquals(test.bugzilla, [])

        bugzilla_branches = DispatchConfig()
        bugzilla_branches.add('repo*')
        bugzilla_branches = bugzilla_branches, bugzilla_branches
        dispatch = DispatchConfig()
        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('repo'))
        self.assertEquals(test.irc, [])
        self.assertEquals(test.bugzilla, [{
            'bug': 42,
            'pusher': 'foo@bar.com',
            'leave_open': True,
            'changesets': [{
                'desc': 'Bug 42 - Changed something',
                'is_backout': False,
                'revlink': 'https://server/repo/rev/1234567890ab',
            }]
        }])

        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('repoa'))
        self.assertEquals(test.irc, [])
        self.assertEquals(test.bugzilla, [{
            'bug': 42,
            'pusher': 'foo@bar.com',
            'leave_open': True,
            'changesets': [{
                'desc': 'Bug 42 - Changed something',
                'is_backout': False,
                'revlink': 'https://server/repoa/rev/1234567890ab',
            }]
        }])

        test = TestPulseDispatcher(bugzilla_branches, dispatch, push('foo'))
        self.assertEquals(test.irc, [])
        self.assertEquals(test.bugzilla, [])

        test_push = push('repo')
        test_push['changesets'][0]['source-repo'] = \
            'https://github.com/servo/servo'
        test = TestPulseDispatcher(bugzilla_branches, dispatch, test_push)
        self.assertEquals(test.irc, [])
        self.assertEquals(test.bugzilla, [])
