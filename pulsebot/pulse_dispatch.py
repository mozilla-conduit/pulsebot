# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import re
import threading
import time
from urllib.parse import urlparse
import unittest
from collections import (
    defaultdict,
)
from queue import Queue, Empty
from pulsebot.bugzilla import (
    Bugzilla,
    BugzillaError,
)
from pulsebot.pulse_hgpushes import PulseHgPushes
from pulsebot.config import DispatchConfig


logger = logging.getLogger(__name__)

REVLINK_RE = re.compile("/rev/[^/]*$")
APPROVE_RE = re.compile(" a=(.*)")
BUG_RE = re.compile(r"""((?:bug|b=) (?:\s*\#?)(\d+)(?=\b))""", re.I | re.X)


def parse_bugs(s):
    bugs = [int(m[1]) for m in BUG_RE.findall(s)]
    return [bug for bug in bugs if bug < 100000000]


BACKOUT_RE = re.compile(r"^back(?:ed)? ?out", re.I)


class BugInfo(object):
    def __init__(self, bug, pusher):
        self.bug = bug
        self.pusher = pusher
        self.leave_open = False
        self.changesets = []
        self.uplift = False

    def add_changeset(self, cs):
        self.changesets.append(
            {
                "revlink": cs["revlink"],
                "desc": cs["desc"],
                "is_backout": bool(BACKOUT_RE.match(cs["desc"])),
            }
        )

    def __iter__(self):
        return iter(self.changesets)


class PulseDispatcher(object):
    instance = None

    def __init__(self, config):
        self.config = config
        self.hgpushes = PulseHgPushes(config)
        self.max_checkins = 10
        self.shutting_down = False
        self.backout_delay = 600

        if config.bugzilla_server and config.bugzilla_api_key:
            self.bugzilla = Bugzilla(
                config.bugzilla_server,
                config.bugzilla_api_key
            )

        if config.pulse_max_checkins:
            self.max_checkins = config.pulse_max_checkins

        if self.config.bugzilla_branches or self.config.uplift_branches:
            self.bugzilla_queue = Queue(42)
            self.bugzilla_thread = threading.Thread(
                target=self.bugzilla_reporter
            )
            self.bugzilla_thread.start()

    def change_reporter(self):
        for push in self.hgpushes:
            self.report_one_push(push)

    def report_one_push(self, push):
        url = urlparse(push["pushlog"])
        branch = os.path.dirname(url.path).strip("/")
        logger.info(f'report_one_push: {url.netloc}{url.path} {branch}')
        if branch in self.config.bugzilla_branches or branch in self.config.uplift_branches:
            for info in self.munge_for_bugzilla(push):
                if branch in self.config.bugzilla_leave_open:
                    info.leave_open = True

                # Find out changeset is approved and branch is uplift
                for cs in info.changesets:
                    match = APPROVE_RE.search(cs["desc"])
                    if match and branch in self.config.uplift_branches:
                        info.uplift = True

                self.bugzilla_queue.put(info)

    @staticmethod
    def munge_for_bugzilla(push):
        info_for_bugs = {}

        for cs in push["changesets"]:
            if cs.get("source-repo", "").startswith("https://github.com/"):
                continue
            bugs = parse_bugs(cs["desc"])
            if bugs:
                logger.info(f'bug found: {bugs[0]}')
                if bugs[0] not in info_for_bugs:
                    info_for_bugs[bugs[0]] = BugInfo(bugs[0], push["user"])
                info_for_bugs[bugs[0]].add_changeset(cs)

        for info in info_for_bugs.values():
            yield info

    @staticmethod
    def bugzilla_summary(cs):
        yield cs["revlink"]

        desc = cs["desc"]
        matches = [
            m for m in BUG_RE.finditer(desc) if int(m.group(2)) < 100000000
        ]

        match = matches[0]
        if match.start() == 0:
            desc = desc[match.end():].lstrip(" \t-,.:")
        else:
            backout = BACKOUT_RE.match(desc)
            if backout and not desc[backout.end(): match.start()].strip():
                desc = desc[: backout.end()] + desc[match.end():]
            elif (
                desc[match.start() - 1] == "("
                and desc[match.end(): match.end() + 1] == ")"
            ):
                desc = (
                    desc[: match.start() - 1].rstrip()
                    + " "
                    + desc[match.end() + 1:].lstrip()
                )

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
                comments = self.bugzilla.get_comments(info.bug)
            except BugzillaError:
                # Don't do anything on errors, such as "You are not authorized
                # to access bug #xxxxx".
                continue

            cs_to_write = []
            for cs_info in info:
                url = cs_info["revlink"]
                # Only write about a changeset if it's never been mentioned
                # at all. This makes us not emit changesets that e.g. land
                # on mozilla-inbound when they were mentioned when landing
                # on mozilla-central.
                if not any(url[-12:] in comment.get("text", "") for comment in comments):
                    cs_to_write.append(cs_info)

            if not cs_to_write:
                continue

            is_backout = all(cs["is_backout"] for cs in cs_to_write)

            def comment():
                if info.uplift:
                    for cs in cs_to_write:
                        yield cs["revlink"]
                else:
                    if is_backout:
                        if info.pusher:
                            yield "Backout by %s:" % info.pusher
                        else:
                            yield "Backout:"
                    elif info.pusher:
                        yield "Pushed by %s:" % info.pusher
                    for cs in cs_to_write:
                        for line in self.bugzilla_summary(cs):
                            yield line

            try:
                fields = ("whiteboard", "keywords", "status")
                values = self.bugzilla.get_fields(info.bug, fields)
                # Delay comments for backouts and checkin-needed in
                # whiteboard
                delay_comment = not delayed and (
                    is_backout or "checkin-needed" in values.get("whiteboard", "")
                )
                if delay_comment:
                    delayed_comments.append(
                        (time.time() + self.backout_delay, info)
                    )
                else:
                    message = "\n".join(comment())

                    # Uplift comments just need comment + uplift tag
                    if info.uplift:
                        self.bugzilla.post_comment(info.bug, text=message, comment_tags=["uplift"])
                    else:
                        kwargs = {}
                        remove_keywords = [
                            kw
                            for kw in ["checkin-needed", "checkin-needed-tb"]
                            if kw in values.get("keywords", {})
                        ]
                        if remove_keywords:
                            kwargs["keywords"] = {"remove": remove_keywords}
                        # TODO: reopen closed bugs on backout
                        if (
                            "leave-open" not in values.get("keywords", {})
                            and not is_backout
                            and not info.leave_open
                            and values.get("status", "")
                            not in ("VERIFIED", "CLOSED", "RESOLVED")
                        ):
                            kwargs["status"] = "RESOLVED"
                            kwargs["resolution"] = "FIXED"
                        if kwargs:
                            kwargs["comment"] = {"body": message}
                            self.bugzilla.update_bug(info.bug, **kwargs)
                        else:
                            self.bugzilla.post_comment(info.bug, text=message)
            except Exception:
                logger.exception(f"Failed to send comment to bug {info.bug}")

    def shutdown(self):
        self.hgpushes.shutdown()
        self.shutting_down = True
        if self.config.bugzilla_branches or self.config.uplift_branches:
            self.bugzilla_thread.join()


class TestPulseDispatcher(unittest.TestCase):
    CHANGESETS = [
        {
            "author": "Ann O'nymous",
            "revlink": "https://server/repo/rev/1234567890ab",
            "desc": "Bug 42 - Changed something",
        },
        {
            "author": "Ann O'nymous",
            "revlink": "https://server/repo/rev/234567890abc",
            "desc": "Fixup for bug 42 - Changed something else",
        },
        {
            "author": "Anon Ymous",
            "revlink": "https://server/repo/rev/34567890abcd",
            "desc": "Bug 43 - Lorem ipsum",
        },
        {
            "author": "Anon Ymous",
            "revlink": "https://server/repo/rev/4567890abcde",
            "desc": "Bug 43 - dolor sit amet",
        },
        {
            "author": "Anon Ymous",
            "revlink": "https://server/repo/rev/567890abcdef",
            "desc": "Bug 43 - consectetur adipiscing elit",
        },
        {
            "author": "Random Bystander",
            "revlink": "https://server/repo/rev/67890abcdef0",
            "desc": "Bug 44 - Ut enim ad minim veniam",
        },
        {
            "author": "Other Bystander",
            "revlink": "https://server/repo/rev/7890abcdef01",
            "desc": "Bug 45 - Excepteur sint occaecat cupidatat non proident",
        },
        {
            "author": "Sheriff",
            "revlink": "https://server/repo/rev/890abcdef012",
            "desc": "Merge branch into repo",
            "is_merge": True,
        },
        {
            "author": "Sheriff",
            "revlink": "https://server/uplift-repo/rev/ec26c420eea4",
            "desc": "Bug 46 - Excepteur sint occaecat cupidatat non proident a=someone",
        },
    ]

    def test_munge_for_bugzilla(self):
        class TestPulseDispatcher(PulseDispatcher):
            def __init__(self, push):
                self.hgpushes = [push]
                self.bugzilla = []

        def munge(push):
            dispatcher = TestPulseDispatcher(push)
            return {
                info.bug: list(info)
                for info in dispatcher.munge_for_bugzilla(push)
            }

        push = {
            "pushlog": "https://server/repo/pushloghtml?startID=1&endID=2",
            "user": "foo@bar.com",
            "changesets": self.CHANGESETS[:1],
        }
        result = {
            42: [
                {
                    "revlink": "https://server/repo/rev/1234567890ab",
                    "desc": "Bug 42 - Changed something",
                    "is_backout": False,
                }
            ],
        }
        self.assertEqual(munge(push), result)

        push["changesets"].append(self.CHANGESETS[1])
        result[42].append(
            {
                "revlink": "https://server/repo/rev/234567890abc",
                "desc": "Fixup for bug 42 - Changed something else",
                "is_backout": False,
            }
        )
        self.assertEqual(munge(push), result)

        push["changesets"].extend(self.CHANGESETS[2:5])
        result[43] = [
            {
                "revlink": "https://server/repo/rev/34567890abcd",
                "desc": "Bug 43 - Lorem ipsum",
                "is_backout": False,
            },
            {
                "revlink": "https://server/repo/rev/4567890abcde",
                "desc": "Bug 43 - dolor sit amet",
                "is_backout": False,
            },
            {
                "revlink": "https://server/repo/rev/567890abcdef",
                "desc": "Bug 43 - consectetur adipiscing elit",
                "is_backout": False,
            },
        ]
        self.assertEqual(munge(push), result)

        push["changesets"].append(
            {
                "author": "Sheriff",
                "revlink": "https://server/repo/rev/90abcdef0123",
                "desc": "Backout bug 41 for bustage",
            }
        )
        result[41] = [
            {
                "revlink": "https://server/repo/rev/90abcdef0123",
                "desc": "Backout bug 41 for bustage",
                "is_backout": True,
            },
        ]
        self.assertEqual(munge(push), result)

    def test_bugzilla_reporter(self):
        class Dummy(object):
            pass

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

            def post_comment(self, bug, **kwargs):
                comment = {
                    "text": kwargs.get("text", "")
                }
                if "comment_tags" in kwargs:
                    comment["comment_tags"] = kwargs.get("comment_tags", [])
                self.comments[bug].append(comment)

            def update_bug(self, bug, **kwargs):
                # TODO: Handle keywords and whiteboard and add a test for the
                # checkin-needed removal.
                for k, v in kwargs.items():
                    if k == "comment":
                        self.post_comment(bug, text=v["body"])
                    else:
                        self.data[bug][k] = v

            def clear(self):
                self.__init__()

        bz = TestBugzilla()

        class TestPulseDispatcher(PulseDispatcher):
            def __init__(self):
                self.config = Dummy()
                self.config.bugzilla_branches = ["repo"]
                self.config.bugzilla_leave_open = ["leave-open"]
                self.config.uplift_branches = ["uplift-repo"]
                self.shutting_down = False
                self.backout_delay = 0
                self.bugzilla = bz
                self.bugzilla_queue = Queue(42)
                self.bugzilla_thread = threading.Thread(target=self.bugzilla_reporter)
                self.bugzilla_thread.start()

            def shutdown(self):
                self.shutting_down = True
                self.bugzilla_thread.join()

        def do_push(push, leave_open=False):
            dispatcher = TestPulseDispatcher()
            if leave_open:
                push["pushlog"] = re.sub('repo', 'leave-open', push["pushlog"])
            dispatcher.report_one_push(push)
            dispatcher.bugzilla_queue.put(None)
            dispatcher.shutdown()

        push = {
            "pushlog": "https://server/repo/pushloghtml?startID=1&endID=2",
            "user": "foo@bar.com",
            "changesets": self.CHANGESETS[:1],
        }
        comments = {
            42: [{
                "text": "Pushed by foo@bar.com:\n"
                "https://server/repo/rev/1234567890ab\n"
                "Changed something"
            }],
        }
        do_push(push)
        self.assertEqual(bz.comments, comments)

        bz.clear()
        push["changesets"].append(self.CHANGESETS[1])
        comments[42][0]["text"] += (
            "\n"
            "https://server/repo/rev/234567890abc\n"
            "Fixup for bug 42 - Changed something else"
        )
        do_push(push)
        self.assertEqual(bz.comments, comments)

        bz.clear()
        push["changesets"].extend(self.CHANGESETS[2:5])
        comments[43] = [{
            "text": "Pushed by foo@bar.com:\n"
            "https://server/repo/rev/34567890abcd\n"
            "Lorem ipsum\n"
            "https://server/repo/rev/4567890abcde\n"
            "dolor sit amet\n"
            "https://server/repo/rev/567890abcdef\n"
            "consectetur adipiscing elit"
        }]
        do_push(push)
        self.assertDictEqual(bz.comments, comments)

        push["changesets"].append(
            {
                "author": "Sheriff",
                "revlink": "https://server/repo/rev/90abcdef0123",
                "desc": "Backout bug 41 for bustage",
            }
        )
        comments[41] = [{
            "text": "Backout by foo@bar.com:\n"
            "https://server/repo/rev/90abcdef0123\n"
            "Backout for bustage"
        }]
        do_push(push)
        self.assertEqual(bz.comments, comments)

        bz.clear()
        # If there is already a comment for the landed changeset, don't
        # add one ourselves.
        bz.post_comment(42, text="Landed: https://server/repo/rev/1234567890ab")
        comments = {42: bz.get_comments(42)}
        push["changesets"] = self.CHANGESETS[:1]
        do_push(push)
        self.assertEqual(bz.comments, comments)

        push["changesets"].append(self.CHANGESETS[1])
        comments[42].append({
            "text": "https://server/repo/rev/234567890abc\n"
            "Fixup for bug 42 - Changed something else"
        })
        do_push(push)
        self.assertEqual(bz.comments, comments)

        # Bug status should be updated
        bz.clear()
        do_push(push)
        self.assertEqual(
            bz.data,
            {
                42: {
                    "status": "RESOLVED",
                    "resolution": "FIXED",
                }
            },
        )

        bz.clear()
        do_push(push, leave_open=True)
        self.assertEqual(bz.data, {})

        bz.clear()
        bz.fields[42] = {"keywords": {"leave-open"}}
        do_push(push)
        self.assertEqual(bz.data, {})

        bz.clear()
        bz.fields[42] = {"status": "VERIFIED"}
        do_push(push)
        self.assertEqual(bz.data, {})

        # Test for uplift specific comment
        bz.clear()
        push = {
            "pushlog": "https://server/uplift-repo/pushloghtml?startID=1&endID=2",
            "user": "foo@bar.com",
            "changesets": self.CHANGESETS[-1:],
        }
        comments = {
            46: [{
                "text": "https://server/uplift-repo/rev/ec26c420eea4",
                "comment_tags": ["uplift"]
            }],
        }
        do_push(push)
        self.assertEqual(bz.comments, comments)

    def test_bugzilla_summary(self):
        def summary_equals(desc, summary):
            self.assertEqual(
                list(
                    PulseDispatcher.bugzilla_summary(
                        {
                            "revlink": "https://server/repo/rev/1234567890ab",
                            "desc": desc,
                        }
                    )
                ),
                [
                    "https://server/repo/rev/1234567890ab",
                    summary,
                ],
            )

        summary_equals(
            "Bug 42 - Changed something",
            "Changed something",
        )

        summary_equals(
            "Bug 42: Changed something",
            "Changed something",
        )

        summary_equals(
            "Bug 42. Changed something",
            "Changed something",
        )

        summary_equals(
            "Bug 42 (part 1) - Changed something",
            "(part 1) - Changed something",
        )

        summary_equals(
            "Bug 42, part 1 - Changed something",
            "part 1 - Changed something",
        )

        summary_equals(
            "Fixup for bug 42 - Changed something else",
            "Fixup for bug 42 - Changed something else",
        )

        summary_equals(
            "Backout bug 41 for bustage",
            "Backout for bustage",
        )

        summary_equals(
            "Backed out changeset 234567890abc (bug 41) for bustage",
            "Backed out changeset 234567890abc for bustage",
        )

    def test_dispatch(self):
        class Dummy(object):
            pass

        class TestPulseDispatcher(PulseDispatcher):
            def __init__(self, bugzilla_branches, push):
                self.max_checkins = 10
                bugzilla_branches, bugzilla_leave_open, uplift = bugzilla_branches
                self.config = Dummy()
                self.config.bugzilla_branches = bugzilla_branches
                self.config.bugzilla_leave_open = bugzilla_leave_open
                self.config.uplift_branches = uplift
                self.hgpushes = [push]
                self.bugzilla = []
                self.change_reporter()

            @property
            def bugzilla_queue(self):
                class FakeQueue(object):
                    @staticmethod
                    def put(info):
                        self.bugzilla.append(info.__dict__)

                return FakeQueue()

        def push(repo, approver=""):
            if approver:
                approver = " a=%s" % approver
            return {
                "pushlog": "https://server/%s/pushloghtml?startID=1&endID=2" % repo,
                "user": "foo@bar.com",
                "changesets": [
                    {
                        "author": "Ann O'nymous",
                        "revlink": "https://server/%s/rev/1234567890ab" % repo,
                        "desc": "Bug 42 - Changed something%s" % approver,
                    }
                ],
            }
        bugzilla_branches = ["repoa", "repob"], {}, ["uplift-repo"]
        test = TestPulseDispatcher(bugzilla_branches, push("repo"))
        self.assertEqual(test.bugzilla, [])

        test = TestPulseDispatcher(bugzilla_branches, push("repoa"))
        self.assertEqual(
            test.bugzilla,
            [
                {
                    "bug": 42,
                    "pusher": "foo@bar.com",
                    "leave_open": False,
                    "uplift": False,
                    "changesets": [
                        {
                            "desc": "Bug 42 - Changed something",
                            "is_backout": False,
                            "revlink": "https://server/repoa/rev/1234567890ab",
                        }
                    ],
                }
            ],
        )

        test = TestPulseDispatcher(bugzilla_branches, push("repob"))
        self.assertEqual(
            test.bugzilla,
            [
                {
                    "bug": 42,
                    "pusher": "foo@bar.com",
                    "leave_open": False,
                    "uplift": False,
                    "changesets": [
                        {
                            "desc": "Bug 42 - Changed something",
                            "is_backout": False,
                            "revlink": "https://server/repob/rev/1234567890ab",
                        }
                    ],
                }
            ],
        )

        # Test for uplift comment support
        test = TestPulseDispatcher(bugzilla_branches, push("uplift-repo", approver="someone"))
        self.assertEqual(
            test.bugzilla,
            [
                {
                    "bug": 42,
                    "pusher": "foo@bar.com",
                    "leave_open": False,
                    "uplift": True,
                    "changesets": [
                        {
                            "desc": "Bug 42 - Changed something a=someone",
                            "is_backout": False,
                            "revlink": "https://server/uplift-repo/rev/1234567890ab",
                        }
                    ]
                }
            ]
        )

        test = TestPulseDispatcher(bugzilla_branches, push("repoc"))
        self.assertEqual(test.bugzilla, [])

        bugzilla_branches = DispatchConfig()
        bugzilla_branches.add("repo*")
        bugzilla_branches = bugzilla_branches, {}, ["uplift-repo"]
        test = TestPulseDispatcher(bugzilla_branches, push("repo"))
        self.assertEqual(
            test.bugzilla,
            [
                {
                    "bug": 42,
                    "pusher": "foo@bar.com",
                    "leave_open": False,
                    "uplift": False,
                    "changesets": [
                        {
                            "desc": "Bug 42 - Changed something",
                            "is_backout": False,
                            "revlink": "https://server/repo/rev/1234567890ab",
                        }
                    ],
                }
            ],
        )

        test = TestPulseDispatcher(bugzilla_branches, push("repoa"))
        self.assertEqual(
            test.bugzilla,
            [
                {
                    "bug": 42,
                    "pusher": "foo@bar.com",
                    "leave_open": False,
                    "uplift": False,
                    "changesets": [
                        {
                            "desc": "Bug 42 - Changed something",
                            "is_backout": False,
                            "revlink": "https://server/repoa/rev/1234567890ab",
                        }
                    ],
                }
            ],
        )

        test = TestPulseDispatcher(bugzilla_branches, push("foo"))
        self.assertEqual(test.bugzilla, [])

        bugzilla_branches = DispatchConfig()
        bugzilla_branches.add("repo*")
        bugzilla_branches = bugzilla_branches, {"repoa"}, ["uplift-repo"]
        test = TestPulseDispatcher(bugzilla_branches, push("repo"))
        self.assertEqual(
            test.bugzilla,
            [
                {
                    "bug": 42,
                    "pusher": "foo@bar.com",
                    "leave_open": False,
                    "uplift": False,
                    "changesets": [
                        {
                            "desc": "Bug 42 - Changed something",
                            "is_backout": False,
                            "revlink": "https://server/repo/rev/1234567890ab",
                        }
                    ],
                }
            ],
        )

        test = TestPulseDispatcher(bugzilla_branches, push("repoa"))
        self.assertEqual(
            test.bugzilla,
            [
                {
                    "bug": 42,
                    "pusher": "foo@bar.com",
                    "leave_open": True,
                    "uplift": False,
                    "changesets": [
                        {
                            "desc": "Bug 42 - Changed something",
                            "is_backout": False,
                            "revlink": "https://server/repoa/rev/1234567890ab",
                        }
                    ],
                }
            ],
        )

        test = TestPulseDispatcher(bugzilla_branches, push("foo"))
        self.assertEqual(test.bugzilla, [])

        bugzilla_branches = DispatchConfig()
        bugzilla_branches.add("repo*")
        bugzilla_branches = bugzilla_branches, bugzilla_branches, bugzilla_branches
        test = TestPulseDispatcher(bugzilla_branches, push("repo"))
        self.assertEqual(
            test.bugzilla,
            [
                {
                    "bug": 42,
                    "pusher": "foo@bar.com",
                    "leave_open": True,
                    "uplift": False,
                    "changesets": [
                        {
                            "desc": "Bug 42 - Changed something",
                            "is_backout": False,
                            "revlink": "https://server/repo/rev/1234567890ab",
                        }
                    ],
                }
            ],
        )

        test = TestPulseDispatcher(bugzilla_branches, push("repoa"))
        self.assertEqual(
            test.bugzilla,
            [
                {
                    "bug": 42,
                    "pusher": "foo@bar.com",
                    "leave_open": True,
                    "uplift": False,
                    "changesets": [
                        {
                            "desc": "Bug 42 - Changed something",
                            "is_backout": False,
                            "revlink": "https://server/repoa/rev/1234567890ab",
                        }
                    ],
                }
            ],
        )

        test = TestPulseDispatcher(bugzilla_branches, push("foo"))
        self.assertEqual(test.bugzilla, [])

        test_push = push("repo")
        test_push["changesets"][0]["source-repo"] = "https://github.com/servo/servo"
        test = TestPulseDispatcher(bugzilla_branches, test_push)
        self.assertEqual(test.bugzilla, [])
