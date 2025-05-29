# encoding: utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import unicode_literals

import requests
import traceback
import unittest
from collections import OrderedDict
from pulsebot.pulse import PulseListener
import logging


logger = logging.getLogger(__name__)


class PulseHgPushes(PulseListener):
    def __init__(self, config):
        super(PulseHgPushes, self).__init__(
            config.pulse_user,
            config.pulse_password,
            "exchange/hgpushes/v1",
            "#",
            config.pulse_applabel if config.pulse_applabel else None,
        )

    def __iter__(self):
        for message in super(PulseHgPushes, self).__iter__():
            for push in self.get_pushes_info(message):
                yield push

    @staticmethod
    def get_pushes_info(pulse_message):
        # Sanity checks
        logger.info("get_pushes_info")
        try:
            payload = pulse_message.get("payload", {})
            pushes = payload.get("pushlog_pushes")
            if not pushes:
                return
        except Exception:
            logger.exception("Failure on retrieving payload data from pulse_message")
            return

        for push in pushes:
            push_url = push.get("push_full_json_url")
            if not push_url:
                continue
            logger.info(f"get_push_info_from: {push_url}")
            try:
                for data in PulseHgPushes.get_push_info_from(push_url):
                    yield data
            except Exception:
                logger.exception(f"Failure on {push_url}")
                for line in traceback.format_exc().splitlines():
                    logger.debug(line)
                logger.debug("Message data was: %r", pulse_message)
                continue

    @staticmethod
    def get_push_info_from(push_url):
        hg_repo = push_url[: push_url.rindex("/")]
        git_repo = "https://github.com/mozilla-firefox/firefox"

        r = requests.get(push_url)
        if r.status_code != requests.codes.ok:
            # If we were not successful, try again once.
            logger.info(
                f"Failure getting {push_url} {r.status_code}...trying once more"
            )
            r = requests.get(push_url)
        if r.status_code != requests.codes.ok:
            logger.error(f"Failure getting {push_url} {r.status_code}")
            return

        data = r.json(object_pairs_hook=OrderedDict)

        for id, d in data.get("pushes", {}).items():
            id = int(id)
            push_data = dict(
                pushlog="%s/pushloghtml?startID=%d&endID=%d" % (hg_repo, id - 1, id),
                user=d.get("user"),
                changesets=[],
            )

            for i, cs in enumerate(d.get("changesets", ())):
                revlinks = [f"{hg_repo}/rev/{cs['node'][:12]}"]
                if cs["git_node"]:
                    revlinks.insert(0, f"{git_repo}/commit/{cs['git_node'][:12]}")

                desc = [line.strip() for line in cs["desc"].splitlines()]
                data = {
                    "revlinks": revlinks,
                    "desc": desc[0].strip(),
                    "author": cs["author"].split(" <")[0].strip(),
                }
                if len(cs["parents"]) > 1:
                    data["is_merge"] = True
                for line in desc:
                    if line.startswith("Source-Repo:"):
                        data["source-repo"] = line.split(" ", 1)[1]
                push_data["changesets"].append(data)

            yield push_data


class TestPushesInfo(unittest.TestCase):
    def test_pushes_info(self):
        # Not ideal: this relies on actual live data.
        results = [
            {
                "changesets": [
                    {
                        "author": "James Teh",
                        "desc": "Bug 1857116 part 1: Reinstate building of the IAccessible2 proxy dll. r=morgan",
                        "revlinks": [
                            "https://github.com/mozilla-firefox/firefox/commit/8dab41f4c61a",
                            "https://hg.mozilla.org/integration/autoland/rev/0453d4a52ea2",
                        ],
                    },
                    {
                        "author": "James Teh",
                        "desc": "Bug 1857116 part 2: Register the IAccessible2 proxy dll for automated tests on CI. "
                        "r=morgan,jmaher",
                        "revlinks": [
                            "https://github.com/mozilla-firefox/firefox/commit/f609a8a873b6",
                            "https://hg.mozilla.org/integration/autoland/rev/3c559d1189a7",
                        ],
                    },
                    {
                        "author": "James Teh",
                        "desc": "Bug 1857116 part 3: Enable browser_textSelectionContainer.js on CI. Tag it as "
                        "os_integration so it is verified when upgrading Windows on CI. r=jmaher",
                        "revlinks": [
                            "https://github.com/mozilla-firefox/firefox/commit/f0e68fd22dc6",
                            "https://hg.mozilla.org/integration/autoland/rev/b72610598081",
                        ],
                    },
                ],
                "pushlog": "https://hg.mozilla.org/integration/autoland/pushloghtml?startID=232563&endID=232564",
                "user": "jteh@mozilla.com",
            },
            {
                "changesets": [
                    {
                        "author": "Olivier Mehani",
                        "desc": "Bug 1967654 - Change line ending to Unix in _CardsSections.scss "
                        "r=reemhamz,home-newtab-reviewers",
                        "revlinks": [
                            "https://github.com/mozilla-firefox/firefox/commit/731168ede47e",
                            "https://hg.mozilla.org/integration/autoland/rev/bc4f7219b7a5",
                        ],
                    }
                ],
                "pushlog": "https://hg.mozilla.org/integration/autoland/pushloghtml?startID=232564&endID=232565",
                "user": "rhamoui@mozilla.com",
            },
        ]

        # single push

        message = {
            "payload": {
                "repo_url": "https://hg.mozilla.org/integration/autoland",
                "pushlog_pushes": [
                    {
                        "push_full_json_url": "https://hg.mozilla.org/integration/autoland/"
                        "json-pushes?version=2&full=1&startID=232564&endID=232565"
                    },
                ],
            }
        }

        pushes = list(PulseHgPushes.get_pushes_info(message))

        self.maxDiff = None
        self.assertEqual(pushes, [results[1]])

        # multiple pushes

        message = {
            "payload": {
                "repo_url": "https://hg.mozilla.org/integration/autoland",
                "pushlog_pushes": [
                    {
                        "push_full_json_url": "https://hg.mozilla.org/integration/autoland/"
                        "json-pushes?version=2&full=1&startID=232563&endID=232564"
                    },
                    {
                        "push_full_json_url": "https://hg.mozilla.org/integration/autoland/"
                        "json-pushes?version=2&full=1&startID=232564&endID=232565"
                    },
                ],
            }
        }

        pushes = list(PulseHgPushes.get_pushes_info(message))

        self.assertEqual(pushes, results)

        # push range spans multiple pushes

        message = {
            "payload": {
                "repo_url": "https://hg.mozilla.org/integration/autoland",
                "pushlog_pushes": [
                    {
                        "push_full_json_url": "https://hg.mozilla.org/integration/autoland/"
                        "json-pushes?version=2&full=1&startID=232563&endID=232565"
                    },
                ],
            }
        }

        pushes = list(PulseHgPushes.get_pushes_info(message))

        self.maxDiff = None
        self.assertEqual(pushes, results)
