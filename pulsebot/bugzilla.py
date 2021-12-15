# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import requests
import logging


logger = logging.getLogger(__name__)


class BugzillaError(Exception):
    pass


class Bugzilla(object):
    def __init__(self, server, api_key):
        self._server = server.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "pulsebot"})
        self._session.params["api_key"] = api_key

    def get_fields(self, bug, fields):
        bug_url = "%s/rest/bug/%d?include_fields=%s" % (
            self._server,
            bug,
            ",".join(fields),
        )
        logger.info(f"get_fields: {bug_url}")
        try:
            r = self._session.get(bug_url)
            r.raise_for_status()
            bug_data = r.json()
        except Exception:
            logger.exception(
                f"Error occurred retrieving bug fields {bug_url} {r.status_code}"
            )
            raise BugzillaError()

        if "error" in bug_data:
            logger.error(
                f"Error occurred retrieving bug fields {bug_url} {bug_data['error']}"
            )
            raise BugzillaError()

        return bug_data.get("bugs", [{}])[0]

    def get_comments(self, bug):
        bug_url = "%s/rest/bug/%d/comment?include_fields=text" % (self._server, bug)

        logger.info(f"get_comments: {bug_url}")
        try:
            r = self._session.get(bug_url)
            r.raise_for_status()
            bug_data = r.json()
        except Exception:
            logger.exception(
                f"Error occurred retrieving comments for {bug_url} {r.status_code}"
            )
            raise BugzillaError()

        if "error" in bug_data:
            logger.error(
                f"Error occurred retrieving comments for {bug_url} {bug_data['error']}"
            )
            raise BugzillaError()

        comments = bug_data["bugs"].get("%d" % bug, {}).get("comments", [])
        return [c.get("text", "") for c in comments]

    def post_comment(self, bug, comment):
        try:
            post_url = "%s/rest/bug/%d/comment" % (self._server, bug)
            logger.info(f"post_comment: {post_url}")
            r = self._session.post(
                post_url,
                data={
                    "comment": comment,
                },
            )
            r.raise_for_status()
        except Exception:
            logger.exception(
                f"Error occurred posting comment to {post_url} {r.status_code}"
            )
            raise BugzillaError()

    def update_bug(self, bug, **kwargs):
        try:
            post_url = "%s/rest/bug/%d" % (self._server, bug)
            logger.info(f"update_bug: {post_url}")
            r = self._session.put(
                post_url,
                data=json.dumps(kwargs),
                headers={"Content-Type": "application/json"},
            )
            r.raise_for_status()
        except Exception:
            logging.exception(f"Error occurred updating bug {post_url} {r.status_code}")
            raise BugzillaError()
