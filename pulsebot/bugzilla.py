# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import requests
import logging


logger = logging.getLogger(__name__)


class BugzillaError(Exception):
    def __init__(self, message):
        logger.exception(message)
    pass


class Bugzilla(object):
    def __init__(self, server, api_key):
        self._server = server.rstrip("/")
        self._headers = {
            "User-Agent": "pulsebot",
            "X-Bugzilla-API-Key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _call(self, method, path, **kwargs):
        method = method.lower() or 'get'
        bug_url = f"{self._server}/{path}"
        logger.info(f"{method}: {bug_url}")
        if method not in ("get", "post", "put"):
            raise BugzillaError(f"Unknown method: {method} {bug_url}")
        r = getattr(requests, method)(bug_url, headers=self._headers, **kwargs)
        if r.status_code not in (200, 201):
            raise BugzillaError(
                f"Request Error: {method.upper()} {bug_url} {r.status_code} {r.reason} {r.text}"
            )
        return r.json()

    def _check_error(self, method, path, bug_data):
        if "error" in bug_data:
            raise BugzillaError(
                f"Data Error: {method} {self._server}/{path} {bug_data['error']}"
            )

    def get_fields(self, bug, fields):
        path = f"rest/pulsebot/bug/{bug}"
        bug_data = self._call(
            "GET", path, params={"include_fields": ",".join(fields)}
        )
        self._check_error("GET", path, bug_data)
        return bug_data.get("bugs", [{}])[0]

    def get_comments(self, bug):
        path = f"rest/pulsebot/bug/{bug}/comment"
        bug_data = self._call(
            "GET", path, params={"include_fields": "text,tags"}
        )
        self._check_error("GET", path, bug_data)
        comments = bug_data["bugs"].get("%d" % bug, {}).get("comments", [])
        results = []
        for c in comments:
            results.append({"text": c.get("text", ""), "tags": c.get("tags", [])})
        return results

    def post_comment(self, bug, **kwargs):
        kwargs["comment"] = kwargs["text"]
        self._call("POST", f"rest/pulsebot/bug/{bug}/comment", json=kwargs)

    def update_bug(self, bug, **kwargs):
        kwargs["ids"] = [bug]
        self._call("PUT", "rest/pulsebot/bug", json=kwargs)
