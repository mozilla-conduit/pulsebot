# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import requests


class BugzillaError(Exception):
    pass


class Bugzilla(object):
    def __init__(self, server, api_key):
        self._server = server.rstrip('/')
        self._session = requests.Session()
        self._session.headers.update({'User-Agent': 'glandium/pulsebot'})
        self._session.params['api_key'] = api_key

    def get_fields(self, bug, fields):
        bug_url = '%s/rest/bug/%d?include_fields=%s' % (
            self._server,
            bug,
            '+'.join(fields),
        )
        try:
            r = self._session.get(bug_url)
            r.raise_for_status()
            bug_data = r.json()
        except Exception:
            raise BugzillaError()

        if 'error' in bug_data:
            raise BugzillaError()

        return bug_data.get('bugs', [{}])[0]

    def get_comments(self, bug):
        bug_url = '%s/rest/bug/%d/comment?include_fields=text' % (
            self._server, bug)

        try:
            r = self._session.get(bug_url)
            r.raise_for_status()
            bug_data = r.json()
        except Exception:
            raise BugzillaError()

        if 'error' in bug_data:
            raise BugzillaError()

        comments = (bug_data['bugs'].get('%d' % bug, {})
                    .get('comments', []))
        return [c.get('text', '') for c in comments]

    def post_comment(self, bug, comment):
        try:
            post_url = '%s/rest/bug/%d/comment' % (self._server, bug)
            r = self._session.post(post_url, data={
                'comment': comment,
            })
            r.raise_for_status()
        except Exception:
            raise BugzillaError()

    def update_bug(self, bug, **kwargs):
        try:
            post_url = '%s/rest/bug/%d' % (self._server, bug)
            r = self._session.put(
                post_url, data=json.dumps(kwargs),
                headers={'Content-Type': 'application/json'})
            r.raise_for_status()
        except Exception:
            raise BugzillaError()
