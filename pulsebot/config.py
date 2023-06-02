# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import fnmatch
from collections import defaultdict
import os


class DispatchConfig(object):
    def __init__(self, *args, **kwargs):
        self._data = defaultdict(set, *args, **kwargs)

    def get(self, key):
        result = self._data.get(key, set())
        for k, v in self._data.items():
            if k == "*" or ("*" in k and fnmatch.fnmatch(key, k)):
                result |= v
        return result

    def __contains__(self, key):
        return bool(self.get(key))

    def add(self, key, value=None):
        self._data[key].add(value)


class Config(object):
    def __init__(self):
        self.pulse_user = os.getenv("PULSE_USER")
        self.pulse_password = os.getenv("PULSE_PASSWORD")
        self.pulse_applabel = os.getenv("PULSE_APPLABEL")
        self.pulse_max_checkins = os.getenv("PULSE_MAX_CHECKINS")
        self.bugzilla_server = os.getenv("BUGZILLA_SERVER")
        self.bugzilla_api_key = os.getenv("BUGZILLA_API_KEY")

        self.bugzilla_branches = DispatchConfig()
        self.bugzilla_leave_open = DispatchConfig()
        self.uplift_branches = DispatchConfig()

        if not self.pulse_user:
            raise Exception("Missing configuration: pulse_user")

        if not self.pulse_password:
            raise Exception("Missing configuration: pulse_password")

        if self.bugzilla_server and self.bugzilla_api_key:
            if not self.bugzilla_server.lower().startswith("https://"):
                raise Exception("bugzilla_server must be a HTTPS url")

            if os.getenv("BUGZILLA_PULSE"):
                for branch in os.getenv("BUGZILLA_PULSE").split(","):
                    self.bugzilla_branches.add(branch)

            if os.getenv("BUGZILLA_LEAVE_OPEN"):
                for branch in os.getenv("BUGZILLA_LEAVE_OPEN").split(","):
                    self.bugzilla_leave_open.add(branch)

            if os.getenv("BUGZILLA_UPLIFT"):
                for branch in os.getenv("BUGZILLA_UPLIFT").split(","):
                    self.uplift_branches.add(branch)
