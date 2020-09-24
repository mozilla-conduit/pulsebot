# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import fnmatch
from collections import defaultdict
from ConfigParser import RawConfigParser


class DispatchConfig(object):
    def __init__(self, *args, **kwargs):
        self._data = defaultdict(set, *args, **kwargs)

    def get(self, key):
        result = self._data.get(key, set())
        for k, v in self._data.iteritems():
            if k == '*' or ('*' in k and fnmatch.fnmatch(key, k)):
                result |= v
        return result

    def __contains__(self, key):
        return bool(self.get(key))

    def add(self, key, value=None):
        self._data[key].add(value)


class Config(object):
    def __init__(self, filename):
        self.bugzilla_branches = DispatchConfig()
        self.bugzilla_leave_open = DispatchConfig()

        self.parser = RawConfigParser()
        self.parser.read(filename)

        if not self.parser.has_option('pulse', 'user'):
            raise Exception('Missing configuration: pulse.user')
        self.pulse_user = self.parser.get('pulse', 'user')

        if not self.parser.has_option('pulse', 'password'):
            raise Exception('Missing configuration: pulse.password')
        self.pulse_password = self.parser.get('pulse', 'password')
        if self.parser.has_option('pulse', 'applabel'):
            self.pulse_applabel = self.parser.get('pulse', 'applabel')
        if self.parser.has_option('pulse', 'applabel'):
            self.pulse_applabel = self.parser.get('pulse', 'applabel')
        if self.parser.has_option('pulse', 'max_checkins'):
            self.pulse_max_checkins = self.parser.get('pulse', 'max_checkins')

        if (self.parser.has_option('bugzilla', 'server') and
                self.parser.has_option('bugzilla', 'api_key')):
            server = self.parser.get('bugzilla', 'server')
            self.bugzilla_server = server
            self.bugzilla_api_key = self.parser.get('bugzilla', 'api_key')
            if not server.lower().startswith('https://'):
                raise Exception('bugzilla.server must be a HTTPS url')

            if self.parser.has_option('bugzilla', 'pulse'):
                for branch in self.parser.get('bugzilla', 'pulse').split(','):
                    self.bugzilla_branches.add(branch)

            if self.parser.has_option('bugzilla', 'leave_open'):
                for branch in self.parser.get('bugzilla', 'leave_open') \
                        .split(','):
                    self.bugzilla_leave_open.add(branch)


def get_input(prompt):
    """Get decoded input from the terminal (equivalent to python 3's ``input``).
    """
    if sys.version_info.major >= 3:
        return input(prompt)
    else:
        return raw_input(prompt).decode('utf8')


if __name__ == '__main__':
    import sys

    try:
        current_config = Config('pulsebot.cfg')
    except Exception:
        current_config = None
    config = Config('pulsebot.cfg.in')
    new_config = RawConfigParser()

    for section in config.parser.sections():
        new_config.add_section(section)

        for name, value in config.parser.items(section):
            if value.startswith('@') and value.endswith('@'):
                s, n = value[1:-1].split('.', 1)
                if current_config and current_config.parser.has_option(s, n):
                    value = current_config.parser.get(s, n)
                else:
                    prompt = 'Please enter a value for %s.%s: ' % (section,
                                                                   name)
                    while True:
                        sys.stderr.write(prompt)
                        value = get_input('')
                        if value:
                            break

            new_config.set(section, name, value)

    new_config.write(sys.stdout)
