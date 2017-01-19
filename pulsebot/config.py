# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import fnmatch
from sopel.config import Config as SopelConfig
from collections import defaultdict


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


class Config(SopelConfig):
    def __init__(self, *args, **kwargs):
        super(Config, self).__init__(*args, **kwargs)
        self.dispatch = DispatchConfig()
        self.bugzilla_branches = DispatchConfig()
        self.bugzilla_leave_open = DispatchConfig()

        if not self.parser.has_option('core', 'enable'):
            self.core.enable = ['']

        if not self.parser.has_option('pulse', 'user'):
            raise Exception('Missing configuration: pulse.user')

        if not self.parser.has_option('pulse', 'password'):
            raise Exception('Missing configuration: pulse.password')

        if (self.parser.has_option('bugzilla', 'server') and
                self.parser.has_option('bugzilla', 'api_key')):
            server = self.bugzilla.server
            if not server.lower().startswith('https://'):
                raise Exception('bugzilla.server must be a HTTPS url')

            if self.parser.has_option('bugzilla', 'pulse'):
                for branch in self.bugzilla.get_list('pulse'):
                    self.bugzilla_branches.add(branch)

            if self.parser.has_option('bugzilla', 'leave_open'):
                for branch in self.bugzilla.get_list('leave_open'):
                    self.bugzilla_leave_open.add(branch)

        if self.parser.has_section('channels'):
            for chan, _ in self.parser.items('channels'):
                for branch in self.channels.get_list(chan):
                    self.dispatch.add(branch, '#' + chan)


if __name__ == '__main__':
    import sys
    from sopel.tools import get_input
    from ConfigParser import RawConfigParser

    try:
        current_config = Config('pulsebot.cfg')
    except:
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
