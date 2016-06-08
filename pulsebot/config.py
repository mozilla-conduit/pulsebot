# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from sopel.config import Config


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
