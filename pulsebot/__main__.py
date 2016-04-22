# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from irc import (
    Bot,
    Config,
)
from treestatus import (
    TreeStatus,
    UnknownBranch,
)
from pulse_dispatch import PulseDispatcher
from pulse import PulseListener
import os


config = Config('pulsebot.cfg')

if not config.parser.has_option('pulse', 'user'):
    raise Exception('Missing configuration: pulse.user')

if not config.parser.has_option('pulse', 'password'):
    raise Exception('Missing configuration: pulse.password')

pulse = PulseListener(
    config.pulse.user,
    config.pulse.password,
    config.pulse.applabel
    if config.parser.has_option('pulse', 'applabel') else None
)

treestatus = TreeStatus(config.treestatus.server)

bot = Bot(config)

dispatcher = PulseDispatcher(bot.msg, config, pulse)

for command, where, nick in bot:
    verb, args = command[0], command[1:]
    if verb == 'status':
        if len(args) != 1:
            bot.msg(where, nick, 'Try again with "status <branch>"')
        else:
            branch = args[0]
            try:
                status = treestatus.current_status(branch)
                bot.msg(
                    where, nick,
                    '%s is %s' % (status['tree'], status['status'].upper())
                )
            except UnknownBranch:
                bot.msg(where, nick, 'Unknown branch: %s' % branch)

pulse.shutdown()
dispatcher.shutdown()
bot.shutdown()
# Sopel doesn't terminate all its threads, so kill them all
os._exit(0)
