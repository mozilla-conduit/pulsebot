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
import os


config = Config('pulsebot.cfg')

treestatus = TreeStatus(config.treestatus.server)

bot = Bot(config)

dispatcher = PulseDispatcher(bot.msg, config)

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

dispatcher.shutdown()
bot.shutdown()
