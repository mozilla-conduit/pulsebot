# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from pulsebot.config import Config
from pulsebot.pulse_dispatch import PulseDispatcher
import logging
import logging.config

logging.config.fileConfig('logging.ini')
logger = logging.getLogger('pulsebot')
logger.propagate = False
logger.info('starting up')

config = Config()
dispatcher = PulseDispatcher(config)
dispatcher.change_reporter()
