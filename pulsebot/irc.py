# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from willie.config import Config
from willie import bot
import threading
import os


class Config(Config):
    def enumerate_modules(self, show_all=False):
        d = os.path.normpath(
            os.path.join(
                os.path.dirname(__file__),
                '..'
            )
        )
        return {
            'treestatus': os.path.join(d, 'treestatus.py'),
            'pulse': os.path.join(d, 'pulse.py'),
        }


class Bot(object):
    def __init__(self):
        config = Config(
            os.path.join(os.path.expanduser('~'), '.willie', 'default.cfg'))

        self._willie = bot.Willie(config)

        self._thread = threading.Thread(target=self._run)
        self._thread.start()

    def _run(self):
        self._willie.run(self._willie.config.core.host,
                         int(self._willie.config.core.port))

    def shutdown(self):
        self._willie.quit('Terminated')
        self._thread.join()
