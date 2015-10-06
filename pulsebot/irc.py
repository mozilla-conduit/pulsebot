# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from willie.config import Config
from willie import bot
from Queue import (
    Empty,
    Queue,
)
import threading
import os


class Willie(bot.Willie):
    def __init__(self, config, queue):
        bot.Willie.__init__(self, config)
        self._queue = queue

    def dispatch(self, pretrigger):
        if pretrigger.event == 'PRIVMSG':
            where, what = pretrigger.args

            if pretrigger.sender != pretrigger.nick:
                if ':' in what:
                    recipient, what = what.split(':', 1)
                    if recipient != self.name:
                        what = ''
                else:
                    what = ''

            what = what.strip()
            if what:
                self._queue.put(
                    (what.split(), pretrigger.sender, pretrigger.nick))

        bot.Willie.dispatch(self, pretrigger)


class Bot(object):
    def __init__(self, config):
        self._queue = Queue(42)
        self._willie = Willie(config, self._queue)

        self._thread = threading.Thread(target=self._run)
        self._thread.start()

    def _run(self):
        self._willie.run(self._willie.config.core.host,
                         int(self._willie.config.core.port))
        self._willie = None

    def __iter__(self):
        while self._willie:
            try:
                yield self._queue.get(timeout=1)
            except Empty:
                continue
            except KeyboardInterrupt:
                break

    def msg(self, where, nick, message):
        if nick and where != nick:
            message = '%s: %s' % (nick, message)
        self._willie.msg(where, message)

    def shutdown(self):
        self._willie.quit('Terminated')
        self._thread.join()
