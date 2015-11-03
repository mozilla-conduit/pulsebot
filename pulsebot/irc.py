# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from sopel.config import Config
from sopel import bot
from Queue import (
    Empty,
    Queue,
)
import threading
import os


class Sopel(bot.Sopel):
    def __init__(self, config, queue):
        bot.Sopel.__init__(self, config)
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

        bot.Sopel.dispatch(self, pretrigger)


class Bot(object):
    def __init__(self, config):
        self._queue = Queue(42)
        self._sopel = Sopel(config, self._queue)

        self._thread = threading.Thread(target=self._run)
        self._thread.start()

    def _run(self):
        self._sopel.run(self._sopel.config.core.host,
                         int(self._sopel.config.core.port))
        self._sopel = None

    def __iter__(self):
        while self._sopel:
            try:
                yield self._queue.get(timeout=1)
            except Empty:
                continue
            except KeyboardInterrupt:
                break

    def msg(self, where, nick, message, max_messages=1):
        if nick and where != nick:
            message = '%s: %s' % (nick, message)
        self._sopel.msg(where, message, max_messages=max_messages)

    def shutdown(self):
        self._sopel.quit('Terminated')
        self._thread.join()
