# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from pulsebot.pulse_dispatch import PulseDispatcher

def setup(bot):
    PulseDispatcher.instance = PulseDispatcher(bot)


def shutdown(bot):
    if PulseDispatcher.instance:
        PulseDispatcher.instance.shutdown()
        PulseDispatcher.instance = None
