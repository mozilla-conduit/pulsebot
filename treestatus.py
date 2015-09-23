# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import requests
import willie.module


class UnknownBranch(Exception):
    pass


class TreeStatus(object):
    instance = None

    def __init__(self, server):
        self._server = server
        self._branches = set(self.current_status().keys())

    def find_branch(self, branch):
        if branch in self._branches:
            return branch

        # Do some fuzzy matching such that e.g. m-i automagically matches
        # mozilla-inbound.
        def possible_match(branch, pattern):
            branch_elements = branch.split('-')
            pattern_elements = pattern.split('-')
            if len(branch_elements) != len(pattern_elements):
                return False
            for branch_element, pattern_element in \
                    zip(branch_elements, pattern_elements):
                if not branch_element.startswith(pattern_element):
                    return False
            return True

        possible_branches = set(b for b in self._branches
            if possible_match(b, branch))

        if len(possible_branches) == 1:
            return possible_branches.pop()

        raise UnknownBranch(branch)

    def current_status(self, branch=''):
        if branch:
            branch = self.find_branch(branch)
        r = requests.get('%s/trees/%s' % (self._server, branch))
        return r.json()['result']


def setup(bot):
    TreeStatus.instance = TreeStatus(bot.config.treestatus.server)


def shutdown(bot):
    if TreeStatus.instance:
        TreeStatus.instance = None


@willie.module.nickname_commands('status')
def treestatus(bot, trigger):
    if not trigger.group(2):
        bot.reply('Missing branch name')
    else:
        branch = trigger.group(2)
        try:
            status = TreeStatus.instance.current_status(branch)
            bot.reply('%s is %s' % (status['tree'], status['status'].upper()))
        except UnknownBranch:
            bot.reply('Unknown branch: %s' % branch)

@willie.module.commands('status')
def pv_treestatus(bot, trigger):
    if trigger.is_privmsg:
        treestatus(bot, trigger)
