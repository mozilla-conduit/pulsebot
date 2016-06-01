pulsebot
========

Pulsebot is a bot listening to pulse.mozilla.org for mercurial changes and notifying channels accordingly. It uses the willie bot for all interactions with IRC servers.

The current setup used on irc.mozilla.org can be replicated as follows:

```
sudo apt-get install python-virtualenv git
virtualenv bot
git clone https://github.com/sopel-irc/sopel
(cd sopel; ../bot/bin/python setup.py install)
bot/bin/pip install MozillaPulse
```

Then create a ```pulsebot.cfg``` configuration in the directory you will start it from. The current configuration for the bot is:

```
[core]
nick = pulsebot
host = irc.mozilla.org
use_ssl = True
port = 6697
owner = glandium
channels = #pulsebot,#bugs,#developers,#tb-bugs,#mozreview,#vcs
user = pulsebot
name = pulsebot
prefix =
admins =
verify_ssl = True
timeout = 120

[pulse]
channels = #pulsebot,#bugs,#developers,#tb-bugs,#mozreview,#vcs
user = pulsebot
password = pulse-password-for-pulsebot

pulsebot = *
bugs = projects/alder,integration/b2g-inbound,releases/comm-aurora,releases/comm-beta,comm-central,integration/fx-team,releases/mozilla-aurora,releases/mozilla-beta,mozilla-central,releases/mozilla-esr*,integration/mozilla-inbound
developers = integration/b2g-inbound,integration/fx-team,releases/mozilla-aurora,releases/mozilla-beta,mozilla-central,releases/mozilla-esr*,integration/mozilla-inbound
fx-team = integration/fx-team
media = projects/alder
tb-bugs = releases/comm-aurora,releases/comm-beta,comm-central
mozreview = hgcustom/version-control-tools
vcs = hgcustom/version-control-tools

[treestatus]
server = https://api.pub.build.mozilla.org/treestatus/trees

[bugzilla]
server = https://bugzilla.mozilla.org/
user = bugzilla-user-for-pulsebot
password = bugzilla-password-for-pulsebot
pulse = integration/b2g-inbound,integration/fx-team,integration/mozilla-inbound,mozilla-central
```

The bot can then be started by
```
bot/bin/python -m pulsebot
```
