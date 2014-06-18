pulsebot
========

Pulsebot is a bot listening to pulse.mozilla.org for mercurial changes and notifying channels accordingly. It comes in the form of a willie module.

The current setup used on irc.mozilla.org can be replicated as follows:

```
sudo apt-get install python-virtualenv git
virtualenv willie-venv
git clone https://github.com/embolalia/willie
curl https://pypi.python.org/packages/source/M/MozillaPulse/MozillaPulse-0.93.tar.gz | tar -zxf -
(cd willie; ../willie-venv/bin/python setup.py install)
(cd MozillaPulse-0.93; ../willie-venv/bin/python setup.py install)
```

Then copy ```pulse.py``` in ```$HOME/.willie/modules``` and create a ```$HOME/.willie/default.cfg``` configuration. The current configuration for the bot is:

```
[core]
nick = pulsebot
host = irc.mozilla.org
use_ssl = True
port = 6697
owner = glandium
channels = #pulsebot,#bugs,#developers,#tb-bugs
user = pulsebot
name = pulsebot
prefix =
admins =
verify_ssl = True
timeout = 120
enable = pulse

[pulse]
channels = #pulsebot,#bugs,#developers,#tb-bugs
pulsebot = *
bugs = projects/alder,integration/b2g-inbound,releases/comm-aurora,releases/comm-beta,comm-central,integration/fx-team,releases/mozilla-aurora,releases/mozilla-beta,mozilla-central,releases/mozilla-esr24,integration/mozilla-inbound
developers = integration/b2g-inbound,integration/fx-team,releases/mozilla-aurora,releases/mozilla-beta,mozilla-central,releases/mozilla-esr24,integration/mozilla-inbound
tb-bugs = releases/comm-aurora,releases/comm-beta,comm-central
```

The bot can then be started by
```
willie-venv/bin/willie
```
