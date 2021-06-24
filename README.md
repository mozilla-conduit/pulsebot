pulsebot
========

Pulsebot is a bot listening to pulse.mozilla.org for mercurial changes and notifying bugzilla accordingly.

The current live setup can be replicated as follows:

```
sudo apt-get install python-virtualenv
virtualenv bot
bot/bin/pip install -r requirements.txt
```

Then create a `pulsebot.cfg` configuration:

```
bot/bin/python -m pulsebot.config > pulsebot.cfg
```

If you already have a `pulsebot.cfg` file, you shall update it with the new
default configuration:

```
bot/bin/python -m pulsebot.config > pulsebot.cfg.new
# Check the differences
diff -u pulsebot.cfg pulsebot.cfg.new
mv pulsebot.cfg.new pulsebot.cfg
```

The bot can then be started with:

```
bot/bin/python -m pulsebot
```
