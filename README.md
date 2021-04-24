# Triagebot

This is a simple Slack bot to help with triaging Bugzilla issues.  It reports new bugs to a designated Slack channel and tracks whether the bugs have been triaged.

## Flows

- NEW bug arrives on the configured Bugzilla product and component →
  send message to channel and pin it to the channel
- "Resolve" button clicked on a bug message →
  unpin message from channel, update message to show that the bug is resolved, log resolution as threaded reply
- Bot mentioned in `unresolve` message in bug thread →
  repin message to channel, update message to show that the bug is unresolved
- Bot mentioned with `track <bug-number|bug-URL>` →
  same behavior as NEW bug; also send threaded reply noting which user requested tracking

## Installing

A `setup.cfg` would be nice, but we don't have one right now.

```sh
cd ~
git clone https://github.com/bgilbert/triagebot
cd triagebot
virtualenv env
env/bin/pip install -r requirements.txt
env/bin/python triagebot.py
```

You'll also need to set up a Slack app in your workspace and get an API token for it, and to get a Bugzilla API key.

## Config format

See [config.example](config.example).
