# Triagebot

This is a simple Slack bot to help with triaging Bugzilla issues.  It reports new bugs to a designated Slack channel and tracks whether the bugs have been triaged.

## Flows

- NEW bug arrives on the configured Bugzilla product and component →
  send message to channel and pin it to the channel
- Open bug arrives on the configured Bugzilla product and component, assigned to default assignee →
  same behavior as NEW bug
- "Resolve" button clicked on a bug message →
  unpin message from channel, update message to show that the bug is resolved, log resolution as threaded reply
- Bot mentioned in `unresolve` message in bug thread →
  repin message to channel, update message to show that the bug is unresolved
- Resolved bug is moved to NEW or to any open state with the default assignee, in the configured component →
  same behavior as `unresolve` message; also send threaded reply noting the change in bug status
- Bot mentioned with `track <bug-number|bug-URL>` →
  same behavior as NEW bug; also send threaded reply noting which user requested tracking

## Installing

A `setup.cfg` would be nice, but we don't have one right now.

```sh
cd ~
git clone https://github.com/coreos/triagebot
cd triagebot
virtualenv env
env/bin/pip install -r requirements.txt
env/bin/python triagebot.py
```

Alternatively, a [container image](https://quay.io/repository/coreos/triagebot) is available.

You'll also need to set up a Slack app in your workspace and get an API token for it, and to get a Bugzilla API key.

## Config format

See [config.example](config.example).  Put this in `~/.triagebot` by default.
