# Triagebot

This is a simple Slack bot to help with triaging Jira issues.  It reports new issues to a designated Slack channel and tracks whether the issues have been triaged.

## Flows

- New issue arrives on the configured Jira project and component →
  send message to channel and pin it to the channel
- Open issue arrives on the configured component, assigned to default assignee →
  same behavior as New issue
- "Resolve" button clicked on a issue message →
  unpin message from channel, update message to show that the issue is resolved, log resolution as threaded reply
- Bot mentioned in `unresolve` message in issue thread →
  repin message to channel, update message to show that the issue is unresolved
- Resolved issue is moved to New or to any open state with the default assignee, in the configured component →
  same behavior as `unresolve` message; also send threaded reply noting the change in issue status
- Bot mentioned with `track <bug-number|bug-URL>` →
  same behavior as New issue; also send threaded reply noting which user requested tracking

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

You'll also need to set up a Slack app in your workspace and get an API token for it, and to get a Jira personal access token.

## Config format

See [config.example](config.example).  Put this in `~/.triagebot` by default.
