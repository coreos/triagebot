# Triagebot

This is a Slack bot to help with triaging Jira issues.  It reports new issues to a designated Slack channel and tracks whether the issues have been triaged.

## Flows

- New issue arrives on the configured Jira project and component →
  send message to channel and pin it to the channel
- Open unassigned issue arrives on the configured component →
  same behavior as New issue
- "Resolve" button clicked on an issue message →
  unpin message from channel, update message to show that the issue is resolved, log resolution as threaded reply
- "Time out" button clicked on an issue message where the issue has "Need Info From" set →
  set timer, update message to show that a timeout has been set, log threaded reply
- Issue with pending timeout is moved out of the component or out of New, is assigned, has "Need Info From" cleared, or gets a new issue comment →
  clear timeout, update message to remove timeout, log threaded reply
- Issue with pending timeout reaches the timeout →
  post comment to the issue and close it as Cannot Reproduce, mark issue resolved
- Bot mentioned in `unresolve` message in issue thread →
  repin message to channel, update message to show that the issue is unresolved
- Resolved issue is moved to New or to any open state with no assignee, in the configured component →
  same behavior as `unresolve` message; also send threaded reply noting the change in issue status
- Bot mentioned with `track <issue-key|issue-URL>` →
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
