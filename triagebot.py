#!/usr/bin/python3
#
# Apache 2.0 license

import argparse
from croniter import croniter
from datetime import datetime, timedelta, timezone
from dotted_dict import DottedDict
from functools import reduce, wraps
from heapq import heappop, heappush
from itertools import count
from jira import JIRA, JIRAError
import os
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.socket_mode import SocketModeClient
from slack_sdk.socket_mode.response import SocketModeResponse
import sqlite3
import time
import traceback
import yaml

ISSUE_LINK = 'https://github.com/coreos/triagebot/issues'
HELP = f'''
I understand these commands:
`unresolve` (in issue thread) - unresolve the issue
`refresh` (in issue thread) - refresh the issue description
`track {{issue-URL|issue-key}}` - start tracking the specified issue
`report` - summarize unresolved issues to the channel
`ping` - check whether the bot is running properly
`refresh-all` - refresh all unresolved issue descriptions
`help` - print this message
Report problems <{ISSUE_LINK}|here>.
'''

def escape(message):
    '''Escape a string for inclusion in a Slack message.'''
    # https://api.slack.com/reference/surfaces/formatting#escaping
    map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
    }
    return reduce(lambda s, p: s.replace(p[0], p[1]), map.items(), message)


def format_date(date):
    return f'<!date^{int(date.timestamp())}^{{date_long}} {{time}}|{date.strftime("%Y-%m-%d %H:%MZ")}>'


class Database:
    def __init__(self, config):
        # Use DB locking to protect against races between the Jira
        # polling thread and the track command, and to avoid SQLITE_BUSY on
        # lock upgrade.  We're not performance-critical.
        self._db = sqlite3.connect(config.database, isolation_level='immediate',
                timeout=60)
        with self:
            ver = self._db.execute('pragma user_version').fetchone()[0]
            if ver < 1:
                self._db.execute('create table issues '
                        '(id integer unique not null, '
                        'channel text not null, '
                        'timestamp text not null, '
                        'resolved integer not null default 0, '
                        # may be null
                        'autoclose_unixtime integer, '
                        # may be null
                        'autoclose_comment_count integer)')
                self._db.execute('create unique index issues_messages on issues '
                        '(channel, timestamp)')
                self._db.execute('create table specials '
                        '(name text unique not null, '
                        'channel text not null, '
                        'id text not null, '
                        'unixtime integer not null)')
                self._db.execute('create unique index specials_messages '
                        'on specials (channel, id)')
                self._db.execute('create table events '
                        '(added integer not null, '
                        'channel text not null, '
                        'timestamp text not null)')
                self._db.execute('create unique index events_unique '
                        'on events (channel, timestamp)')
                self._db.execute('create index issues_resolved on issues '
                        '(resolved)')
                self._db.execute('pragma user_version = 1')

    def __enter__(self):
        '''Start a database transaction.'''
        self._db.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, tb):
        '''Commit a database transaction.'''
        if exc_type is HandledError:
            # propagate exception but commit anyway
            self._db.__exit__(None, None, None)
            return False
        return self._db.__exit__(exc_type, exc_value, tb)

    def add_issue(self, id, channel, ts):
        self._db.execute('insert into issues (id, channel, timestamp) '
                'values (?, ?, ?)', (id, channel, ts))

    def set_resolved(self, id, resolved=True):
        # both resolve and unresolve disable autoclose
        self._db.execute('update issues set resolved = ?, '
                'autoclose_unixtime = null, autoclose_comment_count = null '
                'where id == ?', (int(resolved), id))

    def set_autoclose(self, id, time, comment_count):
        self._db.execute('update issues set resolved = 0, '
                'autoclose_unixtime = ?, autoclose_comment_count = ? '
                'where id == ?', (int(time.timestamp()), comment_count, id))

    def list_unresolved(self):
        res = self._db.execute('select id from issues where '
                'resolved == 0 order by timestamp').fetchall()
        return [r[0] for r in res]

    def list_autoclose(self):
        res = self._db.execute('select id from issues where '
                'autoclose_unixtime not null order by timestamp').fetchall()
        return [r[0] for r in res]

    def lookup_id(self, id):
        res = self._db.execute('select channel, timestamp, resolved, '
                'autoclose_unixtime, autoclose_comment_count '
                'from issues where id == ?', (id,)).fetchone()
        if res is None:
            raise KeyError
        channel, ts, resolved, close_time, close_comments = res
        return channel, ts, bool(resolved), close_time, close_comments

    def lookup_ts(self, channel, ts):
        res = self._db.execute('select id, resolved, autoclose_unixtime, '
                'autoclose_comment_count from issues where '
                'channel == ? and timestamp == ?', (channel, ts)).fetchone()
        if res is None:
            raise KeyError
        id, resolved, close_time, close_comments = res
        return id, bool(resolved), close_time, close_comments

    def set_special(self, name, channel, id):
        self._db.execute('insert or replace into specials '
                '(name, channel, id, unixtime) values (?, ?, ?, ?)',
                (name, channel, id, int(time.time())))

    def lookup_special(self, name):
        res = self._db.execute('select channel, id from specials where '
                'name == ?', (name,)).fetchone()
        if res is None:
            raise KeyError
        return res

    def get_special_unixtime(self, name):
        res = self._db.execute('select unixtime from specials where name == ?',
                (name,)).fetchone()
        if res is None:
            raise KeyError
        return res[0]

    def add_event(self, channel, ts):
        '''Return False if the event is already present.'''
        try:
            self._db.execute('insert into events (added, channel, timestamp) '
                    'values (?, ?, ?)', (int(time.time()), channel, ts))
            return True
        except sqlite3.IntegrityError:
            return False

    def prune_events(self, max_age=3600):
        self._db.execute('delete from events where added < ?',
                (int(time.time() - max_age),))


class Issue:
    # Database transactions must be supplied by the caller.

    def __init__(self, config, client, japi, db, id=None, key=None,
            channel=None, ts=None):
        self._config = config
        self._client = client
        self._japi = japi
        self._db = db
        self.id = id
        self.key = key
        self.channel = channel or config.channel  # default for new issue
        self.ts = ts
        self.resolved = False  # default for new issue
        self.autoclose_time = None  # default for new issue
        self.autoclose_comment_count = None  # default for new issue
        if key is not None:
            # convert to id, which is a stable long-term identifier
            assert channel is None and ts is None and id is None
            info = japi.issue(key, fields=[])
            id = int(info.id)
            self.id = id
            # fall through
        if id is not None:
            assert channel is None and ts is None
            try:
                (self.channel, self.ts, self.resolved, self.autoclose_time,
                        self.autoclose_comment_count) = db.lookup_id(id)
            except KeyError:
                # new issue hasn't been added yet
                pass
        else:
            assert channel is not None and ts is not None
            # raises KeyError on unknown timestamp
            (self.id, self.resolved, self.autoclose_time,
                    self.autoclose_comment_count) = db.lookup_ts(channel, ts)
        if self.autoclose_time is not None:
            self.autoclose_time = datetime.fromtimestamp(self.autoclose_time,
                    timezone.utc)
        fields = ['summary', 'project', 'components', 'assignee', 'status',
                'resolution', config.needinfo_field]
        info = japi.issue(self.id, fields=fields)
        self.key = info.key
        self.url = info.permalink()
        for field in fields:
            if field == config.needinfo_field:
                self.needinfo = bool(getattr(info.fields, config.needinfo_field, []))
            else:
                setattr(self, field, getattr(info.fields, field))
        self.assignee_name = self.assignee.displayName if self.assignee else 'nobody'
        for component in self.components:
            # prioritize the configured component if there are several
            if component.name == config.jira_component:
                self.component_name = component.name
                break
        else:
            if self.components:
                self.component_name = self.components[0].name
            else:
                self.component_name = 'none'

    def __str__(self):
        return f'[{self.key}] {self.summary}'

    @staticmethod
    def is_unresolved(db, id):
        '''Class method returning True if the specified issue is posted and
        unresolved.  This allows the Jira polling loop to check whether
        to process an issue without constructing an Issue, since the latter
        makes an additional Jira query.'''
        try:
            _, _, resolved, _, _ = db.lookup_id(id)
            return not resolved
        except KeyError:
            return False

    @classmethod
    def list_unresolved(cls, config, client, japi, db):
        for id in db.list_unresolved():
            yield cls(config, client, japi, db, id=id)

    @classmethod
    def list_autoclose(cls, config, client, japi, db):
        for id in db.list_autoclose():
            yield cls(config, client, japi, db, id=id)

    @property
    def posted(self):
        '''True if this issue has been posted to Slack.'''
        return self.ts is not None

    @property
    def autoclose(self):
        '''True if this issue has been configured to autoclose.'''
        return self.autoclose_time is not None

    def get_comment_count(self):
        '''Get the number of comments, which is relatively expensive.'''
        info = self._japi.issue(self.id, fields=['comment'])
        return len(info.fields.comment.comments)

    def _make_message(self):
        '''Format the Slack message for an issue.'''
        if self.resolved:
            icon = ':white_check_mark:'
        elif self.autoclose:
            icon = ':timer_clock:'
        else:
            icon = ':jira-1992:'
        message = f'{icon} <{self.url}|[{self.key}] {escape(self.summary)}> :thread:'
        blocks = [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': message,
                }
            }
        ]
        if self.resolved or self.autoclose:
            if self.autoclose:
                status = f'Will close after *{format_date(self.autoclose_time)}*'
            elif self.project.key != self._config.jira_project_key:
                status = f'Moved to *{escape(self.project.name)}*/*{escape(self.component_name)}*'
            elif self.component_name != self._config.jira_component:
                status = f'Moved to *{escape(self.component_name)}*'
            elif self.status.name == 'Closed':
                status = f'Closed as *{escape(self.resolution.name)}*'
            else:
                status = f'Assigned to *{escape(self.assignee_name)}*'
            blocks.append({
                'type': 'context',
                'elements': [
                    {
                        'type': 'mrkdwn',
                        'text': status,
                    },
                ]
            })
        if not self.resolved:
            actions = {
                'type': 'actions',
                'elements': [{
                    'type': 'button',
                    'text': {
                        'type': 'plain_text',
                        'text': 'Resolve'
                    },
                    'value': 'resolve',
                }]
            }
            if not self.autoclose:
                actions['elements'].append({
                    'type': 'button',
                    'text': {
                        'type': 'plain_text',
                        'text': 'Time out'
                    },
                    'value': 'autoclose',
                })
            blocks.append(actions)
        return message, blocks

    def post(self):
        '''Post this issue to Slack and record in DB.'''
        assert not self.posted
        message, blocks = self._make_message()
        self.ts = self._client.chat_postMessage(channel=self.channel,
                text=message, blocks=blocks, unfurl_links=False,
                unfurl_media=False)['ts']
        self._client.pins_add(channel=self.channel, timestamp=self.ts)
        self._db.add_issue(self.id, self.channel, self.ts)

    def update_message(self):
        '''Rerender the existing Slack message for this issue.'''
        assert self.posted
        message, blocks = self._make_message()
        self._client.chat_update(channel=self.channel, ts=self.ts,
                text=message, blocks=blocks)

    def check_can_autoclose(self):
        '''Check the issue against the autoclose rules, and return None if okay
        to autoclose or else a reason string.'''
        if self.status.name != 'New':
            return f'status is *{self.status.name}*'
        elif self.assignee is not None and self.assignee.name != self._config.jira_assignee_id:
            return f'assignee is *{escape(self.assignee_name)}*'
        elif self.project.key != self._config.jira_project_key:
            return f'project is *{escape(self.project.name)}*'
        elif self.component_name != self._config.jira_component:
            return f'component is *{escape(self.component_name)}*'
        elif not self.needinfo:
            return 'does not have Need Info From set'
        else:
            return None

    def set_autoclose(self):
        '''Mark the issue for autoclose in autoclose-minutes minutes and record
        in DB.'''
        assert self.posted
        self.resolved = False
        time = (datetime.now(timezone.utc) +
                timedelta(minutes=self._config.get('autoclose_minutes', 20160)))
        # round down to minute
        self.autoclose_time = (time -
                timedelta(seconds=time.second, microseconds=time.microsecond))
        self.autoclose_comment_count = self.get_comment_count()
        self.update_message()
        try:
            self._client.pins_add(channel=self.channel, timestamp=self.ts)
        except SlackApiError as e:
            if e.response['error'] != 'already_pinned':
                raise
        self._db.set_autoclose(self.id, self.autoclose_time,
                self.autoclose_comment_count)

    def refresh_autoclose(self):
        '''Perform or disable autoclose if needed.'''
        if not self.autoclose:
            return
        fail_reason = self.check_can_autoclose()
        if fail_reason is not None:
            self.log(f'_Issue {fail_reason}, disabling autoclose._')
            self.unresolve()
        elif self.autoclose_comment_count != self.get_comment_count():
            self.log('_Comment added to issue, disabling autoclose._')
            self.unresolve()
        elif self.autoclose_time < datetime.now(timezone.utc):
            self._japi.transition_issue(self.id, 'Closed',
                resolution={'name': 'Cannot Reproduce'},
                comment="We are unable to make progress on this issue without the requested information, so the issue is now being closed. If the problem persists, please provide the requested information and reopen the issue."
            )
            # we just automatically watched the issue
            self._japi.remove_watcher(self.id, self._config.jira_id)
            self.log('_Issue timeout reached, closing as Cannot Reproduce._')
            # refresh invalidated fields
            fields = ['status', 'resolution']
            info = self._japi.issue(self.id, fields=fields)
            for field in fields:
                setattr(self, field, getattr(info.fields, field))
            self.resolve()

    def resolve(self):
        '''Mark the issue resolved and record in DB.  Safe to call if already
        resolved.'''
        assert self.posted
        self.resolved = True
        self.autoclose_time, self.autoclose_comment_count = (None, None)
        self.update_message()
        try:
            self._client.pins_remove(channel=self.channel, timestamp=self.ts)
        except SlackApiError as e:
            if e.response['error'] != 'no_pin':
                raise
        self._db.set_resolved(self.id)

    def unresolve(self):
        '''Mark the issue unresolved and record in DB.  Safe to call if
        already unresolved.'''
        assert self.posted
        self.resolved = False
        self.autoclose_time, self.autoclose_comment_count = (None, None)
        self.update_message()
        try:
            self._client.pins_add(channel=self.channel, timestamp=self.ts)
        except SlackApiError as e:
            if e.response['error'] != 'already_pinned':
                raise
        self._db.set_resolved(self.id, False)

    def log(self, message):
        '''Post the specified message as a threaded reply to the issue.'''
        assert self.posted
        self._client.chat_postMessage(channel=self.channel, text=message,
                thread_ts=self.ts)


def post_report(config, client, japi, db):
    '''Post a summary of unresolved issues to the channel.  Return the channel
    and timestamp.'''
    parts = []
    for issue in Issue.list_unresolved(config, client, japi, db):
        age_days = int((time.time() - float(issue.ts)) / 86400)
        link = client.chat_getPermalink(channel=issue.channel,
                message_ts=issue.ts)["permalink"]
        icon = ':timer_clock:' if issue.autoclose else ':jira-1992:'
        part = f'{icon} <{issue.url}|[{issue.key}]> <{link}|{escape(issue.summary)}> ({age_days} days)'
        parts.append(part)
    if not parts:
        parts.append('_No issues!_')
    message = '\n'.join(['*Unresolved issue summary:*'] + parts)
    ts = client.chat_postMessage(channel=config.channel,
            text=message, unfurl_links=False, unfurl_media=False)['ts']
    return config.channel, ts


class HandledError(Exception):
    '''An exception which should just be swallowed.'''
    pass


def report_errors(f):
    '''Decorator that sends exceptions to an administrator via Slack DM
    and then swallows them.  The first argument of the function must be
    the config.'''
    import socket, urllib.error
    @wraps(f)
    def wrapper(config, *args, **kwargs):
        try:
            return f(config, *args, **kwargs)
        except HandledError:
            pass
        except (socket.timeout, urllib.error.URLError) as e:
            # Exception type leaked from the slack_sdk API.  Assume transient
            # network problem; don't send message.
            print(e)
        except Exception:
            try:
                message = f'Caught exception:\n```\n{traceback.format_exc()}```'
                client = WebClient(token=config.slack_token)
                channel = client.conversations_open(users=[config.error_notification])['channel']['id']
                client.chat_postMessage(channel=channel, text=message)
            except Exception:
                traceback.print_exc()
    return wrapper


@report_errors
def process_event(config, socket_client, req):
    '''Handler for a Slack event.'''
    client = socket_client.web_client
    payload = DottedDict(req.payload)
    db = Database(config)
    japi = JIRA(config.jira, token_auth=config.jira_token)

    def make_issue(**kwargs):
        return Issue(config, client, japi, db, **kwargs)

    def ack_event():
        '''Acknowledge the event, as required by Slack.'''
        resp = SocketModeResponse(envelope_id=req.envelope_id)
        socket_client.send_socket_mode_response(resp)

    def complete_command():
        '''Add a success emoji to a command mention.'''
        client.reactions_add(channel=payload.event.channel,
                name='ballot_box_with_check', timestamp=payload.event.ts)

    def fail_command(message):
        '''Reply to a command mention with an error.'''
        client.chat_postMessage(channel=payload.event.channel,
                text=f"<@{payload.event.user}> {message}",
                # start a new thread or continue the existing one
                thread_ts=payload.event.get('thread_ts', payload.event.ts))
        raise HandledError()

    with db:
        if req.type == 'events_api' and payload.event.type == 'app_mention':
            if payload.event.channel != config.channel:
                # Don't even acknowledge events outside our channel, to
                # avoid interfering with separate instances in other
                # channels.
                return
            ack_event()
            if not db.add_event(payload.event.channel, payload.event.event_ts):
                # When we ignore some events, Slack can send us duplicate
                # retries.  Detect and ignore those after acknowledging.
                return
            message = payload.event.text.replace(f'<@{config.slack_id}>', '').strip()
            if message == 'unresolve':
                if 'thread_ts' not in payload.event:
                    fail_command('`unresolve` command must be used in a thread.')
                try:
                    issue = make_issue(channel=payload.event.channel,
                            ts=payload.event.thread_ts)
                except KeyError:
                    fail_command("Couldn't find an issue matching this thread.")
                issue.unresolve()
                complete_command()
            elif message == 'refresh':
                if 'thread_ts' not in payload.event:
                    fail_command('`refresh` command must be used in a thread.')
                try:
                    issue = make_issue(channel=payload.event.channel,
                            ts=payload.event.thread_ts)
                except KeyError:
                    fail_command("Couldn't find an issue matching this thread.")
                issue.update_message()
                complete_command()
            elif message == 'refresh-all':
                client.reactions_add(channel=payload.event.channel,
                        timestamp=payload.event.ts,
                        name='hourglass_flowing_sand')
                try:
                    for issue in Issue.list_unresolved(config, client, japi, db):
                        issue.update_message()
                finally:
                    client.reactions_remove(channel=payload.event.channel,
                            timestamp=payload.event.ts,
                            name='hourglass_flowing_sand')
                complete_command()
            elif message.startswith('track '):
                try:
                    # Accept an issue key or an issue URL with optional query
                    # string.  Slack puts URLs inside <>.
                    key = message.replace('track ', '', 1). \
                            replace(config.jira_issue_url, '', 1). \
                            split('?')[0]. \
                            strip(' <>')
                except ValueError:
                    fail_command("Invalid issue key.")
                issue = make_issue(key=key)
                if issue.posted:
                    link = client.chat_getPermalink(channel=issue.channel,
                            message_ts=issue.ts)["permalink"]
                    fail_command(f"Issue {key} <{link}|already tracked>.")
                issue.post()
                issue.log(f'_Requested by <@{payload.event.user}>._')
                complete_command()
            elif message == 'report':
                # Post unscheduled report to the channel
                # We make a potentially large number of issue queries; tell
                # the user we're working
                client.reactions_add(channel=payload.event.channel,
                        timestamp=payload.event.ts,
                        name='hourglass_flowing_sand')
                try:
                    post_report(config, client, japi, db)
                finally:
                    client.reactions_remove(channel=payload.event.channel,
                            timestamp=payload.event.ts,
                            name='hourglass_flowing_sand')
                complete_command()
            elif message == 'ping':
                # Check Jira connectivity
                try:
                    japi.my_permissions()
                except Exception:
                    # Swallow exception details and just report the failure
                    fail_command('Cannot contact Jira.')
                # Check time since last successful poll
                try:
                    last_check = db.get_special_unixtime('watchdog')
                except KeyError:
                    fail_command('Have never successfully polled Jira.')
                time_since_check = time.time() - last_check
                if time_since_check > 1.5 * config.jira_poll_interval:
                    fail_command(f'Last successful Jira poll was {int(time_since_check / 60)} minutes ago.')
                complete_command()
            elif message == 'help':
                client.chat_postMessage(channel=payload.event.channel, text=HELP,
                        # start a new thread or continue the existing one
                        thread_ts=payload.event.get('thread_ts', payload.event.ts))
            elif message == 'throw':
                # undocumented
                complete_command()
                raise Exception(f'Throwing exception as requested by <@{payload.event.user}>')
            else:
                fail_command(f"I didn't understand that.  Try `<@{config.slack_id}> help`")
        elif (req.type == 'interactive' and payload.type == 'block_actions' and
                payload.actions[0].value in ('resolve', 'autoclose')):
            if payload.container.channel_id != config.channel:
                # Don't even acknowledge events outside our channel, to
                # avoid interfering with separate instances in other
                # channels.
                return
            ack_event()
            if not db.add_event(payload.container.channel_id, payload.actions[0].action_ts):
                # In case Slack sends duplicate action notifications, detect
                # and ignore them after acknowledging, since we have the
                # infrastructure anyway.
                return
            try:
                issue = make_issue(channel=payload.container.channel_id,
                        ts=payload.container.message_ts)
            except KeyError:
                client.chat_postMessage(channel=payload.container.channel_id,
                        text=f"<@{payload.user.id}> Couldn't find a record of this issue.",
                        thread_ts=payload.container.message_ts)
                return
            if payload.actions[0].value == 'resolve':
                if issue.project.key != config.jira_project_key:
                    status = f'Issue now in *{escape(issue.project.name)}*/*{escape(issue.component_name)}*.'
                elif issue.component_name != config.jira_component:
                    status = f'Issue now in *{escape(issue.component_name)}*.'
                elif issue.status.name == 'Closed':
                    status = f'Issue now *Closed/{escape(issue.resolution.name)}*.'
                elif issue.status.name == 'New':
                    client.chat_postMessage(channel=payload.container.channel_id,
                            text=f"<@{payload.user.id}> Issue still in component {escape(config.jira_component)} and status New, cannot resolve.",
                            thread_ts=payload.container.message_ts)
                    return
                elif issue.assignee is None:
                    client.chat_postMessage(channel=payload.container.channel_id,
                            text=f"<@{payload.user.id}> Issue unassigned, cannot resolve.",
                            thread_ts=payload.container.message_ts)
                    return
                elif issue.assignee.name == config.jira_assignee_id:
                    client.chat_postMessage(channel=payload.container.channel_id,
                            text=f"<@{payload.user.id}> Issue still assigned to {escape(issue.assignee_name)}, cannot resolve.",
                            thread_ts=payload.container.message_ts)
                    return
                else:
                    status = f'Issue now *{escape(issue.status.name)}*, assigned to *{escape(issue.assignee_name)}*.'
                issue.resolve()
                issue.log(f'_Resolved by <@{payload.user.id}>. {status} Unresolve with_ `<@{config.slack_id}> unresolve`')
            elif payload.actions[0].value == 'autoclose':
                fail_reason = issue.check_can_autoclose()
                if fail_reason is not None:
                    client.chat_postMessage(channel=payload.container.channel_id,
                            text=f"<@{payload.user.id}> Issue {fail_reason}, cannot autoclose.",
                            thread_ts=payload.container.message_ts)
                    return
                issue.set_autoclose()
                issue.log(f'_Will close unless an issue comment is added by *{format_date(issue.autoclose_time)}*, as requested by <@{payload.user.id}>. Disable with_ `<@{config.slack_id}> unresolve`')


class Scheduler:
    def __init__(self, config, client, japi, db):
        self._config = config
        self._japi = japi
        self._client = client
        self._db = db
        self._jobs = []
        self._add_timer(self._check_jira, 'jira_poll_interval', 300)
        self._add_cron(self._post_report, 'report_schedule')

    def _add_cron(self, fn, config_key, default=None):
        schedule = self._config.get(config_key, default)
        if schedule is not None:
            it = croniter(schedule)
            # add the list length as a tiebreaker when sorting, so we don't
            # try to compare two fns
            heappush(self._jobs, (next(it), len(self._jobs), fn, it))

    def _add_timer(self, fn, config_key, default=None):
        interval = self._config.get(config_key, default)
        if interval is not None:
            it = count(int(time.time()), interval)
            # add the list length as a tiebreaker when sorting, so we don't
            # try to compare two fns
            heappush(self._jobs, (next(it), len(self._jobs), fn, it))

    def run(self):
        while True:
            # get the next job that's due
            nex, idx, fn, it = heappop(self._jobs)
            # wait for the scheduled time, allowing for spurious wakeups
            while True:
                now = time.time()
                if now >= nex:
                    break
                time.sleep(nex - now)
            # run the job, passing the config to make report_errors() happy
            report_errors(fn)(self._config)
            # schedule the next run, skipping any times that are already
            # in the past
            now = time.time()
            while True:
                nex = next(it)
                if nex > now:
                    break
            heappush(self._jobs, (nex, idx, fn, it))

    def _check_jira(self, _config):
        # we don't do any escaping; the jira package doesn't support it
        # https://github.com/pycontribs/jira/issues/970
        queries = [
            # New issues
            f'project = {self._config.jira_project_key} AND component = "{self._config.jira_component}" AND status = New',
            # Open issues assigned to default assignee
            f'project = {self._config.jira_project_key} AND component = "{self._config.jira_component}" AND status != Closed AND assignee = {self._config.jira_assignee_id}',
        ]
        results = self._japi.search_issues(
            ' OR '.join([f'({q})' for q in queries]),
            fields=[], maxResults=False
        )

        for id in sorted([int(v.id) for v in results]):
            with self._db:
                if not Issue.is_unresolved(self._db, id):
                    issue = Issue(self._config, self._client, self._japi,
                            self._db, id=id)
                    if not issue.posted:
                        # Unknown issue; post it
                        issue.post()
                    else:
                        # Resolved issue; unresolve it
                        assert issue.resolved
                        issue.unresolve()
                        self._client.chat_postMessage(channel=issue.channel,
                                text=f'_Issue now *{escape(issue.status.name)}* in *{escape(issue.component_name)}*, assigned to *{escape(issue.assignee_name)}*. Unresolving._',
                                thread_ts=issue.ts)

        with self._db:
            for issue in Issue.list_autoclose(self._config, self._client,
                    self._japi, self._db):
                issue.refresh_autoclose()

        with self._db:
            self._db.prune_events()
            self._update_watchdog()

    def _update_watchdog(self):
        '''Reschedule the message-in-a-bottle that warns of a bot failure.'''
        # First, add new message
        expiration = int(time.time() + 60 * self._config.watchdog_minutes)
        message = f":robot_face: If you're seeing this, I haven't completed a Jira check in {self._config.watchdog_minutes} minutes.  I may be misconfigured, disconnected, or dead, or Jira may be down."
        new_id = self._client.chat_scheduleMessage(channel=self._config.channel,
                post_at=expiration, text=message)['scheduled_message_id']
        # Then delete the old one
        name = 'watchdog'
        try:
            old_channel, old_id = self._db.lookup_special(name)
        except KeyError:
            # No previous message
            pass
        else:
            try:
                self._client.chat_deleteScheduledMessage(channel=old_channel,
                        scheduled_message_id=old_id)
            except SlackApiError as e:
                if e.response['error'] == 'invalid_scheduled_message_id':
                    # Watchdog timer already fired.  Report that we're back.
                    self._client.chat_postMessage(channel=self._config.channel,
                            text='_is back_')
                else:
                    # Unexpected error.  We already rescheduled the timer, and
                    # it doesn't seem like we should abort the transaction for
                    # this.  Just log it.
                    print(e)
        # Update DB
        self._db.set_special(name, self._config.channel, new_id)

    def _post_report(self, _config):
        with self._db:
            post_report(self._config, self._client, self._japi, self._db)


def main():
    parser = argparse.ArgumentParser(
            description='Jira triage helper bot for Slack.')
    parser.add_argument('-c', '--config', metavar='FILE',
            default='~/.triagebot', help='config file')
    parser.add_argument('-d', '--database', metavar='FILE',
            default='~/.triagebot-db', help='database file')
    args = parser.parse_args()

    # Read config
    with open(os.path.expanduser(args.config)) as fh:
        config = DottedDict(yaml.safe_load(fh))
        config.database = os.path.expanduser(args.database)
    env_map = (
        ('TRIAGEBOT_JIRA_TOKEN', 'jira-token'),
        ('TRIAGEBOT_SLACK_APP_TOKEN', 'slack-app-token'),
        ('TRIAGEBOT_SLACK_TOKEN', 'slack-token'),
    )
    for env, config_key in env_map:
        v = os.environ.get(env)
        if v:
            setattr(config, config_key, v)

    # Connect to services
    client = WebClient(token=config.slack_token)
    # store our user IDs
    config.slack_id = client.auth_test()['user_id']
    japi = JIRA(config.jira, token_auth=config.jira_token)
    try:
        config.jira_id = japi.myself()['name']
    except JIRAError:
        raise Exception('Did not authenticate')
    # look up custom fields
    for field in japi.fields():
        if field['name'] == 'Need Info From':
            config.needinfo_field = field['id']
            break
    else:
        raise Exception("Couldn't find needinfo field")
    db = Database(config)

    # Start socket-mode listener in the background
    socket_client = SocketModeClient(app_token=config.slack_app_token,
            web_client=WebClient(token=config.slack_token))
    socket_client.socket_mode_request_listeners.append(
            lambda socket_client, req: process_event(config, socket_client, req))
    socket_client.connect()

    # Run scheduler
    Scheduler(config, client, japi, db).run()


if __name__ == '__main__':
    main()
