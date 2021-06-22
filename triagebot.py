#!/usr/bin/python3
#
# Apache 2.0 license

import argparse
import bugzilla
from croniter import croniter
from dotted_dict import DottedDict
from functools import reduce, wraps
from heapq import heappop, heappush
from itertools import count
import json
import os
import requests
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.socket_mode import SocketModeClient
from slack_sdk.socket_mode.response import SocketModeResponse
import sqlite3
import time
import traceback
from urllib.error import URLError
import yaml

ISSUE_LINK = 'https://github.com/bgilbert/triagebot/issues'
HELP = f'''
I understand these commands:
`unresolve` (in BZ thread) - unresolve the BZ
`refresh` (in BZ thread) - refresh the BZ description
`track {{BZ-URL|BZ-number}}` - start tracking the specified BZ
`report` - summarize unresolved bugs to the channel
`ping` - check whether the bot is running properly
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


class Database:
    def __init__(self, config):
        # Use DB locking to protect against races between the Bugzilla
        # polling thread and the track command, and to avoid SQLITE_BUSY on
        # lock upgrade.  We're not performance-critical.
        self._db = sqlite3.connect(config.database, isolation_level='immediate',
                timeout=60)
        with self:
            ver = self._db.execute('pragma user_version').fetchone()[0]
            if ver < 1:
                self._db.execute('create table bugs '
                        '(bz integer unique not null, '
                        'channel text not null, '
                        'timestamp text not null, '
                        'resolved integer not null default 0)')
                self._db.execute('create unique index bugs_messages on bugs '
                        '(channel, timestamp)')
            if ver < 2:
                self._db.execute('create table specials '
                        '(name text unique not null, '
                        'channel text not null, '
                        'id text not null)')
                self._db.execute('create unique index specials_messages '
                        'on specials (channel, id)')
            if ver < 3:
                self._db.execute('create table events '
                        '(added integer not null, '
                        'channel text not null, '
                        'timestamp text not null)')
                self._db.execute('create unique index events_unique '
                        'on events (channel, timestamp)')
            if ver < 4:
                self._db.execute('alter table specials add column '
                        'unixtime integer not null default 0')
            if ver < 5:
                self._db.execute('create index bugs_resolved on bugs '
                        '(resolved)')
                self._db.execute('pragma user_version = 5')

    def __enter__(self):
        '''Start a database transaction.'''
        return self._db.__enter__()

    def __exit__(self, *args, **kwargs):
        '''Commit a database transaction.'''
        return self._db.__exit__(*args, **kwargs)

    def add_bug(self, bz, channel, ts):
        self._db.execute('insert into bugs (bz, channel, timestamp) '
                'values (?, ?, ?)', (bz, channel, ts))

    def set_resolved(self, bz, resolved=True):
        self._db.execute('update bugs set resolved = ? where bz == ?',
                (int(resolved), bz))

    def list_unresolved(self):
        res = self._db.execute('select bz from bugs where '
                'resolved == 0 order by timestamp').fetchall()
        return [r[0] for r in res]

    def lookup_bz(self, bz):
        res = self._db.execute('select channel, timestamp, resolved '
                'from bugs where bz == ?', (bz,)).fetchone()
        if res is None:
            raise KeyError
        channel, ts, resolved = res
        return channel, ts, bool(resolved)

    def lookup_ts(self, channel, ts):
        res = self._db.execute('select bz, resolved from bugs where '
                'channel == ? and timestamp == ?', (channel, ts)).fetchone()
        if res is None:
            raise KeyError
        bz, resolved = res
        return bz, bool(resolved)

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


class Bug:
    # Database transactions must be supplied by the caller.

    def __init__(self, config, client, bzapi, db, bz=None, channel=None,
            ts=None):
        self._config = config
        self._client = client
        self._db = db
        self.bz = bz
        self.channel = channel or config.channel  # default for new bug
        self.ts = ts
        self.resolved = False  # default for new bug
        if bz is not None:
            assert channel is None and ts is None
            try:
                self.channel, self.ts, self.resolved = db.lookup_bz(bz)
            except KeyError:
                # new bug hasn't been added yet
                pass
        else:
            assert channel is not None and ts is not None
            # raises KeyError on unknown timestamp
            self.bz, self.resolved = db.lookup_ts(channel, ts)
        fields = ['summary', 'product', 'component', 'assigned_to', 'status',
                'resolution']
        details = bzapi.getbug(self.bz, include_fields=fields)
        for field in fields:
            setattr(self, field, getattr(details, field))
        self.assigned_to_name = details.assigned_to_detail['real_name']

    def __str__(self):
        return f'[{self.bz}] {self.summary}'

    @staticmethod
    def is_unresolved(db, bz):
        '''Class method returning True if the specified BZ is posted and
        unresolved.  This allows the Bugzilla polling loop to check whether
        to process a BZ without constructing a Bug, since the latter makes
        an additional Bugzilla query.'''
        try:
            _, _, resolved = db.lookup_bz(bz)
            return not resolved
        except KeyError:
            return False

    @classmethod
    def list_unresolved(cls, config, client, bzapi, db):
        for bz in db.list_unresolved():
            yield cls(config, client, bzapi, db, bz=bz)

    @property
    def posted(self):
        '''True if this bug has been posted to Slack.'''
        return self.ts is not None

    def _make_message(self):
        '''Format the Slack message for a bug.'''
        icon = ':white_check_mark:' if self.resolved else ':bugzilla:'
        message = f'{icon} <{self._config.bugzilla_bug_url}{self.bz}|[{self.bz}] {escape(self.summary)}> :thread:'
        blocks = [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': message,
                }
            }
        ]
        if not self.resolved:
            blocks.append({
                'type': 'actions',
                'elements': [
                    {
                        'type': 'button',
                        'text': {
                            'type': 'plain_text',
                            'text': 'Resolve'
                        },
                        'value': 'resolve',
                    },
                ]
            })
        else:
            if self.product != self._config.bugzilla_product:
                status = f'Moved to *{escape(self.product)}*/*{escape(self.component)}*'
            elif self.component != self._config.bugzilla_component:
                status = f'Moved to *{escape(self.component)}*'
            elif self.status == 'CLOSED':
                status = f'Closed as *{escape(self.resolution)}*'
            else:
                status = f'Assigned to *{escape(self.assigned_to_name)}*'
            blocks.append({
                'type': 'context',
                'elements': [
                    {
                        'type': 'mrkdwn',
                        'text': status,
                    },
                ]
            })
        return message, blocks

    def post(self):
        '''Post this bug to Slack and record in DB.'''
        assert not self.posted
        message, blocks = self._make_message()
        self.ts = self._client.chat_postMessage(channel=self.channel,
                text=message, blocks=blocks, unfurl_links=False,
                unfurl_media=False)['ts']
        self._client.pins_add(channel=self.channel, timestamp=self.ts)
        self._db.add_bug(self.bz, self.channel, self.ts)

    def update_message(self):
        '''Rerender the existing Slack message for this bug.'''
        assert self.posted
        message, blocks = self._make_message()
        self._client.chat_update(channel=self.channel, ts=self.ts,
                text=message, blocks=blocks)

    def resolve(self):
        '''Mark the bug resolved and record in DB.  Safe to call if already
        resolved.'''
        assert self.posted
        self.resolved = True
        self.update_message()
        try:
            self._client.pins_remove(channel=self.channel, timestamp=self.ts)
        except SlackApiError as e:
            if e.response['error'] != 'no_pin':
                raise
        self._db.set_resolved(self.bz)

    def unresolve(self):
        '''Mark the bug unresolved and record in DB.  Safe to call if
        already unresolved.'''
        assert self.posted
        self.resolved = False
        self.update_message()
        try:
            self._client.pins_add(channel=self.channel, timestamp=self.ts)
        except SlackApiError as e:
            if e.response['error'] != 'already_pinned':
                raise
        self._db.set_resolved(self.bz, False)

    def log(self, message):
        '''Post the specified message as a threaded reply to the bug.'''
        assert self.posted
        self._client.chat_postMessage(channel=self.channel, text=message,
                thread_ts=self.ts)


def post_report(config, client, bzapi, db):
    '''Post a summary of unresolved bugs to the channel.  Return the channel
    and timestamp.'''
    parts = []
    for bug in Bug.list_unresolved(config, client, bzapi, db):
        age_days = int((time.time() - float(bug.ts)) / 86400)
        link = client.chat_getPermalink(channel=bug.channel,
                message_ts=bug.ts)["permalink"]
        part = f':bugzilla: <{config.bugzilla_bug_url}{bug.bz}|[{bug.bz}]> <{link}|{escape(bug.summary)}> ({age_days} days)'
        parts.append(part)
    if not parts:
        parts.append('_No bugs!_')
    message = '\n'.join(['*Unresolved bug summary:*'] + parts)
    blocks = [
        {
            'type': 'section',
            'text': {
                'type': 'mrkdwn',
                'text': message,
            }
        }
    ]
    ts = client.chat_postMessage(channel=config.channel,
            text=message, blocks=blocks, unfurl_links=False,
            unfurl_media=False)['ts']
    return config.channel, ts


def report_errors(f):
    '''Decorator that sends exceptions to an administrator via Slack DM
    and then swallows them.  The first argument of the function must be
    the config.'''
    @wraps(f)
    def wrapper(config, *args, **kwargs):
        try:
            return f(config, *args, **kwargs)
        except (json.JSONDecodeError, requests.ConnectionError, requests.HTTPError, requests.ReadTimeout) as e:
            # Exception type leaked from the bugzilla API.  Assume transient
            # network problem; don't send message.
            print(e)
        except URLError as e:
            # Exception type leaked from the slack_sdk API.  Assume transient
            # network problem; don't send message.
            print(e)
        except Exception as e:
            try:
                message = f'Caught exception:\n```\n{traceback.format_exc()}```'
                client = WebClient(token=config.slack_token)
                channel = client.conversations_open(users=[config.error_notification])['channel']['id']
                client.chat_postMessage(channel=channel, text=message)
            except Exception as e:
                traceback.print_exc()
    return wrapper


@report_errors
def process_event(config, socket_client, req):
    '''Handler for a Slack event.'''
    client = socket_client.web_client
    payload = DottedDict(req.payload)
    db = Database(config)
    bzapi = bugzilla.Bugzilla(config.bugzilla, api_key=config.bugzilla_key,
            force_rest=True)

    def make_bug(**kwargs):
        return Bug(config, client, bzapi, db, **kwargs)

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
            message = payload.event.text.replace(f'<@{config.bot_id}>', '').strip()
            if message == 'unresolve':
                if 'thread_ts' not in payload.event:
                    fail_command('`unresolve` command must be used in a thread.')
                    return
                try:
                    bug = make_bug(channel=payload.event.channel,
                            ts=payload.event.thread_ts)
                except KeyError:
                    fail_command("Couldn't find a BZ matching this thread.")
                    return
                bug.unresolve()
                complete_command()
            elif message == 'refresh':
                if 'thread_ts' not in payload.event:
                    fail_command('`refresh` command must be used in a thread.')
                    return
                try:
                    bug = make_bug(channel=payload.event.channel,
                            ts=payload.event.thread_ts)
                except KeyError:
                    fail_command("Couldn't find a BZ matching this thread.")
                    return
                bug.update_message()
                complete_command()
            elif message.startswith('track '):
                try:
                    # Accept a bug number or a BZ URL with optional anchor.
                    # Slack puts URLs inside <>.
                    bz = int(message.replace('track ', '', 1). \
                            replace(config.bugzilla_bug_url, '', 1). \
                            split('#')[0]. \
                            strip(' <>'))
                except ValueError:
                    fail_command("Invalid bug number.")
                    return
                bug = make_bug(bz=bz)
                if bug.posted:
                    link = client.chat_getPermalink(channel=bug.channel,
                            message_ts=bug.ts)["permalink"]
                    fail_command(f"Bug {bz} <{link}|already tracked>.")
                    return
                bug.post()
                bug.log(f'_Requested by <@{payload.event.user}>._')
                complete_command()
            elif message == 'report':
                # Post unscheduled report to the channel
                # We make a potentially large number of BZ queries; tell
                # the user we're working
                client.reactions_add(channel=payload.event.channel,
                        timestamp=payload.event.ts,
                        name='hourglass_flowing_sand')
                try:
                    channel, ts = post_report(config, client, bzapi, db)
                    client.chat_postMessage(channel=channel, thread_ts=ts,
                            text=f'_Requested by <@{payload.event.user}>._')
                finally:
                    client.reactions_remove(channel=payload.event.channel,
                            timestamp=payload.event.ts,
                            name='hourglass_flowing_sand')
                complete_command()
            elif message == 'ping':
                # Check Bugzilla connectivity
                try:
                    if not bzapi.logged_in:
                        raise Exception('Not logged in.')
                except Exception:
                    # Swallow exception details and just report the failure
                    fail_command('Cannot contact Bugzilla.')
                    return
                # Check time since last successful poll
                try:
                    last_check = db.get_special_unixtime('watchdog')
                except KeyError:
                    fail_command('Have never successfully polled Bugzilla.')
                    return
                time_since_check = time.time() - last_check
                if time_since_check > 1.5 * config.bugzilla_poll_interval:
                    fail_command(f'Last successful Bugzilla poll was {int(time_since_check / 60)} minutes ago.')
                    return
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
                fail_command(f"I didn't understand that.  Try `<@{config.bot_id}> help`")
        elif req.type == 'interactive' and payload.type == 'block_actions' and payload.actions[0].value == 'resolve':
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
                bug = make_bug(channel=payload.container.channel_id,
                        ts=payload.container.message_ts)
            except KeyError:
                client.chat_postMessage(channel=payload.container.channel_id,
                        text=f"<@{payload.user.id}> Couldn't find a record of this bug.",
                        thread_ts=payload.container.message_ts)
                return
            if bug.product != config.bugzilla_product:
                status = f'Bug now in *{escape(bug.product)}*/*{escape(bug.component)}*.'
            elif bug.component != config.bugzilla_component:
                status = f'Bug now in *{escape(bug.component)}*.'
            elif bug.status == 'CLOSED':
                status = f'Bug now *CLOSED/{escape(bug.resolution)}*.'
            elif bug.status == 'NEW':
                client.chat_postMessage(channel=payload.container.channel_id,
                        text=f"<@{payload.user.id}> Bug still in component {escape(config.bugzilla_component)} and status NEW, cannot resolve.",
                        thread_ts=payload.container.message_ts)
                return
            elif bug.assigned_to == config.bugzilla_assignee:
                client.chat_postMessage(channel=payload.container.channel_id,
                        text=f"<@{payload.user.id}> Bug still assigned to {escape(bug.assigned_to_name)}, cannot resolve.",
                        thread_ts=payload.container.message_ts)
                return
            else:
                status = f'Bug now *{escape(bug.status)}*, assigned to *{escape(bug.assigned_to_name)}*.'
            bug.resolve()
            bug.log(f'_Resolved by <@{payload.user.id}>. {status} Unresolve with_ `<@{config.bot_id}> unresolve`')


class Scheduler:
    def __init__(self, config, client, bzapi, db):
        self._config = config
        self._bzapi = bzapi
        self._client = client
        self._db = db
        self._jobs = []
        self._add_timer(self._check_bugzilla, 'bugzilla_poll_interval', 300)
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

    def _check_bugzilla(self, _config):
        queries = [
            # NEW bugs
            self._bzapi.build_query(product=self._config.bugzilla_product,
                    component=self._config.bugzilla_component, status='NEW'),
            # Open bugs assigned to default assignee
            self._bzapi.build_query(product=self._config.bugzilla_product,
                    component=self._config.bugzilla_component,
                    status='__open__',
                    assigned_to=self._config.bugzilla_assignee),
        ]
        bzs = set()
        for query in queries:
            query['include_fields'] = ['id']
            bzs.update(bz.id for bz in self._bzapi.query(query))
        # Remove ignored bugs
        bzs.difference_update(self._config.get('bugzilla_ignore_bugs', []))

        for bz in sorted(bzs):
            with self._db:
                if not Bug.is_unresolved(self._db, bz):
                    bug = Bug(self._config, self._client, self._bzapi,
                            self._db, bz=bz)
                    if not bug.posted:
                        # Unknown bug; post it
                        bug.post()
                    else:
                        # Resolved bug; unresolve it
                        assert bug.resolved
                        bug.unresolve()
                        self._client.chat_postMessage(channel=bug.channel,
                                text=f'_Bug now *{escape(bug.status)}* in *{escape(bug.component)}*, assigned to *{escape(bug.assigned_to_name)}*. Unresolving._',
                                thread_ts=bug.ts)
        with self._db:
            self._db.prune_events()
            self._update_watchdog()

    def _update_watchdog(self):
        '''Reschedule the message-in-a-bottle that warns of a bot failure.'''
        # First, add new message
        expiration = int(time.time() + 60 * self._config.watchdog_minutes)
        message = f":robot_face: If you're seeing this, I haven't completed a Bugzilla check in {self._config.watchdog_minutes} minutes.  I may be misconfigured, disconnected, or dead, or Bugzilla may be down."
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
            post_report(self._config, self._client, self._bzapi, self._db)


def main():
    parser = argparse.ArgumentParser(
            description='Simple Bugzilla triage helper bot for Slack.')
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
        ('TRIAGEBOT_SLACK_APP_TOKEN', 'slack-app-token'),
        ('TRIAGEBOT_SLACK_TOKEN', 'slack-token'),
        ('TRIAGEBOT_BUGZILLA_KEY', 'bugzilla-key')
    )
    for env, config_key in env_map:
        v = os.environ.get(env)
        if v:
            setattr(config, config_key, v)

    # Connect to services
    client = WebClient(token=config.slack_token)
    # store our user ID
    config.bot_id = client.auth_test()['user_id']
    bzapi = bugzilla.Bugzilla(config.bugzilla, api_key=config.bugzilla_key,
            force_rest=True)
    if not bzapi.logged_in:
        raise Exception('Did not authenticate')
    db = Database(config)

    # Start socket-mode listener in the background
    socket_client = SocketModeClient(app_token=config.slack_app_token,
            web_client=WebClient(token=config.slack_token))
    socket_client.socket_mode_request_listeners.append(
            lambda socket_client, req: process_event(config, socket_client, req))
    socket_client.connect()

    # Run scheduler
    Scheduler(config, client, bzapi, db).run()


if __name__ == '__main__':
    main()
