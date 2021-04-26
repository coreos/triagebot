#!/usr/bin/python3
#
# Apache 2.0 license

import argparse
import bugzilla
from dotted_dict import DottedDict
from functools import wraps
import os
import requests
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.socket_mode import SocketModeClient
from slack_sdk.socket_mode.response import SocketModeResponse
import sqlite3
import time
import traceback
import yaml

ISSUE_LINK = 'https://github.com/bgilbert/triagebot/issues'
HELP = f'''
I understand these commands:
`unresolve` (in BZ thread) - unresolve the BZ
`refresh` (in BZ thread) - refresh the BZ description
`track {{BZ-URL|BZ-number}}` - start tracking the specified BZ
`help` - print this message
Report problems <{ISSUE_LINK}|here>.
'''

class Database(object):
    def __init__(self, config):
        # Use DB locking to protect against races between the Bugzilla
        # polling thread and the track command, and to avoid SQLITE_BUSY on
        # lock upgrade.  We're not performance-critical.
        self._db = sqlite3.connect(config.database, isolation_level='immediate')
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
                self._db.execute('pragma user_version = 1')

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


class Bug(object):
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
        details = bzapi.getbug(self.bz, include_fields=['summary'])
        self.summary = details.summary

    def __str__(self):
        return f'[{self.bz}] {self.summary}'

    @staticmethod
    def is_posted(db, bz):
        '''Class method returning True if we've already posted the specified
        BZ.  This allows the Bugzilla polling loop to check whether to
        process a BZ without constructing a Bug, since the latter makes an
        additional Bugzilla query.'''
        try:
            db.lookup_bz(bz)
            return True
        except KeyError:
            return False

    @property
    def posted(self):
        '''True if this bug has been posted to Slack.'''
        return self.ts is not None

    def _make_message(self):
        '''Format the Slack message for a bug.'''
        icon = ':white_check_mark:' if self.resolved else ':bugzilla:'
        message = f'{icon} <{self._config.bugzilla_bug_url}{self.bz}|[{self.bz}] {self.summary}> :thread:'
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


def report_errors(f):
    '''Decorator that sends exceptions to an administrator via Slack DM
    and then swallows them.  The first argument of the function must be
    the config.'''
    @wraps(f)
    def wrapper(config, *args, **kwargs):
        try:
            return f(config, *args, **kwargs)
        except requests.ConnectionError as e:
            # Exception type leaked from the bugzilla API.  Assume transient
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
                name='white_check_mark', timestamp=payload.event.ts)

    def fail_command(message):
        '''Reply to a command mention with an error.'''
        client.chat_postMessage(channel=payload.event.channel,
                text=f"<@{payload.event.user}> {message}",
                # start a new thread or continue the existing one
                thread_ts=payload.event.get('thread_ts', payload.event.ts))

    with db:
        if req.type == 'events_api' and payload.event.type == 'app_mention':
            ack_event()
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
                    fail_command(f"Bug {bz} already tracked: {link}")
                    return
                bug.post()
                bug.log(f'_Requested by <@{payload.event.user}>._')
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
            ack_event()
            try:
                bug = make_bug(channel=payload.container.channel_id,
                        ts=payload.container.message_ts)
            except KeyError:
                client.chat_postMessage(channel=payload.container.channel_id,
                        text=f"<@{payload.user.id}> Couldn't find a record of this bug.",
                        thread_ts=payload.container.message_ts)
                return
            bug.resolve()
            bug.log(f'_Resolved by <@{payload.user.id}>.  Undo with_ `<@{config.bot_id}> unresolve`')


@report_errors
def check_bugzilla(config, bzapi, client, db):
    ignore = set(config.get('bugzilla_ignore_bugs', []))
    query = bzapi.build_query(product=config.bugzilla_product,
            component=config.bugzilla_component, status='NEW',
            include_fields=['id'])
    for bz in bzapi.query(query):
        if bz.id in ignore:
            continue
        with db:
            if not Bug.is_posted(db, bz.id):
                Bug(config, client, bzapi, db, bz=bz.id).post()


def main():
    parser = argparse.ArgumentParser(
            description='Simple Bugzilla triage helper bot for Slack.')
    parser.add_argument('-c', '--config', metavar='FILE',
            default='~/.triagebot', help='config file')
    args = parser.parse_args()

    # Read config and connect to services
    with open(os.path.expanduser(args.config)) as fh:
        config = DottedDict(yaml.safe_load(fh))
        config.database = os.path.expanduser(
                config.get('database', '~/.triagebot-db'))
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

    # Run Bugzilla polling loop
    while True:
        check_bugzilla(config, bzapi, client, db)
        time.sleep(config.get('bugzilla_poll_interval', 300))


if __name__ == '__main__':
    main()
