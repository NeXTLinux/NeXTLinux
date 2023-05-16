import sys
import os
import getpass
import click
import json

from nextlinux.cli.common import nextlinux_print, nextlinux_print_err
from nextlinux.util import contexts
from nextlinux import nextlinux_auth


@click.command(name='login', short_help='Log in to the Nextlinux service.')
@click.option('--user', help='Login with specified nextlinux.io username')
@click.option('--passfile',
              help='Read single line from specified file and use as password')
@click.pass_obj
def login(nextlinux_config, user, passfile):
    """
    Log into Nextlinux service using your username/password from nextlinux.io.
    """
    config = nextlinux_config
    ecode = 0

    try:
        nextlinux_creds_file = os.path.join(nextlinux_config.config_dir,
                                          'nextlinux_creds.json')
        nextlinux_stored_username = None
        nextlinux_stored_password = None
        if os.path.exists(nextlinux_creds_file):
            try:
                with open(nextlinux_creds_file, 'r') as FH:
                    nextlinux_stored_creds = json.loads(FH.read())
                    nextlinux_stored_username = nextlinux_stored_creds.pop(
                        'username', None)
                    nextlinux_stored_password = nextlinux_stored_creds.pop(
                        'password', None)
            except Exception as err:
                raise err

        if user:
            nextlinux_print("Using user from cmdline option: " + str(user))
            username = user
        elif os.getenv('ANCHOREUSER'):
            nextlinux_print("Using user from environment (ANCHOREUSER)")
            username = os.getenv('ANCHOREUSER')
        elif nextlinux_stored_username:
            nextlinux_print("Using stored username from nextlinux_creds.json")
            username = nextlinux_stored_username
        else:
            username = raw_input("Username: ")

        if passfile:
            nextlinux_print("Using password from cmdline option: " +
                          str(passfile))
            with open(passfile, "r") as FH:
                password = FH.read().strip()
        elif os.getenv('ANCHOREPASS'):
            nextlinux_print("Using password from environment (ANCHOREPASS)")
            password = os.getenv('ANCHOREPASS')
        elif nextlinux_stored_password:
            nextlinux_print("Using stored password from nextlinux_creds.json")
            password = nextlinux_stored_password
        else:
            password = getpass.getpass("Password: ")

        aa = contexts['nextlinux_auth']

        new_nextlinux_auth = nextlinux_auth.nextlinux_auth_init(
            username, password, aa['auth_file'], aa['client_info_url'],
            aa['token_url'], aa['conn_timeout'], aa['max_retries'])
        rc, ret = nextlinux_auth.nextlinux_auth_refresh(new_nextlinux_auth)
        if not rc:
            nextlinux_print(
                "Failed to log in: check your username/password and try again!"
            )
            raise Exception("Login failure - message from server: " +
                            str(ret['text']))
        else:
            contexts['nextlinux_auth'].update(new_nextlinux_auth)
            nextlinux_print("Login successful.")

    except Exception as err:
        nextlinux_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)


@click.command(name='logout', short_help='Log out of the Nextlinux service.')
@click.pass_obj
def logout(nextlinux_config):
    """
    Log out of Nextlinux service
    """
    ecode = 0
    try:
        aa = contexts['nextlinux_auth']
        if aa:
            nextlinux_auth.nextlinux_auth_invalidate(aa)
            if 'auth_file' in aa:
                os.remove(aa['auth_file'])
        print "Logout successful."
    except Exception as err:
        nextlinux_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)


@click.command(
    name='whoami',
    short_help='Show user data for current logged-in user if available')
@click.pass_obj
def whoami(nextlinux_config):
    """
    Show user data for current user if available
    :param nextlinux_config:
    :return:
    """
    ecode = 0
    try:
        aa = contexts['nextlinux_auth']
        if aa and 'username' in aa and 'password' in aa:
            info = {
                'Current user':
                aa['user_info'] if aa['user_info'] else 'anonymous'
            }

            nextlinux_print(info, do_formatting=True)
        else:
            nextlinux_print_err(
                'No nextlinux auth context found. Cannot get user info. Try logging in first'
            )
            ecode = 1

    except Exception as err:
        nextlinux_print_err('Cannot get user info')
        ecode = 1

    sys.exit(ecode)
