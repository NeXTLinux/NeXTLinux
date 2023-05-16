import sys
import click
import time
import calendar
import datetime
import collections

from nextlinux.cli.common import nextlinux_print, nextlinux_print_err
from nextlinux import nextlinux_auth, nextlinux_policy
from nextlinux.nextlinux_utils import contexts

config = {}


@click.group(name='policybundle',
             short_help='Manage syncing your stored policy bundles.')
@click.pass_obj
def policybundle(nextlinux_config):
    global config
    config = nextlinux_config

    ecode = 0
    emsg = ""
    success = True

    if not success:
        nextlinux_print_err(emsg)
        sys.exit(1)


@policybundle.command(name='show', short_help="Show bundle information.")
@click.option('--details', help='Show all details of the bundle', is_flag=True)
def show(details):
    """
    Show list of Nextlinux data policies.

    """

    ecode = 0
    try:
        policymeta = nextlinux_policy.load_policymeta()

        if details:
            nextlinux_print(policymeta, do_formatting=True)

        else:
            output = {}

            name = policymeta['name']
            output[name] = {}
            output[name]['id'] = policymeta['id']
            output[name]['policies'] = policymeta['policies']
            output[name]['whitelists'] = policymeta['whitelists']
            output[name]['mappings'] = policymeta['mappings']

            nextlinux_print(output, do_formatting=True)
    except Exception as err:
        nextlinux_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)


@policybundle.command(
    name='sync',
    short_help=
    "Sync (download) latest policy bundle from the Nextlinux.io service.")
@click.option(
    '--infile',
    help=
    'Sync the stored policy bundle from a file, instead of download from nextlinux.io.',
    type=click.Path(exists=True),
    metavar='<file>')
@click.option(
    '--outfile',
    help=
    'Sync and store downloaded bundle to the specified output file, instead of storing internally',
    type=click.Path(),
    metavar='<file>')
def sync(infile, outfile):
    """
    Sync (download) latest policies from the Nextlinux.io service.

    """

    ecode = 0
    try:
        rc, ret = nextlinux_policy.sync_policymeta(bundlefile=infile,
                                                 outfile=outfile)
        if not rc:
            nextlinux_print_err(ret['text'])
            ecode = 1
        elif outfile and outfile == '-':
            nextlinux_print(ret['text'])
    except Exception as err:
        nextlinux_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)
