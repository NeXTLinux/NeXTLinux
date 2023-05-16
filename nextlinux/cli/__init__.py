import os
import click
import subprocess
import docker
import sys
from nextlinux.configuration import NextlinuxConfiguration
from nextlinux.version import version as nextlinux_version

import analyzer
import query
import audit
import system
import logs
import toolbox
import login
import feeds
import policybundle
import nextlinux.nextlinux_image_db, nextlinux.nextlinux_utils

from nextlinux.util import contexts
from .common import init_output_format, nextlinux_print_err, extended_help_option

main_extended_help = """

Nextlinux is a tool for analyzing, querying, and curating container
images to deliver the transparency, predictability, and control
necessary to use containers in production. Nextlinux is composed of a
toolset that runs locally on a host as well as a web service that
monitors the container ecosystem and provides inputs to the local
toolset.

The tool has capabilities to populate a registry, run analysis,
explore/query the analysis results (including custom queries and
checks), and run policy-based gate-functions against container images
to help an ops team decide if a container should go into the CI/CD
pipeline and on to production based on attributes of the Dockerfile,
built image, or both.

After installation, the first command run should be: 'nextlinux feeds
list' to initialize the system and load feed data.

Feeds are different types of data that the nextlinux web service makes
available for certain container image queries and scans.  At any point
in time, you can use the 'nextlinux feeds' commands to sync the latest
data from the nextlinux web service, subscribe and/or unsubscribe from
nextlinux feeds, or get a list of available feeds. Except during feeds
operations, no network connectivity is required by nextlinux to run
analysis and query images.

Configuration Files:

Nextlinux configuration files are automatically installed if not found when looking in-order at:
\b
$HOME/.nextlinux/conf
/etc/nextlinux

A default install will copy the files to $HOME/.nextlinux/conf/, but they may be manually put in /etc/nextlinux for a system global config.

* config.yaml - main configuration file. Used to override default values. Nextlinux will search for it in
$HOME/.nextlinux/conf, then in /etc/nextlinux. If not found in either place, a new one is initilized and copied to $HOME/.nextlinux

* nextlinux_gate.policy - The global gate policy file (see nextlinux-gate(1) for more help on gates).


High-level example flows:

Initialize the system and sync the by-default subscribed feed 'vulnerabilties':

\b
nextlinux feeds list
nextlinux feeds sync

Analyze an image

docker pull nginx:latest
nextlinux analyze --image nginx:latest --imagetype base

Generate a summary report on all analyzed images

nextlinux audit report

Check gate output for nginx:latest:

nextlinux gate --image nginx:latest
"""


@click.group()
@click.option('--verbose',
              is_flag=True,
              help='Enable verbose output to stderr.')
@click.option('--debug',
              is_flag=True,
              help='Developer debug output to stderr.')
@click.option('--quiet',
              is_flag=True,
              help='Only errors to stderr, no status messages.')
@click.option('--json', is_flag=True, help='Output formatted json to stdout.')
@click.option('--plain',
              is_flag=True,
              help='Output formatted scriptable text to stdout.')
@click.option('--html',
              is_flag=True,
              help='Output formatted HTML table to stdout.')
@click.option(
    '--config-override',
    help=
    'Override an nextlinux configuration option (can be used multiple times).',
    metavar='<config_opt>=<config_value>',
    multiple=True)
@click.version_option(version=nextlinux_version)
@click.pass_context
@extended_help_option(extended_help=main_extended_help)
def main_entry(ctx, verbose, debug, quiet, json, plain, html, config_override):
    """
    Nextlinux is a tool to analyze, query, and curate container images. The options at this top level
    control stdout and stderr verbosity and format.

    After installation, the first command run should be: 'nextlinux feeds
    list' to initialize the system and load feed data.


    High-level example flows:

    Initialize the system and sync the by-default subscribed feed 'vulnerabilties':

    \b
    nextlinux feeds list
    nextlinux feeds sync

    Analyze an image

    docker pull nginx:latest
    nextlinux analyze --image nginx:latest --imagetype base

    Generate a summary report on all analyzed images

    nextlinux audit report

    Check gate output for nginx:latest:

    nextlinux gate --image nginx:latest
    """
    # Load the config into the context object
    logfile = None
    debug_logfile = None

    try:
        try:
            config_overrides = {}
            if config_override:
                for el in config_override:
                    try:
                        (key, val) = el.split('=')
                        if not key or not val:
                            raise Exception("could not split by '='")
                        config_overrides[key] = val
                    except:
                        click.echo(
                            "Error: specified --config_override param cannot be parsed (should be <config_opt>=<value>): "
                            + str(el))
                        exit(1)

            args = {
                'verbose': verbose,
                'debug': debug,
                'json': json,
                'plain': plain,
                'html': html,
                'quiet': quiet,
                'config_overrides': config_overrides
            }
            nextlinux_conf = NextlinuxConfiguration(cliargs=args)
        except Exception as err:
            click.echo("Error setting up/reading Nextlinux configuration",
                       err=True)
            click.echo("Info: " + str(err), err=True)
            import traceback
            traceback.print_exc()
            sys.exit(1)
        try:
            logfile = nextlinux_conf.data[
                'log_file'] if 'log_file' in nextlinux_conf.data else None
            debug_logfile = nextlinux_conf.data[
                'debug_log_file'] if 'debug_log_file' in nextlinux_conf.data else None
        except Exception, e:
            click.echo(str(e))

        ctx.obj = nextlinux_conf

    except:
        if ctx.invoked_subcommand != 'system':
            click.echo('Expected, but did not find configuration file at %s' %
                       os.path.join(NextlinuxConfiguration.DEFAULT_CONFIG_FILE),
                       err=True)
            exit(1)

    try:
        init_output_format(json,
                           plain,
                           debug,
                           verbose,
                           quiet,
                           log_filepath=logfile,
                           debug_log_filepath=debug_logfile)
    except Exception, e:
        click.echo('Error initializing logging: %s' % str(e))
        exit(2)

    if not nextlinux_pre_flight_check(ctx):
        nextlinux_print_err("Error running pre-flight checks")
        exit(1)

    try:
        if not nextlinux.nextlinux_utils.nextlinux_common_context_setup(ctx.obj):
            nextlinux_print_err(
                "Error setting up common data based on configuration")
            exit(1)
    except ValueError as err:
        print "ERROR: " + str(err)
        exit(1)


main_entry.add_command(system.system)
main_entry.add_command(query.query)
main_entry.add_command(audit.audit)
main_entry.add_command(analyzer.analyze)
main_entry.add_command(analyzer.gate)
main_entry.add_command(toolbox.toolbox)
main_entry.add_command(login.login)
main_entry.add_command(login.logout)
main_entry.add_command(login.whoami)
main_entry.add_command(feeds.feeds)
main_entry.add_command(policybundle.policybundle)


def nextlinux_pre_flight_check(ctx):
    # helper checks
    try:
        subcommand = ctx.invoked_subcommand
        config = ctx.obj.data
    except:
        return (False)

    if subcommand in ['explore', 'gate', 'analyze']:

        # check for some shellouts for analyzers
        try:
            cmd = ['dpkg-query', '--version']
            sout = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except Exception as err:
            nextlinux_print_err("Nextlinux requires dpkg libs and commands")
            return (False)

        try:
            from rpmUtils.miscutils import splitFilename
            cmd = ['rpm', '--version']
            sout = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except Exception as err:
            nextlinux_print_err("Nextlinux requires yum/rpm libs and commands")
            return (False)

    if subcommand in ['explore', 'gate', 'analyze', 'toolbox']:
        # check DB readiness
        try:
            db = nextlinux.nextlinux_image_db.load(
                driver=config['nextlinux_db_driver'], config=config)
        except Exception as err:
            nextlinux_print_err("Could not set up connection to Nextlinux DB")
            return (False)

    return (True)
