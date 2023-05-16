import sys
import os
import re
import json
import getpass
import click
import yaml
import time
import shutil

from nextlinux.cli.common import nextlinux_print, nextlinux_print_err
from nextlinux.util import contexts
from nextlinux import nextlinux_utils, nextlinux_auth, nextlinux_feeds

config = {}


@click.group(name='system', short_help='System level operations.')
@click.pass_obj
def system(nextlinux_config):
    global config
    config = nextlinux_config


@system.command(name='status', short_help="Show system status.")
@click.option('--conf',
              is_flag=True,
              help='Output the currently used configuration yaml content')
def status(conf):
    """
    Show nextlinux system status.
    """

    ecode = 0
    try:
        if conf:
            if config.cliargs['json']:
                nextlinux_print(config.data, do_formatting=True)
            else:
                nextlinux_print(
                    yaml.safe_dump(config.data,
                                   indent=True,
                                   default_flow_style=False))
        else:
            result = {}
            if contexts['nextlinux_db'].check():
                result["nextlinux_db"] = "OK"
            else:
                result["nextlinux_db"] = "NOTINITIALIZED"

            if nextlinux_feeds.check():
                result["nextlinux_feeds"] = "OK"
            else:
                result["nextlinux_feeds"] = "NOTSYNCED"

            afailed = False
            latest = 0
            for imageId in contexts['nextlinux_db'].load_all_images().keys():
                amanifest = nextlinux_utils.load_analyzer_manifest(imageId)
                for module_name in amanifest.keys():
                    try:
                        if amanifest[module_name]['timestamp'] > latest:
                            latest = amanifest[module_name]['timestamp']
                        if amanifest[module_name]['status'] != 'SUCCESS':
                            analyzer_failed_imageId = imageId
                            analyzer_failed_name = module_name
                            afailed = True
                    except:
                        pass

            if latest == 0:
                result["analyzer_status"] = "NODATA"
            elif afailed:
                result[
                    "analyzer_status"] = "FAIL (" + analyzer_failed_imageId + ")"
                result["analyzer_latest_run"] = time.ctime(latest)
            else:
                result["analyzer_status"] = "OK"
                result["analyzer_latest_run"] = time.ctime(latest)

            nextlinux_print(result, do_formatting=True)

    except Exception as err:
        nextlinux_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)


@system.command(name='show-schemas',
                short_help="Show nextlinux document schemas.")
@click.argument('schemaname', nargs=-1)
def show_schemas(schemaname):
    """
    Show nextlinux document schemas.
    """

    ecode = 0
    try:
        schemas = {}
        schema_dir = os.path.join(contexts['nextlinux_config']['pkg_dir'],
                                  'schemas')
        for f in os.listdir(schema_dir):
            sdata = {}
            try:
                with open(os.path.join(schema_dir, f), 'r') as FH:
                    sdata = json.loads(FH.read())
            except:
                nextlinux_print_err('found schema file but failed to parse: ' +
                                  os.path.join(schema_dir, f))

            if sdata and (not schemaname or f in schemaname):
                schemas[f] = sdata

        if not schemas:
            nextlinux_print_err("no specified schemas were found to show")
        else:
            nextlinux_print(json.dumps(schemas, indent=4))

    except Exception as err:
        nextlinux_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)


@system.command(name='backup',
                short_help="Backup an nextlinux installation to a tarfile.")
@click.argument('outputdir', type=click.Path())
def backup(outputdir):
    """
    Backup an nextlinux installation to a tarfile.
    """

    ecode = 0
    try:
        nextlinux_print('Backing up nextlinux system to directory ' +
                      str(outputdir) + ' ...')
        backupfile = config.backup(outputdir)
        nextlinux_print({"nextlinux_backup_tarball": str(backupfile)},
                      do_formatting=True)
    except Exception as err:
        nextlinux_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)


@system.command(
    name='restore',
    short_help=
    "Restore an nextlinux installation from a previously backed up tar file.")
@click.argument('inputfile', type=click.File('rb'))
@click.argument('destination_root', type=click.Path(), default='/')
def restore(inputfile, destination_root):
    """
    Restore an nextlinux installation from a previously backed up tar file.
    """

    ecode = 0
    try:
        nextlinux_print('Restoring nextlinux system from backup file %s ...' %
                      (str(inputfile.name)))
        restoredir = config.restore(destination_root, inputfile)
        nextlinux_print("Nextlinux restored.")
    except Exception as err:
        nextlinux_print_err('operation failed')
        ecode = 1

    sys.exit(ecode)


@system.command(name='exportdb')
@click.option('--outdir',
              help='output directory for exported nextlinux DB',
              required=True,
              metavar='<export directory>')
def exportdb(outdir):
    """Export all nextlinux images to JSON files"""
    ecode = 0
    try:
        imgdir = os.path.join(outdir, "images")
        feeddir = os.path.join(outdir, "feeds")
        storedir = os.path.join(outdir, "storedfiles")

        for d in [outdir, imgdir, feeddir, storedir]:
            if not os.path.exists(d):
                os.makedirs(d)

        nextlinux_print("exporting images...")
        imagelist = nextlinux_utils.get_image_list().keys()
        for imageId in imagelist:
            thefile = os.path.join(imgdir, imageId + ".json")
            if not os.path.exists(thefile):
                with open(thefile, 'w') as OFH:
                    OFH.write(
                        json.dumps(
                            contexts['nextlinux_db'].load_image_new(imageId)))

            stored_namespaces = contexts['nextlinux_db'].load_files_namespaces(
                imageId)
            for namespace in stored_namespaces:
                stored_files = contexts['nextlinux_db'].load_files_tarfile(
                    imageId, namespace)
                if os.path.exists(stored_files):
                    thedir = os.path.join(storedir, imageId, namespace)
                    if not os.path.exists(thedir):
                        os.makedirs(thedir)
                    thefile = os.path.join(thedir, "stored_files.tar.gz")
                    shutil.copy(stored_files, thefile)

        nextlinux_print("exporting feeds...")
        feedmeta = contexts['nextlinux_db'].load_feedmeta()
        thefile = os.path.join(feeddir, "feedmeta.json")
        with open(thefile, 'w') as OFH:
            OFH.write(json.dumps(feedmeta))

        for feed in feedmeta:
            feedobj = feedmeta[feed]
            for group in feedobj['groups']:
                groupobj = feedobj['groups'][group]
                datafiles = groupobj.pop('datafiles', [])
                for datafile in datafiles:
                    thedir = os.path.join(feeddir, feed, group)
                    if not os.path.exists(thedir):
                        os.makedirs(thedir)
                    thefile = os.path.join(thedir, datafile)
                    if not os.path.exists(thefile):
                        with open(thefile, 'w') as OFH:
                            OFH.write(
                                json.dumps(contexts['nextlinux_db'].
                                           load_feed_group_data(
                                               feed, group, datafile)))

    except Exception as err:
        nextlinux_print_err("operation failed: " + str(err))
        ecode = 1

    sys.exit(ecode)


@system.command(name='importdb')
@click.option('--indir',
              help='directory from previously exported nextlinux DB',
              required=True,
              metavar='<export directory>')
def importdb(indir):
    """Import a previously exported nextlinux DB"""
    ecode = 0
    try:
        imgdir = os.path.join(indir, "images")
        feeddir = os.path.join(indir, "feeds")
        storedir = os.path.join(indir, "storedfiles")

        for d in [indir, imgdir, feeddir, storedir]:
            if not os.path.exists(d):
                raise Exception("specified directory " + str(indir) +
                                " does not appear to be complete (missing " +
                                str(d) + ")")

        nextlinux_print("importing images...")
        #imagelist = []
        for ifile in os.listdir(imgdir):
            patt = re.match("(.*)\.json", ifile)
            if patt:
                imageId = patt.group(1)

                if contexts['nextlinux_db'].is_image_present(imageId):
                    nextlinux_print("\timage (" + str(imageId) +
                                  ") already exists in DB, skipping import.")
                else:
                    #imagelist.append(patt.group(1))
                    thefile = os.path.join(imgdir, ifile)
                    with open(thefile, 'r') as FH:
                        imagedata = json.loads(FH.read())
                    try:
                        rc = contexts['nextlinux_db'].save_image_new(
                            imageId, report=imagedata)
                        if not rc:
                            contexts['nextlinux_db'].delete_image(imageId)
                            raise Exception("save to nextlinux DB failed")
                    except Exception as err:
                        contexts['nextlinux_db'].delete_image(imageId)
                        raise err

                    thedir = os.path.join(storedir, imageId)
                    if os.path.exists(thedir):
                        for namespace in os.listdir(thedir):
                            thefile = os.path.join(thedir, namespace,
                                                   "stored_files.tar.gz")
                            if os.path.exists(thefile):
                                contexts['nextlinux_db'].save_files_tarfile(
                                    imageId, namespace, thefile)

                    nextlinux_print("\timage (" + str(imageId) + ") imported.")

        nextlinux_print("importing feeds...")
        thefile = os.path.join(feeddir, "feedmeta.json")
        with open(thefile, 'r') as FH:
            feedmeta = json.loads(FH.read())

        if feedmeta:
            contexts['nextlinux_db'].save_feedmeta(feedmeta)

        for feed in feedmeta:
            feedobj = feedmeta[feed]
            for group in feedobj['groups']:
                groupobj = feedobj['groups'][group]
                datafiles = groupobj.pop('datafiles', [])
                for datafile in datafiles:
                    thedir = os.path.join(feeddir, feed, group)
                    thefile = os.path.join(thedir, datafile)
                    if not os.path.exists(thefile):
                        pass
                    else:
                        with open(thefile, 'r') as FH:
                            contexts['nextlinux_db'].save_feed_group_data(
                                feed, group, datafile, json.loads(FH.read()))
                    nextlinux_print("\tfeed (" + feed + " " + group + " " +
                                  datafile + ") imported")

        #TODO import stored files

    except Exception as err:
        nextlinux_print_err("operation failed: " + str(err))
        ecode = 1

    sys.exit(ecode)
