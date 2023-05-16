import sys
import click

from nextlinux.cli.common import build_image_list, nextlinux_print, nextlinux_print_err, extended_help_option
from nextlinux import navigator, nextlinux_utils
from nextlinux.util import contexts

config = {}
imagelist = []
nav = None


@click.group(short_help='Commands to generate/review audit reports')
@click.option('--image',
              help='Process specified image ID',
              metavar='<imageid>')
@click.option('--imagefile',
              help='Process image IDs listed in specified file',
              type=click.Path(exists=True),
              metavar='<file>')
@click.option('--include-allnextlinux',
              help='Include all images known by nextlinux',
              is_flag=True)
@click.pass_context
@click.pass_obj
@extended_help_option()
def audit(nextlinux_config, ctx, image, imagefile, include_allnextlinux):
    """
    Image IDs can be specified as hash ids, repo names (e.g. centos), or tags (e.g. centos:latest).
    """

    global config, imagelist, nav
    ecode = 0
    success = True
    config = nextlinux_config

    #include_allnextlinux = True

    if image and imagefile:
        raise click.BadOptionUsage('Can only use one of --image, --imagefile')

    #if image or imagefile:
    #    include_allnextlinux = False

    try:
        imagedict = build_image_list(nextlinux_config, image, imagefile,
                                     not (image or imagefile),
                                     include_allnextlinux)
        imagelist = imagedict.keys()
        try:
            ret = nextlinux_utils.discover_imageIds(imagelist)
        except ValueError as err:
            raise err
        else:
            imagelist = ret

    except Exception as err:
        nextlinux_print_err("could not load input images")
        sys.exit(1)


def init_nav_contexts():
    try:
        # use the obj from the current click context. This is a bit hacky, but works as long as this method is
        # invoked in an execution context of click
        nextlinux_config = click.get_current_context().obj
        nav = navigator.Navigator(nextlinux_config=nextlinux_config,
                                  imagelist=imagelist,
                                  allimages=contexts['nextlinux_allimages'])
        return nav
    except Exception as err:
        nextlinux_print_err("explore operation failed")
        success = False
        ecode = 1

    if not success:
        contexts['nextlinux_allimages'].clear()
        sys.exit(ecode)


@audit.command(short_help='Generate summarized report of specified images.')
#@click.option('--all', help='Show all images including intermediate layer images (default shows only images with a type)', is_flag=True)
#@click.option('--details', help='Show many details in the report (including full image details if --json is supplied)', is_flag=True)
@extended_help_option()
#def report(all, details):
def report():
    """
    Show analysis report of the specified image(s).

    The analysis report includes information on:

    \b
    Image Id - The image id (as a hash)

    Type - The type of image (--imagetype option used when nextlinux analyze was run)

    CurrentTags - The current set of repo tags on the image

    AllTags - The set of all repo tags that have been on the image during analysis passes

    GateStatus - The overall aggregate gate output status: GO|STOP|WARN

    Size - The size in bytes of the image on disk
    
    Counts - The counts for various attributes of the images such as packages, files, and suid files

    BaseDiffs - Differences of this image from its base image

    Report outputs these entries in a table format by default.
    """
    ecode = 0

    try:
        nav = init_nav_contexts()
        result = nav.generate_reports()

        #result = generate_reports(imagelist, showall=all, showdetails=details)

        if result:
            nextlinux_utils.print_result(config, result)

    except:
        nextlinux_print_err("operation failed")
        ecode = 1

    contexts['nextlinux_allimages'].clear()
    sys.exit(ecode)


def generate_reports(imagelist, showall=True, showdetails=True):
    ret = {}

    if showdetails:
        header = [
            'Image_Id', '*Type', 'Current_Tags', 'All_Tags', 'Is_Analyzed',
            'Gate_Status', 'Size(bytes)', 'Counts', 'Base_Diffs'
        ]
    else:
        header = [
            'Image_Id', '*Type', 'Tags', 'Is_Analyzed', 'Gate_Status',
            'Size(bytes)'
        ]

    for imageId in imagelist:
        isanalyzed = str(nextlinux_utils.is_image_analyzed(imageId))
        ireport = nextlinux_utils.load_image_report(imageId)
        if ireport:
            usertype = str(ireport['meta']['usertype'])
            currtags = ','.join(ireport['nextlinux_current_tags'])
            alltags = ','.join(ireport['nextlinux_all_tags'])
        else:
            usertype = "None"
            try:
                idocker = contexts['docker_images'][imageId]
                currtags = ','.join(idocker['RepoTags'])
                alltags = currtags
            except:
                currtags = alltags = "N/A"

        if not showall and ((not usertype or usertype.lower() == 'none') and
                            (not currtags and not alltags)):
            continue

        if ireport:
            baseId = str(ireport['familytree'][0])
            sizebytes = str(ireport['meta']['sizebytes'])
            shortId = str(ireport['meta']['shortId'])

        else:
            baseId = "N/A"
            sizebytes = "N/A"
            shortId = imageId[0:12]

        gates_eval_report = nextlinux_utils.load_gates_eval_report(imageId)
        record = {
            'image_report': ireport,
            'analysis_report': {},
            'gates_report': {},
            'gates_eval_report': gates_eval_report,
            'result': {
                'header': header,
                'rows': list()
            }
        }

        if showdetails:
            record['analysis_report'] = nextlinux_utils.load_analysis_report(
                imageId)
            record['gates_report'] = nextlinux_utils.load_gates_report(imageId)

        gateaction = 'UNKNOWN'
        for g in gates_eval_report:
            if g['trigger'] == 'FINAL':
                gateaction = g['action']
                break

        if showdetails:
            try:
                pnum = str(
                    len(
                        nextlinux_utils.load_analysis_output(
                            imageId, 'package_list', 'pkgs.all').keys()))
            except:
                pnum = "N/A"
            try:
                fnum = str(
                    len(
                        nextlinux_utils.load_analysis_output(
                            imageId, 'file_list', 'files.all').keys()))
            except:
                fnum = "N/A"
            try:
                snum = str(
                    len(
                        nextlinux_utils.load_analysis_output(
                            imageId, 'file_suids', 'files.suids').keys()))
            except:
                snum = "N/A"

            analysis_str = ' '.join(
                ["PKGS=" + pnum, "FILES=" + fnum, "SUIDFILES=" + snum])

            compare_str = "N/A"

            if imageId != baseId:
                diffdata = nextlinux_utils.diff_images(imageId, baseId)
                record['base_compare_data'] = diffdata
                pnum = "N/A"
                if 'package_list' in diffdata and 'pkgs.all' in diffdata[
                        'package_list']:
                    for module_type in diffdata['package_list']['pkgs.all']:
                        pnum = str(
                            len(diffdata['package_list']['pkgs.all']
                                [module_type]))
                        break

                fnum = "N/A"
                if 'file_list' in diffdata and 'files.all' in diffdata[
                        'file_list']:
                    for module_type in diffdata['file_list']['files.all']:
                        fnum = str(
                            len(diffdata['file_list']['files.all']
                                [module_type]))

                snum = "N/A"
                if 'file_suids' in diffdata and 'files.suids' in diffdata[
                        'file_suids']:
                    for module_type in diffdata['file_suids']['files.suids']:
                        snum = str(
                            len(diffdata['file_suids']['files.suids']
                                [module_type]))

                compare_str = ' '.join(
                    ["PKGS=" + pnum, "FILES=" + fnum, "SUIDFILES=" + snum])

            row = [
                shortId, usertype, currtags, alltags, isanalyzed, gateaction,
                sizebytes, analysis_str, compare_str
            ]
        else:
            row = [
                shortId, usertype, currtags, isanalyzed, gateaction, sizebytes
            ]

        record['result']['rows'].append(row)

        ret[imageId] = record

    return ret
