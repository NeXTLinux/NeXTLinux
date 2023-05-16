import sys
import click
import logging
import json

from nextlinux import analyzer, controller, nextlinux_utils, nextlinux_policy
from nextlinux.cli.common import build_image_list, nextlinux_print, nextlinux_print_err, extended_help_option
from nextlinux.util import contexts

_logger = logging.getLogger(__name__)

gate_extended_help = """
Run gate analysis on the specified images with the specified options or else edits the policy that is effective for a specific image or
all images. Nextlinux gates are a set of checks against the image, image's dockerfile and other data sources (e.g. CVEs). The default gate policy
file is found in $nextlinux/conf/nextlinux_gate.policy, where $nextlinux = $HOME/.nextlinux (default) or /etc/nextlinux depending on installation.

Image IDs can be specified as hash ids, repo names (e.g. centos), or tags (e.g. centos:latest).

See the policy file for the set of available gates and their triggers.

\b
The output of each gate is one of:
* GO - Check is ok, no trigger fired
* STOP - Trigger found something. Policy says to output a stop
* WARN - Emit a warning to flag this as something to follow-up on.

The gate results are only output to the user, so their meaning is entirely up to the user. A typical use would be to
not push any container image to production if it has any 'STOP' gate results. But, how to use the gate output is entirely
up to the user.

Editing Gate Policies:

Nextlinux has a global gate policy document, but this can be overridden for each individual image if desired by
running '--editpolicy' for the desired image. The policy file opened for editing will be specific to the image.
A gate policy file is composed of lines of the following format:

<Gate Name>:<Trigger Name>:<Result if triggered>

Gate Policy Example:

``DOCKERFILECHECK:NOFROM:STOP`` specifies a check against an image's dockerfile (if available) such that if the 'NOFROM' trigger evaluates to true then the gate action will be 'STOP'


Usage Examples:

View gate output for the 'node:latest' image:
'nextlinux gate --image node:latest'

View gate output for all images:
'nextlinux gate'

Edit the gate policy for 'nginx:latest':
'nextlinux gate --image nginx:latest --editpolicy'

"""


@click.command(short_help='Perform and view gate evaluation on selected images'
               )
@click.option('--force',
              is_flag=True,
              help='Force gates to run even if they already have.')
@click.option(
    '--image',
    help='Process specified image ID. Cannot be combined with --imagefile',
    metavar='<imageid>')
@click.option(
    '--imagefile',
    help=
    'Process image IDs listed in specified file. Cannot be combined with --image',
    type=click.Path(exists=True),
    metavar='<file>')
@click.option('--include-allnextlinux',
              help='Include all images known by nextlinux',
              is_flag=True)
@click.option('--editpolicy',
              is_flag=True,
              help='Edit the gate policies for specified image(s).')
@click.option(
    '--rmpolicy',
    is_flag=True,
    help='Delete the policies for specified image(s), revert to default policy.'
)
@click.option('--listpolicy',
              is_flag=True,
              help='List the current gate policy for specified image(s).')
@click.option(
    '--updatepolicy',
    help=
    'Store the input gate policy file as the policy for specified image(s).',
    type=click.Path(exists=True),
    metavar='<file>')
@click.option('--policy',
              help='Use the specified policy file instead of the default.',
              type=click.Path(exists=True),
              metavar='<file>')
@click.option(
    '--run-bundle',
    help=
    'Evaluate using an nextlinux policy bundle (see "nextlinux policybundle sync" to get your bundle from nextlinux.io)',
    is_flag=True)
@click.option(
    '--bundlefile',
    help=
    'Use the specified bundle JSON from specified file instead of the stored bundle from "nextlinux policybundle sync".',
    type=click.Path(exists=True),
    metavar='<file>')
@click.option(
    '--usetag',
    help=
    'User the specified tag to evaluate the input image when using --run-bundle',
    metavar='<imagetag>',
    multiple=True)
@click.option(
    '--resultsonly',
    help=
    'With --run-bundle, show only evaluation results (same as regular gate output)',
    is_flag=True)
@click.option(
    '--show-gatehelp',
    help=
    'Show all gate names, triggers, and params that can be used to build an nextlinux policy',
    is_flag=True)
@click.option(
    '--show-policytemplate',
    help='Generate policy template based on all installed gate/triggers',
    is_flag=True)
@click.option(
    '--whitelist',
    is_flag=True,
    help='Edit evaluated gate triggers and optionally whitelist them.')
@click.option('--global-whitelist',
              help='Use the specified global whitelist file.',
              type=click.Path(exists=True),
              metavar='<file>')
@click.option('--show-triggerids',
              is_flag=True,
              help='Show triggered gate IDs in output')
@click.option('--show-whitelisted',
              is_flag=True,
              help='Show gate triggers even if whitelisted (with annotation).')
@click.pass_obj
@extended_help_option(extended_help=gate_extended_help)
def gate(nextlinux_config, force, image, imagefile, include_allnextlinux,
         editpolicy, rmpolicy, listpolicy, updatepolicy, policy, run_bundle,
         bundlefile, usetag, resultsonly, show_gatehelp, show_policytemplate,
         whitelist, global_whitelist, show_triggerids, show_whitelisted):
    """
    Runs gate checks on the specified image(s) or edits the image's gate policy.
    The --editpolicy option is only valid for a single image.

    The --image and --imagefile options are mutually exclusive.

    Image IDs can be specified as hash ids, repo names (e.g. centos), or tags (e.g. centos:latest).
    """

    ecode = 0
    success = True

    # special option, does not need any image inputs
    if show_gatehelp:
        try:
            gate_info = nextlinux_utils.discover_gates()
            nextlinux_print(gate_info, do_formatting=True)
        except Exception as err:
            nextlinux_print_err("operation failed: " + str(err))
            sys.exit(1)
        sys.exit(0)

    if show_policytemplate:
        try:
            outstr = "\n"
            gate_info = nextlinux_utils.discover_gates()
            for g in gate_info.keys():
                for t in gate_info[g].keys():
                    params = list()
                    if 'params' in gate_info[g][t] and gate_info[g][t][
                            'params'] and gate_info[g][t]['params'].lower(
                            ) != 'none':
                        for p in gate_info[g][t]['params'].split(','):
                            params.append(p + "=<a,b,c>")

                    outstr += ':'.join(
                        [g, t, "<STOP|WARN|GO>", ' '.join(params)]) + "\n"

            nextlinux_print(outstr, do_formatting=False)
        except Exception as err:
            nextlinux_print_err("operation failed: " + str(err))
            sys.exit(1)
        sys.exit(0)

    # the rest require some form of image(s) be given as input
    if image and imagefile:
        raise click.BadOptionUsage('Can only use one of --image, --imagefile')

    if policy and (editpolicy or whitelist or listpolicy or updatepolicy
                   or rmpolicy):
        raise click.BadOptionUsage(
            'Cannot use other policy options when --policy <file> is specified.'
        )

    if (policy and run_bundle):
        raise click.BadOptionUsage(
            'Cannot use both --policy and --run_bundle at the same time.')

    if (run_bundle and
        (editpolicy or whitelist or listpolicy or updatepolicy or rmpolicy)):
        raise click.BadOptionUsage(
            'Cannot use other policy options when --run_bundle is specified.')

    if (run_bundle and (usetag and resultsonly)):
        raise click.BadOptionUsage(
            'Cannot use --resultsonly if --usetag is specified.')

    if (run_bundle and (usetag and not image)):
        raise click.BadOptionUsage(
            'Cannot specify --usetag unless gating a single image (using --image)'
        )

    try:
        imagedict = build_image_list(nextlinux_config, image, imagefile,
                                     not (image or imagefile),
                                     include_allnextlinux)
        imagelist = imagedict.keys()
        inputimagelist = list(imagelist)

        try:
            ret = nextlinux_utils.discover_imageIds(imagelist)
        except ValueError as err:
            raise err
        else:
            imagelist = ret

    except Exception as err:
        nextlinux_print_err("could not load any images")
        sys.exit(1)

    try:
        con = controller.Controller(nextlinux_config=nextlinux_config,
                                    imagelist=imagelist,
                                    allimages=contexts['nextlinux_allimages'],
                                    force=force)
    except Exception as err:
        nextlinux_print_err("gate operation failed")
        ecode = 1
    else:
        if editpolicy:
            if not con.editpolicy():
                ecode = 1
        elif whitelist:
            if not con.editwhitelist():
                ecode = 1
        elif rmpolicy:
            if not con.rmpolicy():
                ecode = 1
            else:
                nextlinux_print("policies successfully removed.",
                              do_formatting=True)
        elif updatepolicy:
            if not con.updatepolicy(updatepolicy):
                ecode = 1
            else:
                nextlinux_print("policies successfully updated.",
                              do_formatting=True)
        elif listpolicy:
            result = con.listpolicy()
            record = {}
            if not result:
                ecode = 1
            else:
                try:
                    for imageId in result.keys():
                        record[imageId] = list()
                        pol = result[imageId]
                        for gate in pol.keys():
                            for trigger in pol[gate].keys():
                                if str(pol[gate][trigger]['params']):
                                    outstr = ":".join([
                                        gate, trigger,
                                        str(pol[gate][trigger]['action']),
                                        str(pol[gate][trigger]['params'])
                                    ])
                                else:
                                    outstr = ":".join([
                                        gate, trigger,
                                        str(pol[gate][trigger]['action'])
                                    ])
                                record[imageId].append(outstr)
                    if record:
                        nextlinux_print(record, do_formatting=True)
                except Exception as err:
                    nextlinux_print_err("failed to list policies: " + str(err))
                    ecode = 1
        elif run_bundle:
            try:
                if not nextlinux_policy.check():
                    nextlinux_print_err(
                        "run-bundle specified, but it appears as though no policy bundles have been synced yet: run 'nextlinux policybundle sync' to get your latest bundles from nextlinux.io"
                    )
                    ecode = 1
                else:
                    bundle = nextlinux_policy.load_policymeta(
                        policymetafile=bundlefile)
                    if not bundle:
                        raise Exception(
                            "could not load stored bundle - run 'nextlinux policybundle sync' and try again"
                        )

                    bundleId = bundle['id']

                    inputimage = inputimagelist[0]

                    allresults = {}
                    for inputimage in inputimagelist:
                        result, image_ecode = nextlinux_policy.run_bundle(
                            nextlinux_config=nextlinux_config,
                            image=inputimage,
                            matchtags=usetag,
                            bundle=bundle,
                            show_whitelisted=show_whitelisted,
                            show_triggerIds=show_triggerids)
                        allresults.update(result)

                        if image_ecode == 1:
                            ecode = 1
                        elif ecode == 0 and image_ecode > ecode:
                            ecode = image_ecode

                    if not resultsonly:
                        if nextlinux_config.cliargs['json']:
                            nextlinux_print(json.dumps(allresults))
                        else:
                            for image in allresults.keys():
                                for gate_result in allresults[image][
                                        'evaluations']:
                                    _logger.info(
                                        "Image=" + image + " BundleId=" +
                                        bundleId + " Policy=" +
                                        gate_result['policy_name'] +
                                        " Whitelists=" +
                                        str(gate_result['whitelist_names']))
                                    nextlinux_utils.print_result(
                                        nextlinux_config, gate_result['results'])
                    else:
                        final_result = {}
                        for image in allresults.keys():
                            for gate_result in allresults[image][
                                    'evaluations']:
                                final_result.update(gate_result['results'])
                        nextlinux_utils.print_result(nextlinux_config,
                                                   final_result)
            except Exception as err:
                nextlinux_print_err("failed to run gates")
                ecode = 1

        else:
            try:
                # run the gates
                result = con.run_gates(policy=policy,
                                       global_whitelist=global_whitelist,
                                       show_triggerIds=show_triggerids,
                                       show_whitelisted=show_whitelisted)
                if result:
                    nextlinux_utils.print_result(nextlinux_config, result)
                    success = True
                    ecode = con.result_get_highest_action(result)
            except Exception as err:
                nextlinux_print_err("failed to run gates")
                ecode = 1

    contexts['nextlinux_allimages'].clear()
    sys.exit(ecode)


analyze_extended_help = """
Run the analyzer to scan and summarize a container image and store that analysis in the local host's nextlinux image db for further use in gating, reports, and queries.

Upon completion of analysis of an image there will be an entry in the
db named with the imageid (a directory in $nextlinux/data/, where
$nextlinux = $HOME/.nextlinux (default) or /etc/nextlinux depending on
installation). If the analyzer detects that an image has already been
analyzed it will skip analysis. This behavior can be overridden with
the '--force' flag.

To get the full power of analysis and subsequent gate and query tools
it is recommended to include the dockerfile as often as possible.
When using --dockerfile, you must use --image and specify a single
image. This allows nextlinux to associate that specific dockerfile with
the image in the analysis output. Nextlinux will always try to infer a
dockerfile, but certain constructs and operations in dockerfiles
become opaque after the image is built (e.g. COPY operations, or RUN
operations that invoke a tool that loads data on the image), so
including the actual dockerfile results in the best analysis output
and makes more information available for gate evaluation and later
queries.

Image IDs can be specified as hash ids, repo names (e.g. centos), or tags (e.g. centos:latest).

Image Types: ["none"|"base"]
Specify the type of the image being analyzed. Use 'base' to tell nextlinux that the given image is a base image to be
used to build other images. Use 'none' to not assign a specific image type to the image.


Examples:

Analyze all images listed in a file that contains lines of the form '<image ID> <path/to/dockerfile>' on the local host:

'nextlinux analyze --imagefile myimages.txt'

Analyze a newly built image with it's corresponding dockerfile:

'nextlinux analyze --image myapp:latest --dockerfile myapp.dockerfile'

Analyze all image on the local host except a list (perhaps local tools used in the build process, etc):

'nextlinux analyze --excludefile exclusions.txt'
"""

strategies = [
    'BaseOnly',
]


@click.command(short_help='Perform analysis on specified image IDs.')
@click.option('--force',
              is_flag=True,
              help='Force analysis even if existing analysis is found in db.')
@click.option('--image',
              help='Process specified image ID',
              metavar='<imageid>')
@click.option('--imagefile',
              help='Process image IDs listed in specified file.',
              type=click.Path(exists=True),
              metavar='<file>')
@click.option(
    '--include-allnextlinux',
    help='Include all images known by nextlinux, as found in host-local db',
    is_flag=True)
#@click.option('--imagetar', help='Use with --image if you have a tar of the image instead of having nextlinux save from docker', type=click.Path(exists=True), metavar='<file>')
@click.option('--dockerfile',
              help='Dockerfile of the image to analyze.',
              type=click.Path(exists=True),
              metavar='<file>')
@click.option(
    '--imagetype',
    help=
    'Specify the type of image that is being analyzed (use "none" if unknown).',
    metavar='<typetext>')
@click.option('--skipgates',
              is_flag=True,
              help='Do not run gates as part of analysis.')
@click.option(
    '--layerstrategy',
    type=click.Choice(analyzer.strategies.keys()),
    help=
    'Name of strategy to use for analyzing images in the history of the requested images. Identified by parentIds/imageid in `docker history` output.',
    default='BaseOnly')
@click.option(
    '--excludefile',
    help=
    'Name of file containing images to exclude during analysis. Each line is an image name/id',
    type=click.Path(exists=True),
    metavar='<file>')
@click.pass_obj
@extended_help_option(extended_help=analyze_extended_help)
def analyze(nextlinux_config, force, image, imagefile, include_allnextlinux,
            dockerfile, imagetype, skipgates, layerstrategy, excludefile):
    """
    Invokes the nextlinux analyzer on the specified image(s).

    To include multiple images use the --imagefile, no option, or --include-allnextlinux options.
    To exclude specific images from analysis, use the --excludefile option.

    One of --imagetype or --dockerfile should be supplied for an analysis run. Use --dockerfile whenever possible as the inclusion
    of the dockerfile for an image associates the dockerfile and image for later use in queries etc. The --dockerfile option
    is only valid in combination with the --image option.  If neither --dockerfile and --imagetype is supplied, then 

    When using --imagetype, use 'none' to specify that the image(s) is an unknown or user image and use 'base' to specify
    that the image(s) are approved base images to be used to build other images or it is useful to mark the image one from which
    other images are meant to be derived.

    Image IDs can be specified as hash ids, repo names (e.g. centos), or tags (e.g. centos:latest).

    """

    success = True
    ecode = 0

    args = {}

    if image and imagefile:
        raise click.BadOptionUsage('Can only use one of --image, --imagefile')

    if dockerfile and not image:
        raise click.BadOptionUsage(
            'Must specify --image option when using --dockerfile option')

    if not imagefile:
        if imagetype:
            if imagetype == "nextlinuxbase":
                args['nextlinuxbase'] = True
            elif imagetype == "base":
                args['isbase'] = True
            elif imagetype == "none":
                pass
            else:
                raise click.BadOptionUsage(
                    "Invalid imagetype specified: valid types are 'none' or 'base'"
                )

    try:
        imagedict = build_image_list(nextlinux_config,
                                     image,
                                     imagefile,
                                     not (image or imagefile),
                                     include_allnextlinux,
                                     exclude_file=excludefile,
                                     dockerfile=dockerfile)
        imagelist = imagedict.keys()

        try:
            ret = nextlinux_utils.discover_imageIds(imagelist)
        except ValueError as err:
            raise err
        else:
            #imagelist = ret.keys()
            imagelist = ret

    except Exception as err:
        nextlinux_print_err("could not load any images")
        ecode = 1
    else:

        step = 1
        count = 0
        allimages = {}
        success = True
        for imageId in imagedict.keys():

            if count % step == 0:
                allimages.clear()
                allimages = {}
                count = 0

            args.update({
                'dockerfile': imagedict[imageId]['dockerfile'],
                'skipgates': skipgates,
                'selection_strategy': layerstrategy
            })

            inlist = [imageId]
            try:
                nextlinux_print("Analyzing image: " + imageId)
                rc = analyzer.Analyzer(nextlinux_config=nextlinux_config,
                                       imagelist=inlist,
                                       allimages=allimages,
                                       force=force,
                                       args=args).run()
                if not rc:
                    nextlinux_print_err("analysis failed.")
                    success = False
                    ecode = 1

            except:
                nextlinux_print_err('failed to run analyzer')
                allimages.clear()
                success = False
                ecode = 1
                break

            count = count + 1

        allimages.clear()

        if not success:
            nextlinux_print_err("analysis failed for one or more images.")
            ecode = 1

    sys.exit(ecode)
