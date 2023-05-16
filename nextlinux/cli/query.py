import sys
import click

from nextlinux.cli.common import build_image_list, nextlinux_print, nextlinux_print_err, extended_help_option
from nextlinux import navigator, nextlinux_utils
from nextlinux.util import contexts

config = {}
imagelist = []
nav = None


@click.command(short_help='Run specified query (leave blank to show list).')
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
@click.argument('module', nargs=-1, metavar='<modulename>')
@click.pass_obj
@extended_help_option()
def query(nextlinux_config, image, imagefile, include_allnextlinux, module):
    """
    Image IDs can be specified as hash ids, repo names (e.g. centos), or tags (e.g. centos:latest).

    Execute the specified query (module) with any parameters it requires. Modules are scripts in a specific location.

    Each query has its own parameters and outputs.

    Examples using pre-defined queries:

    'nextlinux query --image nginx:latest list-packages all'
    'nextlinux query has-package wget'
    'nextlinux query --image nginx:latest list-files-detail all'
    'nextlinux query cve-scan all'

    """

    global config, imagelist, nav
    ecode = 0
    success = True
    config = nextlinux_config

    if module:
        if image and imagefile:
            raise click.BadOptionUsage(
                'Can only use one of --image, --imagefile')

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
                #imagelist = ret.keys()
                imagelist = ret

        except Exception as err:
            nextlinux_print_err("could not load input images")
            sys.exit(1)

    try:
        nav = init_nav_contexts()

        result = nav.run_query(list(module))
        if result:
            nextlinux_utils.print_result(config, result)

        if nav.check_for_warnings(result):
            ecode = 2

    except:
        nextlinux_print_err("query operation failed")
        ecode = 1

    contexts['nextlinux_allimages'].clear()
    sys.exit(ecode)


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
