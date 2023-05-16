#!/usr/bin/env python

import sys
import os
import re
import nextlinux.nextlinux_utils

try:
    config = nextlinux.nextlinux_utils.init_query_cmdline(
        sys.argv,
        "params: <base image ID> <base image ID> ...\nhelp: use 'all' to show all base image IDs"
    )
except:
    sys.exit(1)

if not config:
    sys.exit(0)

# clean up the input params into usable imageIds
newparams = list()

for name in config['params']:
    if name != 'all':
        try:
            imageId = nextlinux.nextlinux_utils.discover_imageId(name)
        except:
            imageId = name
    else:
        imageId = 'all'
    newparams.append(imageId)
config['params'] = newparams

print "PARAMS: " + str(config['params'])

outlist = list()
warns = list()
outlist.append([
    "Image_Id", "Repo_Tag", "From_Line", "Actual_Base_Id",
    "Current_From_Base_Id", "Status"
])

result = {}

allimages = {}
for imageId in config['images']:
    try:
        idata = nextlinux.nextlinux_utils.load_image_report(imageId)
        humanname = idata['meta']['humanname']

        realbaseid = None
        familytree = []
        # get the earliest image Id in the familytree as a baseline for the base id
        if idata and 'familytree' in idata and len(idata['familytree']) > 0:
            familytree = idata['familytree']
            realbaseid = familytree[0]

        # get the current fromline and fromID of the image's FROM
        (thefrom, thefromid) = nextlinux.nextlinux_utils.discover_from_info(
            idata['dockerfile_contents'])

        # look for an image in the actual familytree that has or has had the tag in the image's FROM line
        if thefrom and familytree:
            for f in familytree:
                fdata = nextlinux.nextlinux_utils.load_image_report(f)
                if fdata and 'nextlinux_all_tags' in fdata:
                    if thefrom in fdata['nextlinux_all_tags']:
                        # found it, this is the real imageID of the image that has/has had the tar in image's FROM line
                        realbaseid = f
                        break

        if realbaseid and thefromid:
            if realbaseid == imageId:
                outlist.append([
                    imageId, humanname, thefrom, realbaseid, 'N/A',
                    'up-to-date'
                ])
            elif thefromid == 'scratch' or thefromid == '<unknown>':
                outlist.append(
                    [imageId, humanname, thefrom, realbaseid, 'N/A', 'N/A'])
            elif thefromid not in idata['familytree']:
                outlist.append([
                    imageId, humanname, thefrom, realbaseid, thefromid,
                    'out-of-date'
                ])
            else:
                outlist.append([
                    imageId, humanname, thefrom, thefromid, thefromid,
                    'up-to-date'
                ])

        else:
            warns.append("imageId (" + imageId +
                         "): could not evaluate base status: fromline=" +
                         str(thefrom) + " realbaseid=" + str(realbaseid) +
                         " fromid=" + str(thefromid))

    except Exception as err:
        warns.append("Exception: " + str(err))

nextlinux.nextlinux_utils.write_kvfile_fromlist(config['output'], outlist)
if len(warns) > 0:
    nextlinux.nextlinux_utils.write_plainfile_fromlist(config['output_warns'],
                                                   warns)

allimages.clear()
sys.exit(0)
