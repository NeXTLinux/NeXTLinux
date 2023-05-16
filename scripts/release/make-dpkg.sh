#!/bin/bash

if [ ! -f 'setup.py' -o ! -d 'nextlinux' ]; then
    echo "Looks like you are not running this from the root nextlinux code checkout - go there and try again (cd /path/to/checkout/of/nextlinux; ./scripts/release/make-rpm.sh)"
    exit 1
fi

REL=$1

if [ -z "$REL" ]; then
    echo "Need to pass a release number/string as parameter to this script"
    exit 1
fi


python setup.py --command-packages=stdeb.command sdist_dsc --debian-version "$REL" --depends "python-click,python-clint,python-docker,python-prettytable,python-yaml,python-colorama,python-args,python-websocket,libyaml-0-2,python-backports.ssl-match-hostname,python-rpm,yum,python-jsonschema" bdist_deb
python setup.py clean --all
rm -rf nextlinux-*.tar.gz dist/ nextlinux.egg-info/
mv deb_dist dist
