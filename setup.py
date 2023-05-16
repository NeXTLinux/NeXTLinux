#!/usr/bin/python
from setuptools import setup, find_packages
from nextlinux import version

import os, shutil, errno

installroot = '/'
linux_default_config_location = os.path.join(installroot, 'etc/nextlinux')


def install_configs(overwrite=False):
    if overwrite:
        shutil.copytree('/usr/etc/nextlinux', linux_default_config_location)
    else:
        prefix = '/usr/etc/nextlinux'
        if not os.path.isdir(linux_default_config_location):
            try:
                os.makedirs(linux_default_config_location)
            except OSError:
                if errno != 17:
                    raise

        for f in os.listdir(prefix):
            oldfile = os.path.join(prefix, f)
            newfile = os.path.join(linux_default_config_location, f)

            if os.path.exists(newfile):
                shutil.copyfile(newfile, newfile + '.old')
                shutil.copyfile(oldfile, newfile)


with open('requirements.txt') as f:
    requirements = f.read().splitlines()

package_name = "nextlinux"

package_data = {
    package_name: ['conf/*',
                   'schemas/*',
                   'nextlinux-modules/analyzers/*',
                   'nextlinux-modules/gates/*',
                   'nextlinux-modules/queries/*',
                   'nextlinux-modules/multi-queries/*',
                   'nextlinux-modules/shell-utils/*',
                   'nextlinux-modules/examples/queries/*',
                   'nextlinux-modules/examples/multi-queries/*',
                   'nextlinux-modules/examples/analyzers/*',
                   'nextlinux-modules/examples/gates/*',
                   'doc/man/*'
                   ]
}

scripts = ['scripts/nextlinux_bash_completer']

nextlinux_description = 'A toolset for inspecting, querying, and curating containers'
nextlinux_long_description = open('README.rst').read()

url = 'https://github.com/nextlinux/nextlinux.git'

data_files = []

setup(
    name='nextlinux',
    author='Nextlinux Inc.',
    author_email='dev@next-linux.systems',
    license='Apache License 2.0',
    description=nextlinux_description,
    long_description=nextlinux_long_description,
    url=url,
    packages=find_packages(exclude=('conf*', 'tests*')),
    version=version,
    data_files=data_files,
    include_package_data=True,
    package_data=package_data,
    entry_points='''
    [console_scripts]
    nextlinux=nextlinux.cli:main_entry
    ''',
    install_requires=requirements,
    scripts=scripts
)
