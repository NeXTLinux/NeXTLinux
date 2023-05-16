import yaml
import os
import shutil
import filecmp
import datetime
import tarfile

from util.tools import load_and_merge
from pkg_resources import Requirement, resource_filename


class NextlinuxConfiguration(object):
    """
    Backed by a yaml file
    """

    DEFAULT_NEXTLINUX_DATA_DIR = os.path.join(os.getenv('HOME'), '.nextlinux')
    DEFAULT_CONFIG_DIR = os.path.join(DEFAULT_NEXTLINUX_DATA_DIR, 'conf')
    DEFAULT_CONFIG_FILE = os.path.join(DEFAULT_CONFIG_DIR, 'config.yaml')
    DEFAULT_TMP_DIR = os.path.join(DEFAULT_NEXTLINUX_DATA_DIR, 'nextlinuxtmp')
    EXAMPLE_CONFIG_DIR = resource_filename("nextlinux", "conf/")
    EXAMPLE_CONFIG_FILE = resource_filename("nextlinux", "conf/config.yaml")
    DEFAULT_PKG_DIR = resource_filename("nextlinux", "")
    DEFAULT_SCRIPTS_DIR = resource_filename("nextlinux", "nextlinux-modules")
    DEFAULT_ANON_NEXTLINUX_USERNAME = 'anon@next-linux.systems'
    DEFAULT_ANON_NEXTLINUX_PASSWORD = 'pbiU2RYZ2XrmYQ'
    DEFAULT_NEXTLINUX_CLIENT_URL = 'https://next-linux.systems/v1/account/users'
    DEFAULT_NEXTLINUX_TOKEN_URL = 'https://next-linux.systems/oauth/token'
    DEFAULT_NEXTLINUX_FEEDS_URL = 'https://next-linux.systems/v1/service/feeds'
    DEFAULT_NEXTLINUX_POLICY_URL = 'https://next-linux.systems/v1/service/policies/policy'
    DEFAULT_NEXTLINUX_AUTH_CONN_TIMEOUT = 10
    DEFAULT_NEXTLINUX_AUTH_MAX_RETRIES = 3
    DEFAULT_NEXTLINUX_FEEDS_CONN_TIMEOUT = 45
    DEFAULT_NEXTLINUX_FEEDS_MAX_RETRIES = 3
    DEFAULT_NEXTLINUX_POLICY_CONN_TIMEOUT = 45
    DEFAULT_NEXTLINUX_POLICY_MAX_RETRIES = 3
    DEFAULT_NEXTLINUX_DB_DRIVER = "nextlinux_image_db_fs"
    DEFAULT_NEXTLINUX_SQUASH_DRIVER = "docker_export"

    try:
        DEFAULT_EXTRASCRIPTS_DIR = resource_filename("nextlinux-modules", "/")
    except:
        DEFAULT_EXTRASCRIPTS_DIR = None

    DEFAULTS = {
        'nextlinux_data_dir': DEFAULT_NEXTLINUX_DATA_DIR,
        'nextlinux_db_driver': DEFAULT_NEXTLINUX_DB_DRIVER,
        'feeds_dir': 'feeds',
        'feeds_url': DEFAULT_NEXTLINUX_FEEDS_URL,
        'feeds_conn_timeout': DEFAULT_NEXTLINUX_FEEDS_CONN_TIMEOUT,
        'feeds_max_retries': DEFAULT_NEXTLINUX_FEEDS_MAX_RETRIES,
        'policy_dir': 'policy',
        'policy_url': DEFAULT_NEXTLINUX_POLICY_URL,
        'policy_conn_timeout': DEFAULT_NEXTLINUX_POLICY_CONN_TIMEOUT,
        'policy_max_retries': DEFAULT_NEXTLINUX_POLICY_MAX_RETRIES,
        'image_data_store': 'data',
        'tmpdir': DEFAULT_TMP_DIR,
        'pkg_dir': DEFAULT_PKG_DIR,
        'scripts_dir': DEFAULT_SCRIPTS_DIR,
        'user_scripts_dir': 'user-scripts',
        'extra_scripts_dir': DEFAULT_EXTRASCRIPTS_DIR,
        'docker_conn': 'unix://var/run/docker.sock',
        'docker_conn_timeout': '120',
        'nextlinux_client_url': DEFAULT_NEXTLINUX_CLIENT_URL,
        'nextlinux_token_url': DEFAULT_NEXTLINUX_TOKEN_URL,
        'nextlinux_auth_conn_timeout': DEFAULT_NEXTLINUX_AUTH_CONN_TIMEOUT,
        'nextlinux_auth_max_retries': DEFAULT_NEXTLINUX_AUTH_MAX_RETRIES,
        'squash_driver': DEFAULT_NEXTLINUX_SQUASH_DRIVER
    }

    def __init__(self, cliargs=None):
        # config file handling

        # handle override of the default .nextlinux location
        if os.getenv('NEXTLINUXDATADIR'):
            self.DEFAULT_NEXTLINUX_DATA_DIR = os.getenv('NEXTLINUXDATADIR')
            self.DEFAULT_CONFIG_DIR = os.path.join(
                self.DEFAULT_NEXTLINUX_DATA_DIR, 'conf')
            self.DEFAULT_CONFIG_FILE = os.path.join(self.DEFAULT_CONFIG_DIR,
                                                    'config.yaml')
            self.DEFAULT_TMP_DIR = os.path.join(self.DEFAULT_NEXTLINUX_DATA_DIR,
                                                'nextlinuxtmp')
            self.DEFAULTS['tmpdir'] = self.DEFAULT_TMP_DIR
            self.DEFAULTS['nextlinux_data_dir'] = self.DEFAULT_NEXTLINUX_DATA_DIR

        self.config_dir, self.config_file = self.find_config_file()
        try:
            self.data = load_and_merge(file_path=self.config_file,
                                       defaults=self.DEFAULTS)

            self.cliargs = {}
            if cliargs:
                # store CLI arguments
                self.cliargs = cliargs

            if 'config_overrides' in self.cliargs and self.cliargs[
                    'config_overrides']:
                for override_key in self.cliargs['config_overrides']:
                    if override_key in self.data:
                        self.data[override_key] = self.cliargs[
                            'config_overrides'][override_key]

            if not os.path.exists(self.data['nextlinux_data_dir']):
                os.makedirs(self.data['nextlinux_data_dir'])

            if not os.path.exists(self.data['tmpdir']):
                os.makedirs(self.data['tmpdir'])

            #update relative to data dir if not an absolute path
            if not os.path.isabs(self.data['image_data_store']):
                self.data['image_data_store'] = os.path.join(
                    self.data['nextlinux_data_dir'],
                    self.data['image_data_store'])

            if not os.path.exists(self.data['image_data_store']):
                os.makedirs(self.data['image_data_store'])

            if not os.path.isabs(self.data['feeds_dir']):
                self.data['feeds_dir'] = os.path.join(
                    self.data['nextlinux_data_dir'], self.data['feeds_dir'])

            if not os.path.isabs(self.data['policy_dir']):
                self.data['policy_dir'] = os.path.join(
                    self.data['nextlinux_data_dir'], self.data['policy_dir'])

            if not os.path.isabs(self.data['user_scripts_dir']):
                self.data['user_scripts_dir'] = os.path.join(
                    self.data['nextlinux_data_dir'],
                    self.data['user_scripts_dir'])

            if not os.path.exists(self.data['user_scripts_dir']):
                os.makedirs(self.data['user_scripts_dir'])

            for d in [
                    'analyzers', 'gates', 'queries', 'multi-queries',
                    'shell-utils'
            ]:
                thedir = os.path.join(self.data['user_scripts_dir'], d)
                if not os.path.exists(thedir):
                    os.makedirs(thedir)

            dc = filecmp.dircmp(
                os.path.join(self.data['scripts_dir'], 'shell-utils'),
                os.path.join(self.data['user_scripts_dir'], 'shell-utils'))
            for f in dc.left_only + dc.diff_files:
                try:
                    shutil.copy(
                        os.path.join(self.data['scripts_dir'], 'shell-utils',
                                     f),
                        os.path.join(self.data['user_scripts_dir'],
                                     'shell-utils', f))
                except Exception as err:
                    raise err

        except Exception as err:
            self.data = None
            import traceback
            traceback.print_exc()
            raise err

    def __getitem__(self, item):
        """
        Allow dict-style access on the object itself.
        :param item:
        :return:
        """
        return self.data[item]

    def __setitem__(self, key, value):
        """
        Allow dict-style setting of values into the backing structure
        :param key:
        :param value:
        :return:
        """
        self.data[key] = value

    def __str__(self):
        return yaml.safe_dump(self.data)

    def find_config_file(self):
        thefile = ""
        thedir = ""
        if os.path.exists(self.DEFAULT_CONFIG_FILE):
            thefile = self.DEFAULT_CONFIG_FILE
            thedir = self.DEFAULT_CONFIG_DIR
        elif os.path.exists("/etc/nextlinux/config.yaml"):
            thefile = "/etc/nextlinux/config.yaml"
            thedir = "/etc/nextlinux"
        else:
            # config file doesn't exist, copy the example default to ~
            if not os.path.exists(self.DEFAULT_CONFIG_DIR):
                os.makedirs(self.DEFAULT_CONFIG_DIR)
            for d in os.listdir(self.EXAMPLE_CONFIG_DIR):
                if not os.path.exists('/'.join([self.DEFAULT_CONFIG_DIR, d])):
                    shutil.copy('/'.join([self.EXAMPLE_CONFIG_DIR, d]),
                                '/'.join([self.DEFAULT_CONFIG_DIR, d]))
            thefile = self.DEFAULT_CONFIG_FILE
            thedir = self.DEFAULT_CONFIG_DIR

        # refresh if there are new config files in the installation that are not present in existing install
        if thedir and thefile:
            if not os.path.exists(thedir):
                os.makedirs(thedir)
            for d in os.listdir(self.EXAMPLE_CONFIG_DIR):
                if not os.path.exists(os.path.join(thedir, d)):
                    shutil.copy(os.path.join(self.EXAMPLE_CONFIG_DIR, d),
                                os.path.join(thedir, d))
        return thedir, thefile

    def backup(self, destdir='/tmp'):
        dateval = datetime.datetime.now().isoformat('-')
        backupfile = os.path.join(destdir,
                                  'nextlinux-backup-{0}.tar.gz'.format(dateval))

        data_dir = self.data['nextlinux_data_dir']
        image_dir = self.data['image_data_store']

        #module_logger.info('Backing up nextlinux to: %s' % backupfile)
        # Just tar up the whole thing
        with tarfile.TarFile.open(name=backupfile, mode='w:gz') as tf:
            tf.add(data_dir)
            if not data_dir in image_dir:
                # It's outside the regular data dir tree, so explicitly include
                tf.add(image_dir)
            if not data_dir in self.config_dir:
                tf.add(self.config_dir)

        return backupfile

    def restore(self, dest_root, backup_file):
        if not os.path.exists(dest_root):
            raise StandardError('Destination root dir does not exist')

        if isinstance(backup_file, str) and not os.path.exists(backup_file):
            raise StandardError('Backup file %s not found' % backup_file)

        if isinstance(backup_file, str):
            #module_logger.info('Restoring nextlinux from file %s to path: %s' % (backup_file, dest_root))
            with tarfile.TarFile.open(backup_file, mode='r:gz') as tf:
                tf.extractall(path=dest_root)

        else:
            #module_logger.info('Restoring nextlinux from file %s to path: %s' % (backup_file.name, dest_root))
            with tarfile.TarFile.open(fileobj=backup_file, mode='r:gz') as tf:
                tf.extractall(path=dest_root)

        return dest_root
