import logging
import unittest

import nextlinux.cli.logs
import nextlinux.cli.common
import nextlinux.util


class TestLogging(unittest.TestCase):

    @staticmethod
    def do_generic(some_logger, name=None):
        assert isinstance(some_logger, logging.Logger)
        some_logger.debug('debug message - ' + name)
        some_logger.info('info message - ' + name)
        some_logger.warn('warn message - ' + name)
        some_logger.error('error message - ' + name)

        try:
            raise KeyError('Some key not found')
        except KeyError:
            some_logger.exception('Some exception caught - ' + name)

    @staticmethod
    def do_nextlinux_logging():
        print '--NEXTLINUX LOGGER'
        nextlinux_logger = logging.getLogger('nextlinux')
        TestLogging.do_generic(nextlinux_logger, 'nextlinux')

    @staticmethod
    def do_non_nextlinux_logging():
        print '--NON-NEXTLINUX LOGGER'
        rand_logger = logging.getLogger('somepackage.somemodule')
        TestLogging.do_generic(rand_logger, 'non-nextlinux')

    @staticmethod
    def reset_logging_config():
        logging.root.setLevel('NOTSET')
        for f in logging.root.filters:
            logging.root.filters.remove(f)

        for f in logging.root.handlers:
            print 'Removing handler %s' % str(f)
            logging.root.handlers.remove(f)

    def test_quiet(self):
        print '--STARTING TEST: quiet'
        TestLogging.reset_logging_config()
        nextlinux.cli.logs.init_output_formatters(output_verbosity='quiet')
        TestLogging.do_nextlinux_logging()
        TestLogging.do_non_nextlinux_logging()

    def test_normal(self):
        print '--STARTING TEST: normal'
        TestLogging.reset_logging_config()
        nextlinux.cli.logs.init_output_formatters(output_verbosity='normal')
        TestLogging.do_nextlinux_logging()
        TestLogging.do_non_nextlinux_logging()

    def test_verbose(self):
        print '--STARTING TEST: verbose'
        TestLogging.reset_logging_config()
        nextlinux.cli.logs.init_output_formatters(output_verbosity='verbose')
        TestLogging.do_nextlinux_logging()
        TestLogging.do_non_nextlinux_logging()

    def test_debug(self):
        print '--STARTING TEST: debug'
        TestLogging.reset_logging_config()
        nextlinux.cli.logs.init_output_formatters(output_verbosity='debug')
        TestLogging.do_nextlinux_logging()
        TestLogging.do_non_nextlinux_logging()
