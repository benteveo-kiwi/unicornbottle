import configparser
import functools
import logging
import os

CONFIG_FILE = '~/.cli.conf'
logger = logging.getLogger(__name__)

class MissingConfigurationFile(Exception):
    pass

@functools.cache
def read_configuration_file() -> configparser.ConfigParser:
    """
    Reads the applicable configuration file. If the file doesn't exist, it
    fails with a MissingConfigurationFile exception.

    Reads are cached so any changes to the configuration require an application restart.
    """
    config = configparser.ConfigParser()
    config_file = os.path.expanduser(CONFIG_FILE)
    try:
        with open(config_file, 'r') as f:
            config.read_file(f)
    except IOError:
        err_msg = "Could not read file %s" % config_file
        logger.error(err_msg)
        raise MissingConfigurationFile(err_msg)

    return config
