import logging
import os

from .MinHashConfig import MinHashConfig
from .QueueConfig import QueueConfig
from .ShinglerConfig import ShinglerConfig
from .StorageConfig import StorageConfig


class McritConfig(object):

    # NOTE to self: always change this in setup.py as well!
    VERSION = "1.4.1"
    # basic pathing info
    CONFIG_FILE_PATH = str(os.path.abspath(__file__))
    PROJECT_ROOT = str(os.path.abspath(os.sep.join([CONFIG_FILE_PATH, "..", ".."])))

    # Authentication token, which can be optionally used to lock down communication with the API
    AUTH_TOKEN = ""

    ### global logging-config setup
    # Only do basicConfig if no handlers have been configured
    LOG_PATH = "./"
    LOG_LEVEL = logging.INFO
    LOG_FORMAT = "%(asctime)-15s: %(name)-32s - %(message)s"

    # initialize context-based configurations
    MINHASH_CONFIG = MinHashConfig()
    SHINGLER_CONFIG = ShinglerConfig()
    STORAGE_CONFIG = StorageConfig()
    QUEUE_CONFIG = QueueConfig()

    def __init__(self, log_level=logging.INFO):
        if len(logging._handlerList) == 0:
            logging.basicConfig(level=log_level, format=self.LOG_FORMAT)
