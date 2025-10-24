import logging
import os

VERSION = 0.1
# relevant paths
CONFIG_FILE_PATH = str(os.path.abspath(__file__))
PROJECT_ROOT = str(os.path.abspath(os.sep.join([CONFIG_FILE_PATH, ".."])))
PLUGINS_ROOT = str(os.path.abspath(os.sep.join([PROJECT_ROOT, ".."])))
ICON_FILE_PATH = str(os.path.abspath(os.sep.join([PLUGINS_ROOT, "icons"])) + os.sep)

### Configuration of Logging
LOG_PATH = "./"
LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)-15s: %(name)-25s: %(message)s"
if len(logging._handlerList) == 0:
    logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)

MCRIT4IDA_PLUGIN_ONLY = False
MCRITWEB_USERNAME = ""
MCRIT_SERVER = "http://127.0.0.1:8000/"
MCRITWEB_API_TOKEN = ""

### UI behavior configurations
## General behavior
# Enable automatic conversion of IDB to SMDA on plugin startup
AUTO_ANALYZE_SMDA_ON_STARTUP = False
# Enable a question dialog on closing the plugin/IDA in case unsynced function name are detected
SUBMIT_FUNCTION_NAMES_ON_CLOSE = False
## Widget specific behavior
# Block Scope Widget
BLOCKS_FILTER_LIBRARY_FUNCTIONS = False
BLOCKS_LIVE_QUERY = False
BLOCKS_MIN_SIZE = 4
# Function Scope Widget
FUNCTION_FILTER_LIBRARY_FUNCTIONS = False
FUNCTION_LIVE_QUERY = False
FUNCTION_MIN_SCORE = 50
# Function Overview Widget
OVERVIEW_FETCH_LABELS_AUTOMATICALLY = False
OVERVIEW_FILTER_TO_LABELS = False
OVERVIEW_FILTER_TO_CONFLICTS = False
OVERVIEW_MIN_SCORE = 50