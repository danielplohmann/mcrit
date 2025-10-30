import logging
import os
import helpers.McritTableColumn as McritTableColumn

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
#
BLOCK_SUMMARY_TABLE_COLUMNS = [
    McritTableColumn.OFFSET,
    McritTableColumn.PIC_BLOCK_HASH,
    McritTableColumn.SIZE,
    McritTableColumn.FAMILIES,
    McritTableColumn.SAMPLES,
    McritTableColumn.FUNCTIONS,
    McritTableColumn.IS_LIBRARY,
]
BLOCK_MATCHES_TABLE_COLUMNS = [
    McritTableColumn.FAMILY_NAME,
    McritTableColumn.FAMILY_ID,
    McritTableColumn.SAMPLE_ID,
    McritTableColumn.FUNCTION_ID,
    McritTableColumn.OFFSET,
    # McritTableColumn.SHA256,
]
# Function Scope Widget
FUNCTION_FILTER_LIBRARY_FUNCTIONS = False
FUNCTION_LIVE_QUERY = False
FUNCTION_MIN_SCORE = 50
#
FUNCTION_MATCHES_TABLE_COLUMNS = [
    McritTableColumn.SCORE,
    McritTableColumn.SHA256,
    # TODO we want to have the matched function's offset here, needs to be implemented in core MCRIT first
    # MCritTableColumn.OFFSET,
    McritTableColumn.FAMILY_NAME,
    McritTableColumn.VERSION,
    McritTableColumn.SAMPLE_ID,
    McritTableColumn.FUNCTION_ID,
    McritTableColumn.PIC_HASH_MATCH,
    McritTableColumn.IS_LIBRARY,
]
FUNCTION_NAMES_TABLE_COLUMNS = [
    McritTableColumn.FUNCTION_ID,
    McritTableColumn.SCORE,
    McritTableColumn.USER,
    McritTableColumn.FUNCTION_LABEL,
    # McritTableColumn.TIMESTAMP,
]
# Function Overview Widget
OVERVIEW_FETCH_LABELS_AUTOMATICALLY = False
OVERVIEW_FILTER_TO_LABELS = False
OVERVIEW_FILTER_TO_CONFLICTS = False
OVERVIEW_MIN_SCORE = 50
#
OVERVIEW_TABLE_COLUMNS = [
    McritTableColumn.OFFSET,
    McritTableColumn.FAMILIES,
    McritTableColumn.SAMPLES,
    McritTableColumn.FUNCTIONS,
    McritTableColumn.IS_LIBRARY,
    McritTableColumn.SCORE_AND_LABEL,
]