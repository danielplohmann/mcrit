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
MCRIT_SERVER = "http://127.0.0.1:8000/"
MCRITWEB_API_TOKEN = ""