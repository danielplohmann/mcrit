from dataclasses import dataclass

from mcrit.config.ConfigInterface import ConfigInterface

@dataclass
class GunicornConfig(ConfigInterface):
    # specified as "<host>:<port>" to be able to pass it easily into gunicorn config
    BIND = "0.0.0.0:8000"
    # The number of workers gunicorn will spin up
    WORKERS = 4
    # The number of threads in each worker
    THREADS = 8
    # timeout before silent workers are killed
    TIMEOUT = 120