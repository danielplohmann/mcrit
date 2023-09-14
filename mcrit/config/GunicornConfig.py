from dataclasses import asdict, dataclass, field

from mcrit.config.ConfigInterface import ConfigInterface

@dataclass
class GunicornConfig(ConfigInterface):
    # introduce a switch for gunicorn
    USE_GUNICORN: bool = False
    # specified as "<host>:<port>" to be able to pass it easily into gunicorn config
    BIND: str = "0.0.0.0:8000"
    # The number of workers gunicorn will spin up
    WORKERS: int = 4
    # The number of threads in each worker
    THREADS: int = 8
    # timeout before silent workers are killed
    TIMEOUT: int = 120