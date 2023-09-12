from mcrit.config.ConfigInterface import ConfigInterface

class GunicornConfig(ConfigInterface):
    BIND = "0.0.0.0:8000"
    # The number of workers gunicorn will spin up
    WORKERS = 4
    # The number of threads in each worker
    THREADS = 8