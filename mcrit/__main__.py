import os
import sys
import platform

def runWorker(profiling=False):
    from mcrit.Worker import Worker
    worker = Worker(profiling=profiling)
    worker.run()


def runServer(profiling=False):
    from waitress import serve
    from mcrit.server.wsgi import app
    from mcrit.config.GunicornConfig import GunicornConfig
    from gunicorn.app.base import BaseApplication

    class gunicornServer(BaseApplication):
        def __init__(self, app):
            self.app = app
            super().__init__()
        
        def load_config(self):
            for key, value in GunicornConfig().toDict():
                self.cfg.set(key.lower(), value)

        def load(self):
            return self.app

    wrapped_app = app
    if profiling:
        print("[!] Running as profiled application.")
        from werkzeug.middleware.profiler import ProfilerMiddleware
        profile_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "profiler")
        os.makedirs(profile_dir, exist_ok=True)
        wrapped_app = ProfilerMiddleware(
            wrapped_app,
            restrictions=[30],
            profile_dir=profile_dir,
            filename_format="{method}-{path}-{time:.0f}-{elapsed:.0f}ms.prof",
        )
    
    platform = platform.system().lower()
    if platform == "linux":
        print("[!] Detected linux platform. Using gunicorn deployment.")
        gunicornServer(wrapped_app).run()
        sys.exit()
    elif platform == "windows":
        print("[!] Detected windows platform. Using waitress deployment.")
    else:
        print("[!] Could not determine platform. Defaulting to waitress deployment.")
    # TODO consider allowing an argument to pass an configuration for initial setup of the instance
    serve(wrapped_app, listen="*:8000")


def runClient():
    from mcrit.client.McritConsole import McritConsole
    # we will re-parse arguments with more detail in McritConsole to keep this file concise
    console_client = McritConsole()
    console_client.run()


# do not use argparse for processing here to allow using argparse help for the more intricate things in McritConsole
if len(sys.argv) >= 2:
    is_profiling = False
    if len(sys.argv) >= 3 and sys.argv[2] == "--profile":
        is_profiling = True
    if sys.argv[1] == "server":
        runServer(profiling=is_profiling)
    elif sys.argv[1] == "worker":
        runWorker(profiling=is_profiling)
    elif sys.argv[1] == "client":
        runClient()
    else:
        print("Unrecognized command, please use {{server, worker, client}}")
else:
    print(f"Usage: {sys.argv[0]} {{server, worker, client}}")
    print("Optionally use --profiling for {server, worker}")
    sys.exit()
