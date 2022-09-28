import os
import json
import argparse

from waitress import serve

from mcrit.server.wsgi import app
from mcrit.client.McritClient import McritClient
from mcrit.Worker import Worker


def runWorker(profiling=False):
    worker = Worker(profiling=profiling)
    worker.run()


def runServer(profiling=False):
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
    # TODO consider allowing an argument to pass an configuration for initial setup of the instance
    serve(wrapped_app, listen="*:8000")


def runClient(arguments):
    client = McritClient()
    result = None
    if ARGS.client_command == "status":
        result = client.getStatus()
        print(result)
    elif ARGS.client_command == "import":
        if os.path.isfile(ARGS.filepath):
            with open(ARGS.filepath) as fin:
                result = client.addImportData(json.load(fin))
                print(result)
    elif ARGS.client_command == "export":
        sample_ids = None
        if ARGS.sample_ids is not None:
            sample_ids = [int(i) for i in ARGS.sample_ids.split(",")]
        result = client.getExportData(sample_ids=sample_ids)
        with open(ARGS.filepath, "w") as fout:
            json.dump(result, fout, indent=1)
        print(f"wrote export to {ARGS.filepath}.")
    elif ARGS.client_command == "search":
        result = client.search(ARGS.search_term)
        print(result)
    elif ARGS.client_command == "queue":
        result = client.getQueueData(filter=ARGS.filter)
        for entry in result:
            job_id = entry.job_id
            result_id = entry.result
            created = entry.created_at if entry.created_at is not None else "-"
            started = entry.started_at if entry.started_at is not None else "-"
            finished = entry.finished_at if entry.finished_at is not None else "-"
            method = entry.parameters
            progress = entry.progress
            print(f"{job_id} {result_id} | {created} {started} {finished} | {method} - {progress}")


parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="command")

parser_server = subparsers.add_parser("server")
parser_server.add_argument("--profile", help="Profile server. Requires werkzeug package.", action="store_true")
parser_worker = subparsers.add_parser("worker")
parser_worker.add_argument("--profile", help="Profile worker. Requires cProfile.", action="store_true")
# create a set of subparsers for all client commands
parser_client = subparsers.add_parser("client")
subparser_client = parser_client.add_subparsers(dest="client_command")
client_status = subparser_client.add_parser("status")
client_import = subparser_client.add_parser("import")
client_import.add_argument("filepath", type=str, help="Import a given <filepath> containing MCRIT data into the storage.")
client_export = subparser_client.add_parser("export")
client_export.add_argument("filepath", type=str, help="Export the full storage into <filepath>.")
client_export.add_argument("--sample_ids", type=str, help="Limit export to a list of comma-separated <sample_ids>.")
client_search = subparser_client.add_parser("search")
client_search.add_argument("search_term", type=str, help="Conduct a search with a given <search_term>.")
client_queue = subparser_client.add_parser("queue")
client_queue.add_argument("--filter", type=str, help="Filter queue entries with this term.")

ARGS = parser.parse_args()

if ARGS.command == "server":
    runServer(profiling = ARGS.profile)
elif ARGS.command == "worker":
    runWorker(profiling = ARGS.profile)
elif ARGS.command == "client":
    runClient(ARGS)
else:
    parser.print_usage()
