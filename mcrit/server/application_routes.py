import json
import logging
import os

import falcon

from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.server.FamilyResource import FamilyResource
from .FunctionResource import FunctionResource
from .JobResource import JobResource
from .MatchResource import MatchResource
from .QueryResource import QueryResource
from .SampleResource import SampleResource
from .StatusResource import StatusResource

# Only do basicConfig if no handlers have been configured
if len(logging._handlerList) == 0:
    logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOGGER = logging.getLogger(__name__)



def create_index():
    # TODO we will want to load config values and everyting from the database instead of initializing everytime here
    index = MinHashIndex()
    this_path = str(os.path.abspath(__file__))
    root_path = os.sep.join(this_path.split(os.sep)[:-2])
    index_path = os.sep.join([root_path, "db", "index.json"])
    index_json = None
    if os.path.isfile(index_path):
        LOGGER.info("Found index.json, loading and using data...")
        with open(index_path, "r") as fjson:
            index_json = json.load(fjson)
        index.setStorageData(index_json)
    return index


def get_app():
    index = create_index()
    status_resource = StatusResource(index)
    family_resource = FamilyResource(index)
    sample_resource = SampleResource(index)
    function_resource = FunctionResource(index)
    match_resource = MatchResource(index)
    query_resource = QueryResource(index)
    job_resource = JobResource(index)

    _app = falcon.App()
    _app.req_options.strip_url_path_trailing_slash = True
    _app.add_route("/", status_resource)
    _app.add_route("/status", status_resource, suffix="status")
    _app.add_route("/config", status_resource, suffix="config")
    _app.add_route("/export", status_resource, suffix="export")
    _app.add_route("/export/{comma_separated_sample_ids}", status_resource, suffix="export_selection")
    # NOTE: adds to storage, does not replace storage
    _app.add_route("/import", status_resource, suffix="import")  # post
    # drops storage and sets up new empty instance
    _app.add_route("/respawn", status_resource, suffix="respawn")  # post

    # search suitable fields based on query
    _app.add_route("/search/families", status_resource, suffix="search_families")
    _app.add_route("/search/samples", status_resource, suffix="search_samples")
    _app.add_route("/search/functions", status_resource, suffix="search_functions")
    _app.add_route("/search/pichashes", status_resource, suffix="search_pichashes")

    _app.add_route("/families", family_resource, suffix="collection")
    _app.add_route("/families/{family_id:int}", family_resource)

    # supports GET and POST(to insert one sample)
    _app.add_route("/samples", sample_resource, suffix="collection")
    # post only
    _app.add_route("/samples/binary", sample_resource, suffix="submit_binary")
    # supports GET and DELETE(for one sample)
    _app.add_route("/samples/{sample_id:int}", sample_resource)
    _app.add_route("/samples/{sample_id:int}/functions", sample_resource, suffix="functions")
    _app.add_route(
        "/samples/{sample_id:int}/functions/{function_id:int}",
        sample_resource,
        suffix="function",
    )

    _app.add_route("/functions", function_resource, suffix="collection")
    _app.add_route("/functions/{function_id:int}", function_resource)

    _app.add_route("/matches/sample/{sample_id:int}", match_resource, suffix="sample")
    _app.add_route("/matches/sample/{sample_id:int}/{sample_id_2:int}", match_resource, suffix="sample_vs")
    _app.add_route("/matches/function/{function_id:int}/{function_id_2:int}", match_resource, suffix="function_vs")
    _app.add_route("/matches/function/{function_id:int}", match_resource, suffix="function")

    _app.add_route("/query", query_resource, suffix="query_smda")
    _app.add_route("/query/binary", query_resource, suffix="query_binary")
    _app.add_route(
        "/query/binary/mapped/{base_address}",
        query_resource,
        suffix="query_binary_mapped",
    )

    _app.add_route("/jobs", job_resource, suffix="collection")
    _app.add_route("/jobs/{job_id}", job_resource)
    _app.add_route("/jobs/{job_id}/result", job_resource, suffix="job_result")
    _app.add_route("/results/{result_id}", job_resource, suffix="results")

    return _app
