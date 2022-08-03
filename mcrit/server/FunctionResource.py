import logging
from re import M

import falcon

from mcrit.server.utils import timing, jsonify
from mcrit.index.MinHashIndex import MinHashIndex

LOGGER = logging.getLogger(__name__)


class FunctionResource:
    def __init__(self, index: MinHashIndex):
        self.index = index

    @timing
    def on_get(self, req, resp, function_id=None):
        LOGGER.info("FunctionResource.on_get_function")
        query_with_xcfg = False 
        if "with_xcfg" in req.params:
            query_with_xcfg = req.params["with_xcfg"].lower().strip() == "true"
        if not self.index.isFunctionId(function_id):
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "We don't have a function with that id."},
                }
            )
            resp.status = falcon.HTTP_404
            return
        data = self.index.getFunctionById(function_id, with_xcfg=query_with_xcfg).toDict()
        resp.data = jsonify(
            {
                "status": "successful",
                "data": data,
            }
        )

    @timing
    def on_get_collection(self, req, resp):
        LOGGER.info("FunctionResource.on_get_collection")
        # parse optional request parameters
        start_index = 0 
        if "start" in req.params:
            try:
                start_index = int(req.params["start"])
            except:
                pass
        limit_function_count = 0 
        if "limit" in req.params:
            try:
                limit_function_count = int(req.params["limit"])
            except:
                pass
        function_overview = {}
        function_entries = self.index.getFunctions(start_index, limit_function_count)
        for function_entry in function_entries:
            function_overview[function_entry.function_id] = function_entry.toDict()
        resp.data = jsonify({"status": "successful", "data": function_overview})
