import logging

import falcon

from mcrit.server.utils import timing, jsonify, getMatchingParams
from mcrit.index.MinHashIndex import MinHashIndex

LOGGER = logging.getLogger(__name__)

class QueryResource:
    def __init__(self, index: MinHashIndex):
        self.index = index
        self._query_option_best_only = False

    @timing
    def on_post_query_smda(self, req, resp):
        LOGGER.info("QueryResource.on_post_query_smda")
        parameters = getMatchingParams(req.params)
        if not req.content_length:
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "POST request without body can't be processed."},
                }
            )
            resp.status = falcon.HTTP_400
            return
        smda_report = req.media
        summary = self.index.getMatchesForSmdaReport(smda_report, **parameters)
        resp.data = jsonify({"status": "successful", "data": summary})

    @timing
    def on_post_query_binary(self, req, resp):
        parameters = getMatchingParams(req.params)
        LOGGER.info("QueryResource.on_post_query_binary")
        if not req.content_length:
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "POST request without body can't be processed."},
                }
            )
            resp.status = falcon.HTTP_400
            return
        binary = req.stream.read()
        summary = self.index.getMatchesForUnmappedBinary(binary, **parameters)
        resp.data = jsonify({"status": "successful", "data": summary})

    def on_post_query_binary_mapped(self, req, resp, base_address=None):
        parameters = getMatchingParams(req.params)
        LOGGER.info("QueryResource.on_post_query_binary_mapped")
        if not req.content_length:
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "POST request without body can't be processed."},
                }
            )
            resp.status = falcon.HTTP_400
            return
        # convert string to int. 0 means figure out base automatically.
        base_address = int(base_address, 0)
        binary = req.stream.read()
        summary = self.index.getMatchesForMappedBinary(binary, base_address, **parameters)
        resp.data = jsonify({"status": "successful", "data": summary})
