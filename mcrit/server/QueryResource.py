import re
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

    @timing
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

    @timing
    def on_get_query_pichash(self, req, resp, pichash):
        LOGGER.info("QueryResource.on_get_query_pichash")
        pichash_pattern = "[a-fA-F0-9]{16}"
        match = re.match(pichash_pattern, pichash)
        if not match:
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "No valid PicHash provided."},
                }
            )
            resp.status = falcon.HTTP_400
            return
        pichash_int = int(pichash, 16)
        pichash_matches = self.index.getMatchesForPicHash(pichash_int)
        resp.data = jsonify({"status": "successful", "data": pichash_matches})

    @timing
    def on_get_query_pichash_summary(self, req, resp, pichash):
        LOGGER.info("QueryResource.on_get_query_pichash_summary")
        pichash_pattern = "[a-fA-F0-9]{16}"
        match = re.match(pichash_pattern, pichash)
        if not match:
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "No valid PicHash provided."},
                }
            )
            resp.status = falcon.HTTP_400
            return
        pichash_int = int(pichash, 16)
        pichash_matches = self.index.getMatchesForPicHash(pichash_int)
        summary = {
            "families": len(set([e[0] for e in pichash_matches])),
            "samples": len(set([e[1] for e in pichash_matches])),
            "functions": len(set([e[2] for e in pichash_matches])),
        }
        resp.data = jsonify({"status": "successful", "data": summary})

    @timing
    def on_get_query_picblockhash(self, req, resp, picblockhash):
        LOGGER.info("QueryResource.on_get_query_picblockhash")
        pichash_pattern = "[a-fA-F0-9]{16}"
        match = re.match(pichash_pattern, picblockhash)
        if not match:
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "No valid PicHash provided."},
                }
            )
            resp.status = falcon.HTTP_400
            return
        pichash_int = int(picblockhash, 16)
        pichash_matches = self.index.getMatchesForPicBlockHash(pichash_int)
        resp.data = jsonify({"status": "successful", "data": pichash_matches})

    @timing
    def on_get_query_picblockhash_summary(self, req, resp, picblockhash):
        LOGGER.info("QueryResource.on_get_query_picblockhash_summary")
        pichash_pattern = "[a-fA-F0-9]{16}"
        match = re.match(pichash_pattern, picblockhash)
        if not match:
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "No valid PicHash provided."},
                }
            )
            resp.status = falcon.HTTP_400
            return
        pichash_int = int(picblockhash, 16)
        pichash_matches = self.index.getMatchesForPicBlockHash(pichash_int)
        summary = {
            "families": len(set([e[0] for e in pichash_matches])),
            "samples": len(set([e[1] for e in pichash_matches])),
            "functions": len(set([e[2] for e in pichash_matches])),
            "offsets" : len(pichash_matches)
        }
        resp.data = jsonify({"status": "successful", "data": summary})
