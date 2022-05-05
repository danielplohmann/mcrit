import logging

import falcon

from mcrit.server.utils import timing, jsonify, getMatchingParams
from mcrit.index.MinHashIndex import MinHashIndex


LOGGER = logging.getLogger(__name__)


class MatchResource:
    def __init__(self, index: MinHashIndex):
        self.index = index

    @timing
    def on_get_sample(self, req, resp, sample_id=None):
        LOGGER.info("SampleResource.on_get_matches")
        parameters = getMatchingParams(req.params)
        if not self.index.isSampleId(sample_id):
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "We don't have a sample with that id."},
                }
            )
            resp.status = falcon.HTTP_404
            return

        sample_matches = self.index.getMatchesForSample(sample_id, **parameters)
        resp.data = jsonify({"status": "successful", "data": sample_matches})
        # resp.status = falcon.HTTP_202
        # resp.location = "/matches/123"
        # resp.retry_after = 2

    def on_get_sample_vs(self, req, resp, sample_id=None, sample_id_2=None):
        # NOTE: We don't need to check if the kw parameters are None. The routing ensures that they are always set.
        LOGGER.info("SampleResource.on_get_matches_vs")
        parameters = getMatchingParams(req.params)
        if not self.index.isSampleId(sample_id) or not self.index.isSampleId(sample_id_2):
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "We don't have a sample with that id."},
                }
            )
            resp.status = falcon.HTTP_404
            return
        sample_matches = self.index.getMatchesForSampleVs(sample_id, sample_id_2, **parameters)
        resp.data = jsonify({"status": "successful", "data": sample_matches})

    @timing
    def on_get_function(self, req, resp, function_id=None):
        resp.status = falcon.HTTP_NOT_IMPLEMENTED
        return

    @timing
    def on_get_function_vs(self, req, resp, function_id=None, function_id_2=None):
        resp.status = falcon.HTTP_NOT_IMPLEMENTED
        return
