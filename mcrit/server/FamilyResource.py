import logging

import falcon

from mcrit.server.utils import timing, jsonify
from mcrit.index.MinHashIndex import MinHashIndex

LOGGER = logging.getLogger(__name__)

class FamilyResource:
    def __init__(self, index: MinHashIndex):
        self.index = index

    @timing
    def on_get(self, req, resp, family_id=None):
        LOGGER.info("FamilyResource.on_get")
        if self.index.getFamily(family_id) is None:
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "We don't have a family with that id."},
                }
            )
            resp.status = falcon.HTTP_404
            return

        result = {}
        samples = self.index.getSamplesByFamilyId(family_id)
        result[family_id] = {
            "family_id": family_id,
            "family": self.index.getFamily(family_id),
            "num_samples": len(samples),
            "num_versions": len(set([sample.version for sample in samples])),
            "samples": {},
        }
        for sample in samples:
            result[family_id]["samples"][sample.sample_id] = self.index.getSampleById(sample.sample_id).toDict()
        resp.data = jsonify({"status": "successful", "data": result})

    @timing
    def on_get_collection(self, req, resp):
        LOGGER.info("FamilyResource.on_get_collection")
        # parse optional request parameters
        start_index = 0 
        if "start" in req.params:
            try:
                start_index = max(0, int(req.params["start"]))
            except:
                pass
        limit_family_count = 0 
        if "limit" in req.params:
            try:
                limit_family_count = max(0, int(req.params["limit"]))
            except:
                pass
        family_overview = {}
        index = 0
        for family_id, family_entry in self.index.getFamilies().items():
            if index >= start_index:
                if (limit_family_count == 0) or (len(family_overview) < limit_family_count):
                    family_overview[family_id] = family_entry
                else:
                    break
            index += 1
        resp.data = jsonify({"status": "successful", "data": family_overview})
