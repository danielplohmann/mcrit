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
        # parse optional request parameters
        with_samples = True 
        if "with_samples" in req.params:
            with_samples = req.params["with_samples"].lower().strip() == "true"
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

        family = self.index.getFamily(family_id)
        if with_samples:
            samples = self.index.getSamplesByFamilyId(family_id)
            family.samples = {}
            for sample in samples:
                family.samples[sample.sample_id] = self.index.getSampleById(sample.sample_id)
        result = family.toDict()
        resp.data = jsonify({"status": "successful", "data": result})

    @timing
    def on_delete(self, req, resp, family_id=None):
        if family_id is None or self.index.getFamily(family_id) is None:
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "We don't have a family with that id."},
                }
            )
            resp.status = falcon.HTTP_404
            return
        # parse optional request parameters
        keep_samples = False 
        if "keep_samples" in req.params:
            keep_samples = req.params["keep_samples"].lower().strip() == "true"
        LOGGER.info("FamilyResource.on_delete")
        successful = self.index.deleteFamily(family_id, keep_samples=keep_samples)
        if successful:
            resp.data = jsonify({"status": "successful", "data": {"message": "Family deleted."}})
            resp.status = falcon.HTTP_202
        else:
            resp.data = jsonify({"status": "failed", "data": {"message": "Failed to delete family."}})
            # TODO whats the correct code?
            resp.status = falcon.HTTP_410

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
                    family_overview[family_id] = family_entry.toDict()
                else:
                    break
            index += 1
        resp.data = jsonify({"status": "successful", "data": family_overview})
