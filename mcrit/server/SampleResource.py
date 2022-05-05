import logging

import falcon

from mcrit.server.utils import timing, jsonify
from mcrit.index.MinHashIndex import MinHashIndex

LOGGER = logging.getLogger(__name__)


class SampleResource:
    def __init__(self, index: MinHashIndex):
        self.index = index

    @timing
    def on_get(self, req, resp, sample_id=None):
        LOGGER.info("SampleResource.on_get")
        if not self.index.isSampleId(sample_id):
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "We don't have a sample with that id."},
                }
            )
            resp.status = falcon.HTTP_404
            return
        resp.data = jsonify({"status": "successful", "data": self.index.getSampleById(sample_id).toDict()})

    @timing
    def on_delete(self, req, resp, sample_id=None):
        successful = self.index.deleteSample(sample_id)
        if successful:
            resp.data = jsonify({"status": "successful"})
            resp.status = falcon.HTTP_202
        else:
            resp.data = jsonify({"status": "failed"})
            # TODO whats the correct code?
            resp.status = falcon.HTTP_410

    @timing
    def on_post_collection(self, req, resp):
        LOGGER.info("SampleResource.on_post_collection")
        # TODO 2019-05-07 verify integrity of SMDA report
        if not req.content_length:
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "POST request without body can't be processed."},
                }
            )
            resp.status = falcon.HTTP_400
            return
        summary = self.index.addReportJson(req.media)
        # TODO 2019-05-10 return full sample_entry in response
        resp.data = jsonify({"status": "successful", "data": summary})

    @timing
    def on_post_submit_binary(self, req, resp):
        LOGGER.info("SampleResource.on_post_submit_binary")
        if not req.content_length:
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "POST request without body can't be processed."},
                }
            )
            resp.status = falcon.HTTP_400
            return
        # TODO parse respective query fields -> escape / sanitize input
        filename = req.params["filename"] if "filename" in req.params else None
        family = req.params["family"] if "family" in req.params else None
        version = req.params["version"] if "version" in req.params else None
        is_dump = True if ("version" in req.params and req.params["is_dump"] in ["True", "true", "1", 1]) else False
        base_address = 0 
        if "base_addr" in req.params:
            try:
                base_address = int(req.params["base_addr"], 16)
            except:
                pass
        bitness = int(req.params["bitness"]) if ("bitness" in req.params and req.params["bitness"] in ["32", "64"]) else 32
        # binary itself
        binary = req.stream.read()
        job_id = self.index.addBinarySample(binary, filename, family, version, is_dump, base_address, bitness)
        LOGGER.info("job_id %s", job_id)
        # TODO 2019-05-10 return full sample_entry in response
        resp.data = jsonify({"status": "successful", "data": job_id})

    @timing
    def on_get_collection(self, req, resp):
        LOGGER.info("SampleResource.on_get_collection")
        # parse optional request parameters
        start_index = 0 
        if "start" in req.params:
            try:
                start_index = int(req.params["start"])
            except:
                pass
        limit_sample_count = 0 
        if "limit" in req.params:
            try:
                limit_sample_count = int(req.params["limit"])
            except:
                pass
        sample_overview = {}
        sample_entries = self.index.getSamples(start_index, limit_sample_count)
        for sample_entry in sample_entries:
            sample_overview[sample_entry.sample_id] = sample_entry.toDict()
        resp.data = jsonify({"status": "successful", "data": sample_overview})

    @timing
    def on_get_function(self, req, resp, sample_id=None, function_id=None):
        LOGGER.info("SampleResource.on_get_function")
        if not self.index.isSampleId(sample_id):
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "We don't have a sample with that id."},
                }
            )
            resp.status = falcon.HTTP_404
            return
        if not self.index.isFunctionId(function_id):
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "We don't have a function with that id."},
                }
            )
            resp.status = falcon.HTTP_404
            return
        data = self.index.getFunctionById(function_id).toDict()
        # check if function_id belongs to sample_id
        if data["sample_id"] != sample_id:
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "This sample doesn't have a function with that id."},
                }
            )
            resp.status = falcon.HTTP_404
            return
        resp.data = jsonify(
            {
                "status": "successful",
                "data": data
            }
        )

    @timing
    def on_get_functions(self, req, resp, sample_id=None):
        LOGGER.info("SampleResource.on_get_functions")
        if not self.index.isSampleId(sample_id):
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "We don't have a sample with that id."},
                }
            )
            resp.status = falcon.HTTP_404
            return
        function_entries = self.index.getFunctionsBySampleId(sample_id)

        data = {
            function_entry.function_id: function_entry.toDict() 
            for function_entry 
            in sorted(function_entries, key=lambda func: func.offset)
        }
        resp.data = jsonify(
            {
                "status": "successful",
                "data": data
            }
        )