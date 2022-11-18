import logging

import falcon
import re
import json

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
    def on_get_by_sha256(self, req, resp, sample_sha256):
        LOGGER.info("SampleResource.on_get_by_sha256")
        sha256_pattern = "[a-fA-F0-9]{64}"
        match = re.match(sha256_pattern, sample_sha256)
        if not match:
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "No valid SHA256 provided."},
                }
            )
            resp.status = falcon.HTTP_400
            return
        sample_entry = self.index.getSampleBySha256(sample_sha256)
        if sample_entry is None:
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "We don't have a sample with that SHA256."},
                }
            )
            resp.status = falcon.HTTP_404
            return

        resp.data = jsonify({"status": "successful", "data": sample_entry.toDict()})

    @timing
    def on_delete(self, req, resp, sample_id=None):
        successful = self.index.deleteSample(sample_id, force_recalculation=True)
        if successful:
            resp.data = jsonify({"status": "successful", "data": successful})
            resp.status = falcon.HTTP_202
        else:
            resp.data = jsonify({"status": "failed", "data": {"message": "Failed to delete sample."}})
            # TODO whats the correct code?
            resp.status = falcon.HTTP_400

    @timing
    def on_put(self, req, resp, sample_id=None):
        resp.status = falcon.HTTP_400
        if not req.content_length or not isinstance(req.media, dict):
            resp.data = jsonify({"status": "failed","data": {"message": "PUT request without body can't be processed."}})
            return
        # sanitize sample information
        information_update = req.media
        if "family_name" in information_update and not re.match("^(?=[a-zA-Z0-9._\-]{0,64}$)(?!.*[\-_.]{2})[^\-_.].*[^\-_.]$", information_update["family_name"]):
            resp.data = jsonify({"status": "failed","data": {"message": "family_name may be 0-64 alphanumeric chars with single dots, dashes, underscores inbetween."}})
            return
        if "version" in information_update and not re.match("^[ -~]{1,64}$", information_update["version"]):
            resp.data = jsonify({"status": "failed","data": {"message": "version may be 0-64 printable characters."}})
            return
        if "component" in information_update and not re.match("^[ -~]{1,64}$", information_update["component"]):
            resp.data = jsonify({"status": "failed","data": {"message": "component may be 0-64 printable characters."}})
            return
        if "is_library" in information_update:
            if not (isinstance(information_update["is_library"], bool) or information_update["is_library"] in ["True", "False", "true", "false", "0", "1", 0, 1]):
                resp.data = jsonify({"status": "failed","data": {"message": "is_library must be boolean."}})
                return
            if information_update["is_library"] in ["True", "true", "1", 1]:
                information_update["is_library"] = True
            elif information_update["is_library"] in ["False", "false", "0", 0]:
                information_update["is_library"] = False
        successful = self.index.modifySample(sample_id, information_update, force_recalculation=True)
        if successful:
            resp.data = jsonify({"status": "successful", "data": {"message": "Sample modified."}})
            resp.status = falcon.HTTP_202
        else:
            resp.data = jsonify({"status": "failed", "data": {"message": "Failed to modify sample."}})

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
        if summary is not None:
            resp.data = jsonify({"status": "successful", "data": summary})
        else:
            resp.data = jsonify({"status": "failed", "data": {"message": "Could not process JSON."}})

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
            LOGGER.info("no body for post")
            return
        # TODO parse respective query fields -> escape / sanitize input
        filename = req.params["filename"] if "filename" in req.params else None
        family = req.params["family"] if "family" in req.params else None
        version = req.params["version"] if "version" in req.params else None
        is_dump = True if ("is_dump" in req.params and req.params["is_dump"] in ["True", "true", "1", 1]) else False
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