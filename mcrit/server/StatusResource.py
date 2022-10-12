import re
import json
import logging
import zipfile

import falcon

from mcrit.server.utils import timing, jsonify
from mcrit.index.MinHashIndex import MinHashIndex

LOGGER = logging.getLogger(__name__)

class StatusResource:
    def __init__(self, index: MinHashIndex):
        self.index = index

    @timing
    def on_get(self, req, resp):
        LOGGER.info("StatusResource.on_get")
        resp.data = jsonify({"status": "successful", "data": {"message": "Welcome to MCRIT"}})

    @timing
    def on_get_status(self, req, resp):
        LOGGER.info("StatusResource.on_get_status")
        resp.data = jsonify({"status": "successful", "data": self.index.getStatus()})

    @timing
    def on_get_version(self, req, resp):
        LOGGER.info("StatusResource.on_get_version")
        resp.data = jsonify({"status": "successful", "data": self.index.getVersion()})

    @timing
    def on_get_config(self, req, resp):
        LOGGER.info("StatusResource.on_get_config")
        resp.status = falcon.HTTP_NOT_IMPLEMENTED
        return
        resp.data = jsonify({"status": "error", "data": {"message": "We don't have that yet."}})

    @timing
    def on_get_export(self, req, resp):
        LOGGER.info("StatusResource.on_get_export")
        compress_data = True if "compress" in req.params and req.params["compress"].lower() == "true" else False
        exported_data = self.index.getExportData(compress_data=compress_data)
        resp.data = jsonify({"status": "successful", "data": exported_data})

    @timing
    def on_get_export_selection(self, req, resp, comma_separated_sample_ids=None):
        LOGGER.info("StatusResource.on_get_export_selection")
        # NOTE if we encounter extreme cases (super long URLs), we might have to switch to post here.
        compress_data = True if "compress" in req.params and req.params["compress"].lower() == "true" else False
        exported_data = {}
        if re.match("^\d+(?:[\s]*,[\s]*\d+)*$", comma_separated_sample_ids):
            target_sample_ids = [int(sample_id) for sample_id in comma_separated_sample_ids.split(",")]
            exported_data = self.index.getExportData(target_sample_ids, compress_data=compress_data)
        resp.data = jsonify({"status": "successful", "data": exported_data})

    @timing
    def on_post_import(self, req, resp):
        LOGGER.info("StatusResource.on_post_import")
        if not req.content_length:
            resp.data = jsonify(
                {
                    "status": "failed",
                    "data": {"message": "POST request without body can't be processed."},
                }
            )
            resp.status = falcon.HTTP_400
            return
        import_data = json.loads(req.stream.read())
        import_report = self.index.addImportData(import_data)
        resp.data = jsonify({"status": "successful", "data": import_report})
        return

    @timing
    def on_post_respawn(self, req, resp):
        LOGGER.info("StatusResource.on_post_respawn")
        self.index.respawn()
        resp.data = jsonify({"status": "successful", "data": {"message": "Successfully performed reset of MCRIT instance."}})

    @timing
    def on_get_complete_minhashes(self, req, resp):
        LOGGER.info("StatusResource.on_get_complete_minhashes")
        minhash_report = self.index.updateMinHashes(None)
        resp.data = jsonify({"status": "successful", "data": minhash_report})
        return

    @staticmethod
    def _get_search_args(params):
        result = {
            "search_term": params["query"],
            "cursor": params.get("cursor", None),
            "sort_by": params.get("sort_by", None),
            "is_ascending": params.get("is_ascending", "true").lower() != "false",
        }
        try: 
            result["limit"] = int(params.get("limit"))
        except:
            pass
        return result

    @timing
    def on_get_search_families(self, req, resp):
        LOGGER.info("StatusResource.on_get_search_families")
        args = self._get_search_args(req.params)
        resp.data = jsonify({"status": "successful", "data": self.index.getFamilySearchResults(**args)})

    @timing
    def on_get_search_samples(self, req, resp):
        LOGGER.info("StatusResource.on_get_search_samples")
        args = self._get_search_args(req.params)
        resp.data = jsonify({"status": "successful", "data": self.index.getSampleSearchResults(**args)})

    @timing
    def on_get_search_functions(self, req, resp):
        LOGGER.info("StatusResource.on_get_search_functions")
        args = self._get_search_args(req.params)
        resp.data = jsonify({"status": "successful", "data": self.index.getFunctionSearchResults(**args)})
