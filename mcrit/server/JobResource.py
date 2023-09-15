import re
import logging

import falcon

from mcrit.server.utils import timing, jsonify
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.server.utils import db_log_msg

# TODO these should also return status and data in their json response

class JobResource:
    def __init__(self, index: MinHashIndex):
        self.index = index

    @timing
    def on_get_collection(self, req, resp):
        # parse optional request parameters
        query_filter = None
        if "filter" in req.params:
            query_filter = req.params["filter"]
        start_job_id = 0 
        if "start" in req.params:
            try:
                start_job_id = int(req.params["start"])
            except:
                pass
        limit_job_count = 0 
        if "limit" in req.params:
            try:
                limit_job_count = int(req.params["limit"])
            except:
                pass
        # newest first
        queue_data = reversed(self.index.getQueueData(filter=query_filter))
        result_data = []
        num_jobs_included = 0
        for index, job_data in enumerate(queue_data):
            if index < start_job_id:
                continue
            if (limit_job_count == 0) or (num_jobs_included < limit_job_count):
                result_data.append(job_data)
                num_jobs_included += 1
            else:
                break
            if limit_job_count and num_jobs_included >= limit_job_count:
                break
        resp.data = jsonify({"status": "successful", "data": result_data})
        db_log_msg(self.index, req, f"JobResource.on_get_collection - success.")

    @timing
    def on_get(self, req, resp, job_id=None):
        # validate that we only allow hexstrings with 24 chars
        if not re.match("[a-fA-F0-9]{24}", job_id):
            resp.status = falcon.HTTP_400
            resp.data = jsonify({"status": "failed", "data": {"message": "Valid JobIDs are hexstrings with 24 characters."}})
            db_log_msg(self.index, req, f"JobResource.on_get - failed - invalid job_id.")
            return  
        data = self.index.getJobData(job_id)
        # TODO throw 404 if job_id is unknown
        # resp.status = falcon.HTTP_404
        resp.data = jsonify({"status": "successful", "data": data})
        db_log_msg(self.index, req, f"JobResource.on_get - success.")

    @timing
    def on_get_results(self, req, resp, result_id=None):
        # validate that we only allow hexstrings with 24 chars
        if not re.match("[a-fA-F0-9]{24}", result_id):
            resp.status = falcon.HTTP_400
            resp.data = jsonify({"status": "failed", "data": {"message": "Valid ResultIDs are hexstrings with 24 characters."}})
            db_log_msg(self.index, req, f"JobResource.on_get_results - failed - invalid result_id.")
            return  
        data = self.index.getResult(result_id)
        # TODO throw 404 if job_id is unknown
        # resp.status = falcon.HTTP_404
        resp.data = jsonify({"status": "successful", "data": data})
        db_log_msg(self.index, req, f"JobResource.on_get_results - success.")

    @timing
    def on_get_job_result(self, req, resp, job_id=None):
        # validate that we only allow hexstrings with 24 chars
        if not re.match("[a-fA-F0-9]{24}", job_id):
            resp.status = falcon.HTTP_400
            resp.data = jsonify()
            db_log_msg(self.index, req, f"JobResource.on_get_job_result - failed - invalid job_id.")
            return  
        data = self.index.getResultForJob(job_id)
        # TODO throw 404 if job_id is unknown
        # resp.status = falcon.HTTP_404
        resp.data = jsonify({"status": "successful", "data": data})
        db_log_msg(self.index, req, f"JobResource.on_get_job_result - success.")

    @timing
    def on_get_result_job(self, req, resp, result_id=None):
        # validate that we only allow hexstrings with 24 chars
        if not re.match("[a-fA-F0-9]{24}", result_id):
            resp.status = falcon.HTTP_400
            resp.data = jsonify({"status": "failed", "data": {"message": "Valid ResultIDs are hexstrings with 24 characters."}})
            db_log_msg(self.index, req, f"JobResource.on_get_job_result - failed - invalid result_id.")
            return  
        job_id = self.index.getJobIdForResult(result_id)
        data = self.index.getJobData(job_id)
        # TODO throw 404 if job_id is unknown
        # resp.status = falcon.HTTP_404
        resp.data = jsonify({"status": "successful", "data": data})
        db_log_msg(self.index, req, f"JobResource.on_get_result_job - success.")