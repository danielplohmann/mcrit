import re
import logging
import datetime

import falcon

from mcrit.server.utils import timing, jsonify
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.server.utils import db_log_msg
from mcrit.queue.LocalQueue import Job

# TODO these should also return status and data in their json response

class JobResource:
    def __init__(self, index: MinHashIndex):
        self.index = index

    @timing
    def on_get_collection(self, req, resp):
        # parse optional request parameters
        ascending = False
        if "ascending" in req.params:
            ascending = req.params["ascending"].lower().strip() == "true"
        method_filter = None
        if "method" in req.params:
            method_filter = req.params["method"]
        state_filter = None
        if "state" in req.params:
            state_filter = req.params["state"]
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
        queue_data = self.index.getQueueData(start_index=start_job_id, limit=limit_job_count, method=method_filter, state=state_filter, filter=query_filter, ascending=ascending)
        resp.data = jsonify({"status": "successful", "data": queue_data})
        db_log_msg(self.index, req, f"JobResource.on_get_collection - success.")

    @timing
    def on_get_stats(self, req, resp):
        query_with_refresh = False
        if "with_refresh" in req.params:
            query_with_refresh = req.params["with_refresh"].lower().strip() == "true"
        queue_data = self.index.getQueueStats(refresh=query_with_refresh)
        resp.data = jsonify({"status": "successful", "data": queue_data})
        db_log_msg(self.index, req, f"JobResource.on_get_stats - success.")

    @timing
    def on_delete_collection(self, req, resp):
        # parse optional request parameters, to be used as an "AND" query
        method_filter = None
        if "method" in req.params:
            method_filter = req.params["method"]
        created_before = None
        if "created_before" in req.params:
            try:
                if len(req.params["created_before"]) == 10:
                    created_before = datetime.datetime.strptime(req.params["created_before"], "%Y-%m-%d")
                else:
                    created_before = datetime.datetime.strptime(req.params["created_before"], "%Y-%m-%dT%H:%M:%S")
            except:
                pass
        finished_before = None
        if "finished_before" in req.params:
            try:
                if len(req.params["finished_before"]) == 10:
                    finished_before = datetime.datetime.strptime(req.params["finished_before"], "%Y-%m-%d")
                else:
                    finished_before = datetime.datetime.strptime(req.params["finished_before"], "%Y-%m-%dT%H:%M:%S")
            except:
                pass
        # newest first
        result = self.index.deleteQueueData(method=method_filter, created_before=created_before, finished_before=finished_before)
        resp.data = jsonify({"status": "successful", "data": {"num_deleted": result}})
        db_log_msg(self.index, req, f"JobResource.on_delete_collection - success.")

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
    def on_delete(self, req, resp, job_id=None):
        # validate that we only allow hexstrings with 24 chars
        if not re.match("[a-fA-F0-9]{24}", job_id):
            resp.status = falcon.HTTP_400
            resp.data = jsonify({"status": "failed", "data": {"message": "Valid JobIDs are hexstrings with 24 characters."}})
            db_log_msg(self.index, req, f"JobResource.on_delete - failed - invalid job_id.")
            return  
        result = self.index.deleteJob(job_id)
        # TODO throw 404 if job_id is unknown
        # resp.status = falcon.HTTP_404
        resp.data = jsonify({"status": "successful", "data": {"num_deleted": result}})
        db_log_msg(self.index, req, f"JobResource.on_delete - success.")

    @timing
    def on_get_results(self, req, resp, result_id=None):
        # validate that we only allow hexstrings with 24 chars
        if not re.match("[a-fA-F0-9]{24}", result_id):
            resp.status = falcon.HTTP_400
            resp.data = jsonify({"status": "failed", "data": {"message": "Valid ResultIDs are hexstrings with 24 characters."}})
            db_log_msg(self.index, req, f"JobResource.on_get_results - failed - invalid result_id.")
            return 
        job_id = self.index.getJobIdForResult(result_id)
        job_data = self.index.getJobData(job_id)
        data = self.index.getResult(result_id)
        if "compact" in req.params and req.params["compact"].lower().strip() == "true":
            if job_data:
                job_info = Job(job_data, None)
                if job_info.is_matching_job or job_info.is_query_job:
                    data["matches"].pop("functions")
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
        job_data = self.index.getJobData(job_id)
        data = self.index.getResultForJob(job_id)
        if "compact" in req.params and req.params["compact"].lower().strip() == "true":
            if job_data:
                job_info = Job(job_data, None)
                if job_info.is_matching_job or job_info.is_query_job:
                    data["matches"].pop("functions")
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
