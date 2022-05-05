#   Copyright 2012 Kapil Thangavelu
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


import json
import traceback
from datetime import datetime, timedelta

import gridfs
import pymongo
from pymongo import ReturnDocument
from bson.objectid import ObjectId

DEFAULT_INSERT = {
    "attempts": 0,
    "locked_by": None,
    "locked_at": None,
    "last_error": None,
    "finished_at": None,
    "created_at": None,
    "started_at": None,
    "terminated": False,
    "number": None,
    "result": None,
}

# added to track incremental job numbers via MCRIT storage (apart from OIDs)
def _useCounter(database, name: str) -> int:
    result = database.counters.find_one_and_update(
        filter={"name": name}, 
        update={"$inc": {"value": 1}}, 
        upsert=True
    )
    if result is None:
        return 0
    return result["value"]


class MongoQueue(object):
    """A queue class"""

    def __init__(self, collection, consumer_id, timeout=300, max_attempts=3):
        """ """
        self.collection = collection
        self.consumer_id = consumer_id
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.fs = gridfs.GridFS(self.collection.database)
        self.fs_files = self.collection.database["fs.files"]
        self._ensure_indices()
        self.cache_time = 10 ** 9

    def _ensure_indices(self):
        self.collection.create_index("payload.descriptor")
        self.fs_files.create_index("metadata.sha256")

    def close(self):
        """Close the in memory queue connection."""
        self.collection.connection.close()

    def clear(self):
        """Clear the queue."""
        self.collection.database["fs"].drop()
        self.collection.drop()
        self._ensure_indices()

    def size(self):
        """Total size of the queue"""
        return self.collection.count_documents({"finished_at": None})

    def size_inc_finished(self):
        """Total size of the queue"""
        return self.collection.count_documents(ilter={})

    def repair(self):
        """Clear out stale locks.

        Increments per job attempt counter.
        """
        self.collection.find_one_and_update(
            filter={"locked_by": {"$ne": None}, "locked_at": {"$lt": datetime.now() - timedelta(self.timeout)}},
            update={"$set": {"locked_by": None, "locked_at": None}, "$inc": {"attempts": 1}},
        )

    def drop_max_attempts(self):
        """ """
        self.collection.find_one_and_update({"attempts": {"$gte": self.max_attempts}}, remove=True)

    def put(self, payload, priority=0):
        """Place a job into the queue"""
        job = dict(DEFAULT_INSERT)
        job["number"] = _useCounter(self.collection.database, "job")
        job["created_at"] = datetime.now()
        job["priority"] = priority
        job["payload"] = payload
        insert_result = self.collection.insert_one(job)
        if insert_result.acknowledged:
            return insert_result.inserted_id
        return None

    def next(self):
        current_time = datetime.now()
        return self._wrap_one(
            self.collection.find_one_and_update(
                filter={
                    "locked_by": None,
                    "locked_at": None,
                    "attempts": {"$lt": self.max_attempts},
                    "finished_at": None,
                },
                update={"$set": {"locked_by": self.consumer_id, "locked_at": current_time, "started_at": current_time}},
                sort=[("priority", pymongo.DESCENDING), ("created_at", pymongo.ASCENDING)],
                new=1,
                # limit=1
            )
        )

    def _jobs_to_do(self):
        return self.collection.find(
            filter={"locked_by": None, "locked_at": None, "attempts": {"$lt": self.max_attempts}, "finished_at": None},
            sort=[("priority", pymongo.DESCENDING)],
        )

    def _jobs_in_progress(self):
        return self.collection.find(
            filter={
                "locked_by": {"$ne": None},
                "locked_at": {"$ne": None},
                "attempts": {"$lt": self.max_attempts},
                "finished_at": None,
            },
            sort=[("priority", pymongo.DESCENDING)],
        )

    def _jobs_given_up(self):
        return self.collection.find(
            filter={"attempts": {"$ge": self.max_attempts}, "finished_at": None},
            sort=[("priority", pymongo.DESCENDING)],
        )

    def _jobs_finished(self):
        return self.collection.findOne(
            filter={"finished_at": {"$ne": None}},
            sort=[("priority", pymongo.DESCENDING)],
        )

    def _wrap_one(self, data):
        return data and Job(self, data) or None

    def stats(self):
        """Get statistics on the queue.

        Use sparingly requires a collection lock.
        """
        querys = []
        querys.append({"locked_by": None, "attempts": {"$lt": self.max_attempts}})
        querys.append({"locked_by": {"$ne": None}})
        querys.append({"attempts": {"$gte": self.max_attempts}})
        querys.append({})
        counts = [self.collection.count_documents(q) for q in querys]
        js = """function queue_stat(){
        return db.eval(
        function(){
           var a = db.%(collection)s.count(
               {'locked_by': null,
                'attempts': {$lt: %(max_attempts)i}});
           var l = db.%(collection)s.count({'locked_by': /.*/});
           var e = db.%(collection)s.count(
               {'attempts': {$gte: %(max_attempts)i}});
           var t = db.%(collection)s.count();
           return [a, l, e, t];
           })}""" % {
            "collection": self.collection.name,
            "max_attempts": self.max_attempts,
        }

        return dict(zip(["available", "locked", "errors", "total"], counts))

    def get_jobs(self):
        jobs = []
        for job_document in self.collection.find():
            jobs.append(self._wrap_one(job_document))
        return jobs

    def get_job(self, job_id):
        job_id = ObjectId(job_id)
        return self._wrap_one(self.collection.find_one({"_id": job_id}))

    def _file_to_grid(self, binary, metadata=None):
        object_id = self.fs.put(binary, metadata=metadata)
        return str(object_id)

    def _grid_to_file(self, grid, results_only=True):
        oid = ObjectId(grid)
        if not self.fs.exists(oid):
            return None
        entry = self.fs.get(oid)
        if results_only:
            metadata = entry.metadata
            if not "result" in metadata or not metadata["result"]:
                return b'"Access Not Allowed"'
        result = entry.read()
        return result

    def _dicts_to_grid(self, dicts, **kwargs):
        return self._file_to_grid(json.dumps(dicts).encode("ascii"), **kwargs)

    def _grid_to_dicts(self, grid, **kwargs):
        result = None
        grid_file = self._grid_to_file(grid, **kwargs)
        if grid_file is not None:
            decoded_file = grid_file.decode("ascii")
            result = json.loads(grid_file)
        return result

    def _delete_grid(self, grid):
        oid = ObjectId(grid)
        self.fs.delete(oid)

    def _grid_to_meta(self, grid):
        oid = ObjectId(grid)
        entry = self.fs.get(oid)
        return entry.metadata

    def get_cached_job_id(self, payload):
        job = self._wrap_one(
            self.collection.find_one(
                {
                    "attempts": {"$lt": self.max_attempts},
                    "payload.descriptor": payload["descriptor"],
                    "terminated": False,
                },
                sort=[("created_at", pymongo.DESCENDING)],
            )
        )
        return job and job.job_id or None

    def _get_file_by_hash(self, sha256):
        file = self.fs.find_one({"metadata.sha256": sha256})

    def get_file_by_hash_inc_lock(self, sha256):
        file = self.fs_files.find_one_and_update({"metadata.sha256": sha256}, {"$inc": {"metadata.tmp_lock": 1}})
        return file and str(file["_id"]) or None

    def add_job_id_to_file(self, job_id, file_id):
        file_id = ObjectId(file_id)
        self.fs_files.find_one_and_update(
            {"_id": file_id}, {"$inc": {"metadata.tmp_lock": -1}, "$addToSet": {"metadata.jobs": job_id}}
        )

    def clean(self):
        time_threshold = datetime.now() - timedelta(seconds=self.cache_time)
        job_query = {"finished_at": {"$lt": time_threshold}}
        to_delete = self.collection.find(job_query)
        to_delete = list(to_delete)
        results = [data["result"] for data in to_delete]
        file_params = {data["_id"]: list(json.loads(data["payload"]["file_params"]).values()) for data in to_delete}

        # delete results
        for r in results:
            self._delete_grid(r)

        # remove job from params
        for job, params in file_params.items():
            self.fs_files.update_many(
                {"_id": {"$in": [ObjectId(p) for p in params]}}, {"$pull": {"metadata.jobs": str(job)}}
            )

        # delete params
        all_params = [ObjectId(j) for i in file_params.values() for j in i]
        # for all of the params that can be deleted (with no jobs, and no lock), remove the sha256
        # In this way the file cannot be utilized as a cached file again
        self.fs_files.update_many(
            {"_id": {"$in": all_params}, "metadata.jobs": [], "metadata.tmp_lock": 0},
            {"$set": {"metadata.sha256": None}},
        )
        # now get the list of files to be deleted
        params_to_delete = self.fs_files.find(
            {"_id": {"$in": all_params}, "metadata.jobs": [], "metadata.tmp_lock": 0, "metadata.sha256": None}
        )
        # delete them
        for p in params_to_delete:
            self.fs.delete(ObjectId(p["_id"]))

        # delete jobs
        self.collection.delete_many(job_query)


    def terminate_all_jobs(self):
        pass

class Job(object):
    def __init__(self, queue, data):
        """ """
        self._queue = queue
        self._data = data

    def __str__(self) -> str:
        return f"ID: {self.job_id}, created: {self.created_at}, finished: {self.finished_at}, result: {self.result}"

    @property
    def method(self):
        return self._data["payload"]["method"]

    @property
    def payload(self):
        return self._data["payload"]

    @property
    def job_id(self):
        return self._data["_id"]

    @property
    def number(self):
        return self._data["number"] if "number" in self._data else -1

    @property
    def priority(self):
        return self._data["priority"]

    @property
    def attempts(self):
        return self._data["attempts"]

    @property
    def locked_by(self):
        return self._data["locked_by"]

    @property
    def locked_at(self):
        return self._data["locked_at"]

    @property
    def created_at(self):
        return self._data["created_at"]

    @property
    def started_at(self):
        return self._data["started_at"]

    @property
    def last_error(self):
        return self._data["last_error"]

    @property
    def finished_at(self):
        return self._data["finished_at"]

    @property
    def is_finished(self):
        return self._data["finished_at"] is not None

    @property
    def parameters(self):
        method_str = ""
        if "payload" in self._data and "params" in self._data["payload"] and "method" in self._data["payload"]:
            payload_params = json.loads(self._data["payload"]["params"])
            method_str = self._data["payload"]["method"]
            indexed_key_values = []
            named_key_values = []
            for k, v in payload_params.items():
                try:
                    int(k)
                    indexed_key_values.append(v)
                except:
                    named_key_values.append(v)
            combined_values = indexed_key_values + named_key_values
            method_str += "(" + ", ".join([str(v) for v in combined_values]) + ")"
        return method_str

    @property
    def progress(self):
        return self._data["progress"]

    @property
    def result(self):
        return self._data["result"]

    @result.setter
    def result(self, res):
        self._data["result"] = res

    ## job control

    def complete(self, result=None):
        """job has been completed."""
        if result:
            self._data["result"] = result
        return self._queue.collection.find_one_and_update(
            filter={"_id": self.job_id, "locked_by": self._queue.consumer_id},
            update={"$set": {"finished_at": datetime.now(), "result": self._data["result"], "progress": 1}},
            return_document=ReturnDocument.AFTER
        )

    def error(self, message=None):
        """note an error processing a job, and return it to the queue."""
        self._queue.collection.find_one_and_update(
            filter={"_id": self.job_id, "locked_by": self._queue.consumer_id},
            update={"$set": {"locked_by": None, "locked_at": None, "last_error": message}, "$inc": {"attempts": 1}},
        )

    def progressor(self, count=0):
        """note progress on a long running task."""
        return self._queue.collection.find_one_and_update(
            filter={"_id": self.job_id, "locked_by": self._queue.consumer_id},
            update={"$set": {"progress": count, "locked_at": datetime.now()}},
            return_document=ReturnDocument.AFTER
        )

    def release(self):
        """put the job back into_queue."""
        return self._queue.collection.find_one_and_update(
            filter={"_id": self.job_id, "locked_by": self._queue.consumer_id},
            update={"$set": {"locked_by": None, "locked_at": None}, "$inc": {"attempts": 1}},
            return_document=ReturnDocument.AFTER
        )

    ## context manager support

    def __enter__(self):
        return self._data

    def __exit__(self, type, value, tb):
        if (type, value, tb) == (None, None, None):
            self.complete()
        else:
            error = traceback.format_exc()
            self.error(error)

    # only works for jobs that report progress
    def _is_terminated(self, use_cached=False):
        if use_cached:
            data = self._data
        else:
            data = self._queue.collection.find_one({"_id": self.job_id})

        if data is None:
            return True

        return ("terminated" in data) and data["terminated"] or False

    # only works for jobs that report progress
    def terminate(self):
        return self._queue.collection.find_one_and_update(
            filter={"_id": self.job_id}, 
            update={"$set": {"terminated": True, "locked_at": datetime.now()}},
            return_document=ReturnDocument.AFTER
        )
