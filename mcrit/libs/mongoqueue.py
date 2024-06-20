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
from typing import List, Any, Dict, Iterable, List, Optional, Set, Tuple, Union

import gridfs
import pymongo
from pymongo import MongoClient, ReturnDocument
from bson.objectid import ObjectId

DEFAULT_INSERT = {
    "locked_by": None,
    "locked_at": None,
    "last_error": None,
    "finished_at": None,
    "created_at": None,
    "started_at": None,
    "terminated": False,
    "required_by": [],
    "number": None,
    "result": None,
    "notify_done": False,
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

    def __init__(self, queue_config, consumer_id, timeout=300, max_attempts=3):
        """ """
        self.queue_config = queue_config
        self.collection = None
        self.queue_counters = None
        self.queue_counters_initialized = False
        self.consumer_id = consumer_id
        self.timeout = timeout
        self.max_attempts = max_attempts
        self._default_insert = dict(DEFAULT_INSERT)
        self._default_insert["attempts_left"] = max_attempts
        self.fs = None
        self.fs_files = None
        self.cache_time = 10 ** 9

    def _getCollection(self):
        # because of gunicorn and forking workers, we want to delay creation of MongoClient until actual usage and avoid it within __init__()
        if self.collection is None:
            userpw_url = f"{self.queue_config.QUEUE_MONGODB_USERNAME}:{self.queue_config.QUEUE_MONGODB_PASSWORD}@" if self.queue_config.QUEUE_MONGODB_USERNAME and len(self.queue_config.QUEUE_MONGODB_USERNAME) > 0 and self.queue_config.QUEUE_MONGODB_PASSWORD and len(self.queue_config.QUEUE_MONGODB_PASSWORD) > 0 else ""
            port_url = f":{self.queue_config.QUEUE_PORT}" if self.queue_config.QUEUE_PORT else ""
            flags_url = f"?{self.queue_config.QUEUE_MONGODB_FLAGS}" if self.queue_config.QUEUE_MONGODB_FLAGS and len(self.queue_config.QUEUE_MONGODB_FLAGS) > 0 else ""

            mongo_uri = f"mongodb://{userpw_url}{self.queue_config.QUEUE_SERVER}{port_url}/{self.queue_config.QUEUE_MONGODB_DBNAME}{flags_url}"

            db = MongoClient(mongo_uri, connect=False)
            self.collection = db[self.queue_config.QUEUE_MONGODB_DBNAME][self.queue_config.QUEUE_MONGODB_COLLECTION_NAME]
            self.fs = gridfs.GridFS(self.collection.database)
            self.fs_files = self.collection.database["fs.files"]
            self.queue_counters = db[self.queue_config.QUEUE_MONGODB_DBNAME][self.queue_config.QUEUE_MONGODB_COLLECTION_NAME + "_counters"]
            self.queue_counters_initialized = self.queue_counters.find_one({"last_updated": {"$ne": None}})
            if not self.queue_counters_initialized:
                self.refreshCounters()
            self.registerWorker()
            self._ensure_indices()
        return self.collection
    
    def _getFs(self):
        if self.fs is None:
            collection = self._getCollection()
            self.fs = gridfs.GridFS(collection.database)
            self.fs_files = self.collection.database["fs.files"]
        return self.fs
    
    def _getFsFiles(self):
        if self.fs_files is None:
            collection = self._getCollection()
            self.fs = gridfs.GridFS(self.collection.database)
            self.fs_files = collection.database["fs.files"]
        return self.fs_files

    def _ensure_indices(self):
        # should only be called, after self.collection has been initiated
        self.collection.create_index("payload.method")
        self.collection.create_index("payload.descriptor")
        self.fs_files.create_index("metadata.sha256")

    def _identifyJobState(self, doc):
        # started_at and not finished_at or terminated -> in_progress
        if doc["started_at"] and doc["locked_by"] and not (doc["finished_at"] or doc["terminated"]):
            return "in_progress"
        # attempts_left == 0 and not finished_at and not terminated -> failed
        elif doc["attempts_left"] == 0 and not doc["finished_at"] and not doc["terminated"]:
            return "failed"
        # not finished_at, not locked_by -> queued
        elif not doc["finished_at"] and not doc["locked_by"] and not doc["terminated"]:
            return "queued"
        # finished_at and not terminated -> finished
        elif doc["finished_at"] and not doc["terminated"]:
            return "finished"
        # terminated -> terminated
        elif doc["terminated"]:
            return "terminated"
        return "unknown"
    
    def getQueueStatistics(self, refresh=False):
        self._getCollection()
        if refresh:
            self.refreshCounters()
        statistics = {}
        for doc in self.queue_counters.find({}, {"_id": 0}):
            if "name" in doc and doc["name"] != "workers":
                name = doc.pop("name")
                statistics[name] = doc
        return statistics

    def refreshCounters(self):
        aggregated = {}
        for doc in self.collection.find():
            method = doc["payload"]["method"]
            if method not in aggregated:
                aggregated[method] = {
                    "queued": 0,
                    "failed": 0,
                    "in_progress": 0,
                    "finished": 0,
                    "terminated": 0
                }
            state = self._identifyJobState(doc)
            aggregated[method][state] += 1
        for key, counters in aggregated.items():
            self.queue_counters.update_one({"name": key}, {"$set": counters}, upsert=True)
        self.queue_counters.update_one({"last_updated": {"$ne": None}}, {"$set": {"last_updated": datetime.now()}}, upsert=True)

    def updateQueueCounter(self, method, state, value):
        self._getCollection()
        self.queue_counters.update_one({"name": method}, {"$inc": {state: value}}, upsert=True)
        # could probably also be done in one line with an aggregator update
        if value < 0:
            self.queue_counters.update_one({"name": method, state: {"$lt": 0}}, {"$set": {state: 0}})
        self.queue_counters.update_one({"last_updated": {"$ne": None}}, {"$set": {"last_updated": datetime.now()}}, upsert=True)
        return

    def registerWorker(self):
        if self.consumer_id != "index":
            self.queue_counters.find_one_and_update(
                {"name": "workers"},
                {"$push": {"workers": self.consumer_id}},
                upsert=True
            )
        self.release_orphaned_jobs()

    def unregisterWorker(self):
        if self.queue_counters is not None:
            self.queue_counters.find_one_and_update(
                {"name": "workers"},
                {"$pull": {"workers": self.consumer_id}},
                upsert=True
            )

    def close(self):
        """Close the in memory queue connection."""
        self._getCollection().connection.close()

    def clear(self):
        """Clear the queue."""
        self._getCollection().database["fs"].drop()
        self._getCollection().drop()
        self._ensure_indices()

    def size(self):
        """Total size of the queue"""
        return self._getCollection().count_documents({"finished_at": None})

    def size_inc_finished(self):
        """Total size of the queue"""
        return self._getCollection().count_documents(ilter={})

    def repair(self):
        """Clear out stale locks.

        Increments per job attempt counter.
        """
        self._getCollection().find_one_and_update(
            filter={"locked_by": {"$ne": None}, "locked_at": {"$lt": datetime.now() - timedelta(self.timeout)}},
            update={"$set": {"locked_by": None, "locked_at": None}, "$inc": {"attempts_left": -1}},
        )

    def drop_max_attempts(self):
        """ """
        self._getCollection().find_one_and_update({"attempts_left": {"$lte": 0}}, remove=True)

    def put(self, payload, priority=0, await_jobs:List[str]=[]):
        """Place a job into the queue"""
        job = dict(self._default_insert)
        job["number"] = _useCounter(self._getCollection().database, "job")
        job["created_at"] = datetime.now()
        job["priority"] = priority
        job["payload"] = payload
        await_jobs_set = set(await_jobs)
        job["unfinished_dependencies"] = list(await_jobs_set)
        job["all_dependencies"] = list(await_jobs_set)
        insert_result = self._getCollection().insert_one(job)
        if insert_result.acknowledged:
            job_id = insert_result.inserted_id
            for child_job_id in await_jobs_set:
                self._notify_on_done(child_job_id, job_id)
            self.updateQueueCounter(payload["method"], "queued", 1)
            return job_id
        return None

    def _notify_on_done(self, notifying_job_id:str, notified_job_id:str):
        self._getCollection().find_one_and_update(
            filter={"_id": ObjectId(notifying_job_id)},
            update={"$push": {'required_by': notified_job_id}}
        )
        notifying_job = self._getCollection().find_one({"_id": ObjectId(notifying_job_id)})
        if notifying_job["notify_done"]:
            self._getCollection().find_one_and_update(
                filter={"_id": ObjectId(notified_job_id)},
                update={"$pull": {'unfinished_dependencies': notifying_job_id}},
            )
        #     # atomically
        #     # should handle already deleted deps gracefully
        #     remove job.id from job_to_notify.unfinished_deps
    
    def _notify_dependent_jobs(self, job_id:str):
        job = self._getCollection().find_one_and_update(
            filter={"_id": ObjectId(job_id)},
            update={"$set": {'notify_done': True}},
        )
        for job_id_to_notify in job["required_by"]:
            self._getCollection().find_one_and_update(
                filter={"_id": ObjectId(job_id_to_notify)},
                update={"$pull": {'unfinished_dependencies': job_id}},
            )

    def next(self):
        current_time = datetime.now()
        job =  self._getCollection().find_one_and_update(
                filter={
                    "locked_by": None,
                    "locked_at": None,
                    "attempts_left": {"$gt": 0},
                    "finished_at": None,
                    "unfinished_dependencies": [],
                },
                update={"$set": {"locked_by": self.consumer_id, "locked_at": current_time, "started_at": current_time}},
                sort=[("priority", pymongo.DESCENDING), ("created_at", pymongo.ASCENDING)],
                new=1,
                # limit=1
            )
        if job:
            self.updateQueueCounter(job["payload"]["method"], "in_progress", 1)
            self.updateQueueCounter(job["payload"]["method"], "queued", -1)
        return self._wrap_one(job)

    def _jobs_to_do(self):
        return self._getCollection().find(
            filter={"locked_by": None, "locked_at": None, "attempts_left": {"$gt": 0}, "finished_at": None},
            sort=[("priority", pymongo.DESCENDING)],
        )

    def _jobs_in_progress(self):
        return self._getCollection().find(
            filter={
                "locked_by": {"$ne": None},
                "locked_at": {"$ne": None},
                "attempts_left": {"gt": 0},
                "finished_at": None,
            },
            sort=[("priority", pymongo.DESCENDING)],
        )

    def _jobs_given_up(self):
        return self._getCollection().find(
            filter={"attempts_left": {"$le": 0}, "finished_at": None},
            sort=[("priority", pymongo.DESCENDING)],
        )

    def _jobs_finished(self):
        return self._getCollection().findOne(
            filter={"finished_at": {"$ne": None}},
            sort=[("priority", pymongo.DESCENDING)],
        )

    def _wrap_one(self, data):
        return data and Job(self, data) or None

    def stats(self):
        """Get statistics on the queue.

        Use sparingly requires a collection lock.
        """
        queries = []
        queries.append({"locked_by": None, "attempts_left": {"$gt": 0}})
        queries.append({"locked_by": {"$ne": None}})
        queries.append({"attempts_left": {"$lte": 0}})
        queries.append({})
        counts = [self._getCollection().count_documents(q) for q in queries]

        return dict(zip(["available", "locked", "errors", "total"], counts))

    def get_jobs(self, start_index: int, limit: int, method=None, state=None, ascending=False) -> Optional[List["Job"]]:
        jobs = []
        query_filter = {} if method == None else {"payload.method": method}
        if state is None:
            if ascending:
                for job_document in self._getCollection().find(query_filter).skip(start_index).limit(limit):
                    jobs.append(self._wrap_one(job_document))
            else:
                for job_document in self._getCollection().find(query_filter, sort=[("_id", -1)]).skip(start_index).limit(limit):
                    jobs.append(self._wrap_one(job_document))
        else:
            # we go with an inefficient implementation for now to see if this is a desired feature and revise the query in case we deem this useful.
            # TODO improve performance of these queries, we probably want to find a query_filter for the different possible states to allow use of skip/limit
            all_jobs = []
            if ascending:
                for job_document in self._getCollection().find(query_filter):
                    if self._identifyJobState(job_document) == state:
                        all_jobs.append(self._wrap_one(job_document))
            else:
                for job_document in self._getCollection().find(query_filter, sort=[("_id", -1)]):
                    if self._identifyJobState(job_document) == state:
                        all_jobs.append(self._wrap_one(job_document))
            # apply skip/limit as slice on the result
            if limit:
                jobs = all_jobs[start_index:start_index+limit]
            else:
                jobs = all_jobs[start_index:]
        return jobs

    def get_job(self, job_id):
        job_id = ObjectId(job_id)
        return self._wrap_one(self._getCollection().find_one({"_id": job_id}))

    def delete_job(self, job_id, with_result=True):
        job_id = ObjectId(job_id)
        deletable_job = self._getCollection().find_one({"_id": job_id})
        if deletable_job:
            self.updateQueueCounter(deletable_job["payload"]["method"], self._identifyJobState(deletable_job), -1)
            # if job has file parameters, we need to remove them from GridFS as well
            print(deletable_job)
            if "file_params" in deletable_job["payload"]:
                file_params_dict = json.loads(deletable_job["payload"]["file_params"])
                for _, file_object_id in file_params_dict.items():
                    file_object_id = ObjectId(file_object_id)
                    # update gridFs entry of file to not link
                    # to this job anymore
                    self._getFs().update_one(
                        {"_id": file_object_id}, {"$pull": {"metadata.jobs": str(job_id)}}
                    )
                    # check if file is safe to delete
                    if self._getFs().count_documents(
                        {"_id": file_object_id, "metadata.jobs": [], "metadata.tmp_lock": 0}
                    ) > 0:
                        self._getFs().delete(file_object_id)
            if with_result:
                # delete result from GridFS  
                self._getFs().delete(ObjectId(deletable_job["result"]))
        job_deletion_result = self._getCollection().delete_one({"_id": job_id})
        return job_deletion_result.deleted_count

    def delete_jobs(self, method=None, created_before=None, finished_before=None, with_results=True):
        filter_count = len([1 for item in [method, created_before, finished_before] if item is not None])
        combined_filter = {"$and": []} if filter_count > 1 else {}
        method_filter = {}
        created_filter = {}
        finished_filter = {}
        if method is not None:
            method_filter = {"payload.method": method}
            if filter_count > 1:
                combined_filter["$and"].append(method_filter)
            else:
                combined_filter = method_filter
        if created_before is not None:
            created_filter = {"created_at": {"$lt": created_before}}
            if filter_count > 1:
                combined_filter["$and"].append(created_filter)
            else:
                combined_filter = created_filter
        elif finished_before is not None:
            finished_filter = {"finished_at": {"$lt": finished_before}}
            if filter_count > 1:
                combined_filter["$and"].append(finished_filter)
            else:
                combined_filter = finished_filter
        # run find() first to determine how many jobs of which method will be deleted and what their results are
        jobs_to_be_deleted = [j for j in self._getCollection().find(combined_filter)]
        # delete results
        for deletable_job in jobs_to_be_deleted:
            self.updateQueueCounter(deletable_job["payload"]["method"], self._identifyJobState(deletable_job), -1)
            if with_results and deletable_job["result"]:
                    # delete result from GridFS  
                    self._getFs().delete(ObjectId(deletable_job["result"]))
        job_deletion_result = self._getCollection().delete_many(combined_filter)
        if len(jobs_to_be_deleted) != job_deletion_result.deleted_count:
            raise Exception("Number of deleted jobs was unequal to number of jobs to delete!")
        return job_deletion_result.deleted_count

    def _file_to_grid(self, binary, metadata=None):
        object_id = self._getFs().put(binary, metadata=metadata)
        return str(object_id)

    def _grid_to_file(self, grid, results_only=True):
        oid = ObjectId(grid)
        if not self._getFs().exists(oid):
            return None
        entry = self._getFs().get(oid)
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
        self._getFs().delete(oid)

    def _grid_to_meta(self, grid):
        oid = ObjectId(grid)
        entry = self._getFs().get(oid)
        return entry.metadata

    def get_cached_job_id(self, payload):
        job = self._wrap_one(
            self._getCollection().find_one(
                {
                    "attempts_left": {"$gt": 0},
                    "payload.descriptor": payload["descriptor"],
                    "terminated": False,
                },
                sort=[("created_at", pymongo.DESCENDING)],
            )
        )
        return job and job.job_id or None

    def getFileByHash(self, sha256, max_bytes=-1):
        file = self._getFs().find_one({"metadata.sha256": sha256})
        if file:
            return file.read(max_bytes)

    def get_file_by_hash_inc_lock(self, sha256):
        file = self._getFsFiles().find_one_and_update({"metadata.sha256": sha256}, {"$inc": {"metadata.tmp_lock": 1}})
        return file and str(file["_id"]) or None

    def add_job_id_to_file(self, job_id, file_id):
        file_id = ObjectId(file_id)
        self._getFsFiles().find_one_and_update(
            {"_id": file_id}, {"$inc": {"metadata.tmp_lock": -1}, "$addToSet": {"metadata.jobs": job_id}}
        )

    def clean(self):
        # TODO consider a good way to implement this
        # we probably do not want to drop matches and their results automatically, which would be the case right now
        time_threshold = datetime.now() - timedelta(seconds=self.cache_time)
        job_query = {"finished_at": {"$lt": time_threshold}}
        to_delete = self._getCollection().find(job_query)
        to_delete = list(to_delete)
        results = [data["result"] for data in to_delete]
        file_params = {data["_id"]: list(json.loads(data["payload"]["file_params"]).values()) for data in to_delete}

        # delete results
        for r in results:
            self._delete_grid(r)

        # remove job from params
        for job, params in file_params.items():
            self._getFsFiles().update_many(
                {"_id": {"$in": [ObjectId(p) for p in params]}}, {"$pull": {"metadata.jobs": str(job)}}
            )

        # delete params
        all_params = [ObjectId(j) for i in file_params.values() for j in i]
        # for all of the params that can be deleted (with no jobs, and no lock), remove the sha256
        # In this way the file cannot be utilized as a cached file again
        self._getFsFiles().update_many(
            {"_id": {"$in": all_params}, "metadata.jobs": [], "metadata.tmp_lock": 0},
            {"$set": {"metadata.sha256": None}},
        )
        # now get the list of files to be deleted
        params_to_delete = self._getFsFiles().find(
            {"_id": {"$in": all_params}, "metadata.jobs": [], "metadata.tmp_lock": 0, "metadata.sha256": None}
        )
        # delete them
        for p in params_to_delete:
            self._getFs().delete(ObjectId(p["_id"]))

        # delete jobs
        self._getCollection().delete_many(job_query)

    def release_all_jobs(self, consumer_id=None):
        # release all jobs associated with our consumer id if they are started, locked, but not finished.
        self._getCollection().update_many(
        filter={"locked_by": consumer_id if consumer_id else self.consumer_id, "started_at": {"$ne": None}, "finished_at": {"$eq": None}},
        update={"$set": {"locked_by": None, "locked_at": None}, "$inc": {"attempts_left": -1}}
        )

    def release_orphaned_jobs(self):
        # release all jobs associated with non- or no longer existing worker_ids, if they are started, locked, but not finished.
        all_worker_ids = set([wid for wid in self._getCollection().distinct("locked_by") if wid])
        active_workers = self.queue_counters.find_one({"name": "workers"}, {"workers": 1, "_id": 0})
        orphan_ids = []
        if active_workers:
            active_worker_ids = set(active_workers["workers"])
            orphan_ids = all_worker_ids.difference(active_worker_ids)
        else:
            orphan_ids = all_worker_ids

        orphaned_jobs = []
        for orphan_id in orphan_ids:
            for job in self._getCollection().find(filter={"locked_by": orphan_id , "started_at": {"$ne": None}, "finished_at": {"$eq": None}}):
                orphaned_jobs.append(job)

        for orphan_consumer_id in orphan_ids:
            self._getCollection().update_many(
            filter={"locked_by": orphan_consumer_id , "started_at": {"$ne": None}, "finished_at": {"$eq": None}},
            update={"$set": {"locked_by": None, "locked_at": None}, "$inc": {"attempts_left": -1}}
            )

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
    def attempts_left(self):
        return self._data["attempts_left"]

    @property
    def is_failed(self):
        return self._data["attempts_left"] == 0

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


    # This is a GridFS id, not the actual result
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
        job = self._queue.collection.find_one_and_update(
            filter={"_id": self.job_id, "locked_by": self._queue.consumer_id},
            update={"$set": {"finished_at": datetime.now(), "result": self._data["result"], "progress": 1}},
            return_document=ReturnDocument.AFTER
        )
        self._queue.updateQueueCounter(job["payload"]["method"], "in_progress", -1)
        self._queue.updateQueueCounter(job["payload"]["method"], "finished", 1)
        self._queue._notify_dependent_jobs(str(job["_id"]))
        return job 

    def error(self, message=None):
        """note an error processing a job, and return it to the queue."""
        job = self._queue.collection.find_one_and_update(
            filter={"_id": self.job_id, "locked_by": self._queue.consumer_id},
            update={"$set": {"locked_by": None, "locked_at": None, "last_error": message}, "$inc": {"attempts_left": -1}},
            return_document=ReturnDocument.AFTER
        )
        self._queue.updateQueueCounter(job["payload"]["method"], "in_progress", -1)
        self._queue.updateQueueCounter(job["payload"]["method"], "queued", 1)
        if job["attempts_left"] <= 0:
            self._queue._notify_dependent_jobs(self, str(job["_id"]))
            self._queue.updateQueueCounter(job["payload"]["method"], "queued", -1)
            self._queue.updateQueueCounter(job["payload"]["method"], "failed", 1)


    def progressor(self, count=0):
        """note progress on a long running task."""
        return self._queue.collection.find_one_and_update(
            filter={"_id": self.job_id, "locked_by": self._queue.consumer_id},
            update={"$set": {"progress": count, "locked_at": datetime.now()}},
            return_document=ReturnDocument.AFTER
        )

    def release(self):
        """put the job back into_queue."""
        job = self._queue.collection.find_one_and_update(
            filter={"_id": self.job_id, "locked_by": self._queue.consumer_id},
            update={"$set": {"locked_by": None, "locked_at": None}, "$inc": {"attempts_left": -1}},
            return_document=ReturnDocument.AFTER
        )
        self._queue.updateQueueCounter(job["payload"]["method"], "in_progress", -1)
        self._queue.updateQueueCounter(job["payload"]["method"], "queued", 1)
        if job["attempts_left"] <= 0:
            self._queue._notify_dependent_jobs(self, str(job["_id"]))
            self._queue.updateQueueCounter(job["payload"]["method"], "queued", -1)
            self._queue.updateQueueCounter(job["payload"]["method"], "failed", 1)
        return job

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
        job = self._queue.collection.find_one_and_update(
            filter={"_id": self.job_id}, 
            update={"$set": {"terminated": True, "locked_at": datetime.now()}},
            return_document=ReturnDocument.AFTER
        )
        self._queue.updateQueueCounter(job["payload"]["method"], "in_progress", -1)
        self._queue.updateQueueCounter(job["payload"]["method"], "terminated", 1)
        return job
