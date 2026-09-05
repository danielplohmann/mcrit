import json
import logging
import os
import time
import unittest
from datetime import datetime, timedelta
from unittest import TestCase

import pymongo
import pytest

from mcrit.config.QueueConfig import QueueConfig
from mcrit.libs.mongoqueue import MongoQueue

from .context import getTestMongoServerAndPort

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


@pytest.mark.mongo
class MongoQueueTest(TestCase):
    def setUp(self):
        self.client = pymongo.MongoClient(os.environ.get("TEST_MONGODB"))
        queue_config = QueueConfig()
        queue_config.QUEUE_SERVER, queue_config.QUEUE_PORT = getTestMongoServerAndPort()
        queue_config.QUEUE_MONGODB_DBNAME = "test_queue"
        queue_config.QUEUE_MONGODB_COLLECTION_NAME = "queue_1"
        self.queue = MongoQueue(queue_config, "consumer_1")

    def tearDown(self):
        self.client.drop_database("test_queue")

    def assert_job_equal(self, job, data):
        for k, v in data.items():
            self.assertEqual(job.payload[k], v)

    def test_put_next(self):
        data = {"method": "test_method", "context_id": "alpha", "data": [1, 2, 3], "more-data": time.time()}
        self.queue.put(dict(data))
        job = self.queue.next()
        self.assert_job_equal(job, data)

    def test_get_empty_queue(self):
        job = self.queue.next()
        self.assertEqual(job, None)

    def test_priority(self):
        self.queue.put({"method": "test_method", "name": "alice"}, priority=1)
        self.queue.put({"method": "test_method", "name": "bob"}, priority=2)
        self.queue.put({"method": "test_method", "name": "mike"}, priority=0)

        self.assertEqual(
            ["bob", "alice", "mike"],
            [self.queue.next().payload["name"], self.queue.next().payload["name"], self.queue.next().payload["name"]],
        )

    def test_complete(self):
        data = {"method": "test_method", "context_id": "alpha", "data": [1, 2, 3], "more-data": datetime.now()}

        self.queue.put(data)
        self.assertEqual(self.queue.size(), 1)
        job = self.queue.next()
        job.complete()
        self.assertEqual(self.queue.size(), 0)

    def test_repair_uses_seconds_not_days(self):
        # timedelta()'s first positional argument is days, so the seconds-denominated
        # timeout (QUEUE_TIMEOUT, default 300) used to describe 300 DAYS and repair()
        # could never reclaim anything
        data = {"method": "test_method", "context_id": "alpha", "data": [1]}
        self.queue.put(data)
        job = self.queue.next()
        self.assertIsNotNone(job.job_id)
        # age the lock past the timeout without touching anything else
        stale_locked_at = datetime.now() - timedelta(seconds=self.queue.timeout + 60)
        collection = self.queue._getCollection()
        assert collection is not None
        collection.update_one({"_id": job.job_id}, {"$set": {"locked_at": stale_locked_at}})
        self.queue.repair()
        repaired = collection.find_one({"_id": job.job_id})
        assert repaired is not None
        self.assertIsNone(repaired["locked_by"])
        self.assertIsNone(repaired["locked_at"])
        self.assertEqual(repaired["attempts_left"], self.queue.max_attempts - 1)
        # and the job is claimable again
        self.assertIsNotNone(self.queue.next().job_id)

    def test_repair_leaves_fresh_locks_alone(self):
        data = {"method": "test_method", "context_id": "alpha", "data": [1]}
        self.queue.put(data)
        job = self.queue.next()
        self.queue.repair()
        collection = self.queue._getCollection()
        assert collection is not None
        untouched = collection.find_one({"_id": job.job_id})
        assert untouched is not None
        self.assertEqual(untouched["locked_by"], self.queue.consumer_id)
        self.assertIsNotNone(untouched["locked_at"])
        self.assertEqual(untouched["attempts_left"], self.queue.max_attempts)

    def test_progressor_does_not_resurrect_released_lock(self):
        # regression test for the half-locked starvation found while reproducing #106:
        # a progress heartbeat racing a concurrent release must not write locked_at back
        # onto a job whose locked_by was just cleared - the job would otherwise satisfy
        # neither "claimable" nor "locked" and starve forever
        data = {"method": "test_method", "context_id": "alpha", "data": [1]}
        self.queue.put(data)
        job = self.queue.next()
        job.release()
        job.progressor(count=0.5)
        collection = self.queue._getCollection()
        assert collection is not None
        document = collection.find_one({"_id": job.job_id})
        assert document is not None
        self.assertIsNone(document["locked_by"])
        self.assertEqual(document["progress"], 0.5)
        reclaimed = self.queue.next()
        self.assertIsNotNone(reclaimed.job_id)

    def test_next_claims_half_released_job(self):
        # jobs left half-released by older versions (locked_by None, locked_at set) must
        # remain claimable: locked_by is the authoritative lock, locked_at its heartbeat
        data = {"method": "test_method", "context_id": "alpha", "data": [1]}
        self.queue.put(data)
        job = self.queue.next()
        collection = self.queue._getCollection()
        assert collection is not None
        collection.update_one({"_id": job.job_id}, {"$set": {"locked_by": None}})
        reclaimed = self.queue.next()
        self.assertIsNotNone(reclaimed.job_id)
        self.assertEqual(reclaimed.job_id, job.job_id)

    def test_release(self):
        data = {"method": "test_method", "context_id": "alpha", "data": [1, 2, 3], "more-data": time.time()}

        self.queue.put(data)
        job = self.queue.next()
        job.release()
        self.assertEqual(self.queue.size(), 1)
        job = self.queue.next()
        self.assert_job_equal(job, data)

    def test_error(self):
        pass

    def test_progress(self):
        pass

    def test_stats(self):

        for i in range(5):
            data = {"method": "test_method", "context_id": "alpha", "data": [1, 2, 3], "more-data": time.time()}
            self.queue.put(data)
        job = self.queue.next()
        job.error("problem")
        stats = self.queue.stats()
        self.assertEqual({"available": 5, "total": 5, "locked": 0, "errors": 0}, stats)

    def test_ensure_indices(self):
        collection = self.queue._getCollection()
        assert collection is not None
        index_information = collection.index_information()
        self.assertIn("locked_by_1_finished_at_1_priority_-1_created_at_1", index_information)
        self.assertEqual(
            [("locked_by", 1), ("finished_at", 1), ("priority", -1), ("created_at", 1)],
            index_information["locked_by_1_finished_at_1_priority_-1_created_at_1"]["key"],
        )

    def test_jobs_in_progress(self):
        self.queue.put({"method": "test_method", "name": "alice"})
        self.queue.put({"method": "test_method", "name": "bob"})
        self.assertEqual(0, len(list(self.queue._jobs_in_progress())))
        job = self.queue.next()
        jobs_in_progress = list(self.queue._jobs_in_progress())
        self.assertEqual(1, len(jobs_in_progress))
        self.assertEqual(job.job_id, jobs_in_progress[0]["_id"])

    def test_put_records_username(self):
        with_user = self.queue.put({"method": "test_method"}, username="alice")
        without_user = self.queue.put({"method": "test_method"})
        self.assertEqual("alice", self.queue.get_job(with_user).username)
        self.assertIsNone(self.queue.get_job(without_user).username)
        # a document from before the field existed
        self.queue._getCollection().update_one({"_id": without_user}, {"$unset": {"username": ""}})
        self.assertIsNone(self.queue.get_job(without_user).username)

    def test_state_queries_agree_with_identify_job_state(self):
        # fkie-cad/mcritweb#57: the per-state queries replace a per-document classification in Python; over
        # every combination of the fields that classification reads, each document must be
        # selected by exactly the query of its state
        from itertools import product

        now = datetime.now()
        documents = []
        for started_at, locked_by, finished_at, terminated, attempts_left in product((None, now), (None, "worker"), (None, now), (False, True), (0, 1)):
            document = dict(self.queue._default_insert)
            document.update(
                {
                    "payload": {"method": "test_method", "params": "{}", "descriptor": "d"},
                    "created_at": now,
                    "started_at": started_at,
                    "locked_by": locked_by,
                    "finished_at": finished_at,
                    "terminated": terminated,
                    "attempts_left": attempts_left,
                }
            )
            documents.append(document)
        self.queue._getCollection().insert_many(documents)
        self.assertEqual(32, self.queue.get_job_count())
        # a document no branch claims (e.g. locked but never started) is "unknown" in Python
        # and is selected by no state query either
        unknown = {doc["_id"] for doc in documents if self.queue._identifyJobState(doc) == "unknown"}
        seen = set()
        for state in ("in_progress", "failed", "queued", "finished", "terminated"):
            expected = {doc["_id"] for doc in documents if self.queue._identifyJobState(doc) == state}
            selected = {job.job_id for job in self.queue.get_jobs(0, 0, state=state)}
            self.assertEqual(expected, selected, state)
            self.assertEqual(len(expected), self.queue.get_job_count(state=state), state)
            self.assertTrue(seen.isdisjoint(selected), state)
            seen |= selected
        self.assertEqual(32 - len(unknown), len(seen))
        self.assertTrue(seen.isdisjoint(unknown))

    def test_filter_and_username_select_before_paging(self):
        for i in range(5):
            self.queue.put({"method": "test_method", "params": '{"0": "apple %d"}' % i, "descriptor": "a%d" % i}, username="alice")
            self.queue.put({"method": "other_method", "params": '{"0": "pear %d"}' % i, "descriptor": "p%d" % i}, username="bob")
        self.assertEqual(5, self.queue.get_job_count(filter="Apple"))
        self.assertEqual(5, self.queue.get_job_count(filter="other_"))
        self.assertEqual(5, self.queue.get_job_count(username="bob"))
        self.assertEqual(0, self.queue.get_job_count(filter="apple", username="bob"))
        self.assertEqual(10, self.queue.get_job_count(state="queued"))
        self.assertEqual(["apple 4", "apple 3", "apple 2"], [json.loads(job.payload["params"])["0"] for job in self.queue.get_jobs(0, 3, filter="apple")])
        self.assertEqual(["apple 1", "apple 0"], [json.loads(job.payload["params"])["0"] for job in self.queue.get_jobs(3, 3, filter="apple")])
        self.assertEqual(["apple 0", "apple 1"], [json.loads(job.payload["params"])["0"] for job in self.queue.get_jobs(0, 2, filter="apple", ascending=True)])
        # a regex special character in the filter is literal
        self.assertEqual(0, self.queue.get_job_count(filter="apple.*"))

    def test_context_manager_error(self):
        self.queue.put({"method": "test_method", "context_id": "alpha", "data": [1, 2, 3], "more-data": time.time()})
        job = self.queue.next()
        try:
            with job as data:
                self.assertEqual(data["payload"]["method"], "test_method")
                # Item is returned to the queue on error
                raise SyntaxError
        except SyntaxError:
            pass

        job = self.queue.next()
        self.assertEqual(job.attempts_left, self.queue.max_attempts - 1)

    def test_context_manager_complete(self):
        self.queue.put({"method": "test_method", "context_id": "alpha", "data": [1, 2, 3], "more-data": time.time()})
        job = self.queue.next()
        with job as data:
            self.assertEqual(data["payload"]["method"], "test_method")
        job = self.queue.next()
        self.assertEqual(job, None)


if __name__ == "__main__":
    unittest.main()
