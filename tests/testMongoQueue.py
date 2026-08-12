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

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


@pytest.mark.mongo
class MongoQueueTest(TestCase):
    def setUp(self):
        self.client = pymongo.MongoClient(os.environ.get("TEST_MONGODB"))
        queue_config = QueueConfig()
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
        self.queue.collection.update_one({"_id": job.job_id}, {"$set": {"locked_at": stale_locked_at}})
        self.queue.repair()
        repaired = self.queue.collection.find_one({"_id": job.job_id})
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
        untouched = self.queue.collection.find_one({"_id": job.job_id})
        self.assertEqual(untouched["locked_by"], self.queue.consumer_id)
        self.assertIsNotNone(untouched["locked_at"])
        self.assertEqual(untouched["attempts_left"], self.queue.max_attempts)

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
        self.queue._getCollection()
        index_information = self.queue.collection.index_information()
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
