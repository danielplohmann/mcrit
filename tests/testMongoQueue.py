import logging
import os
import time
from datetime import datetime
from unittest import TestCase

import pymongo

from mcrit.libs.mongoqueue import MongoQueue
from mcrit.config.QueueConfig import QueueConfig

from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


### Added mongo attribute
import pytest


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
        self.assertEqual(job.attempts_left, self.queue.max_attempts-1)

    def test_context_manager_complete(self):
        self.queue.put({"method": "test_method", "context_id": "alpha", "data": [1, 2, 3], "more-data": time.time()})
        job = self.queue.next()
        with job as data:
            self.assertEqual(data["payload"]["method"], "test_method")
        job = self.queue.next()
        self.assertEqual(job, None)


if __name__ == "__main__":
    unittest.main()
