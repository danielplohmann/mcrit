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

    def test_cached_job_prefers_finished_over_running(self):
        # fkie-cad/mcritweb#47: a force rematch that is still running must not shadow the finished job whose
        # result is what a repeated request can actually use
        payload = {"method": "test_method", "descriptor": "same-request"}
        finished_id = self.queue.put(dict(payload))
        self.queue.next().complete("result-1")
        running_id = self.queue.put(dict(payload))
        self.queue.next()  # locked by the consumer, in progress
        self.assertEqual(finished_id, self.queue.get_cached_job_id(payload))
        # once the newer job is finished as well, the newest finished result wins
        self.queue.get_job(running_id).complete("result-2")
        self.assertEqual(running_id, self.queue.get_cached_job_id(payload))

    def test_cached_job_ignores_failed_and_terminated(self):
        payload = {"method": "test_method", "descriptor": "same-request"}
        self.queue.max_attempts = 1
        self.queue._default_insert["attempts_left"] = 1
        failed_id = self.queue.put(dict(payload))
        self.queue.next().error("boom")
        self.assertEqual(0, self.queue.get_job(failed_id).attempts_left)
        self.assertIsNone(self.queue.get_cached_job_id(payload))
        terminated_id = self.queue.put(dict(payload))
        self.queue.next().terminate()
        self.assertTrue(self.queue.get_job(terminated_id)._is_terminated())
        self.assertIsNone(self.queue.get_cached_job_id(payload))
        queued_id = self.queue.put(dict(payload))
        self.assertEqual(queued_id, self.queue.get_cached_job_id(payload))

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


@pytest.mark.mongo
class WorkerLivenessTest(TestCase):
    """Jobs held by a worker that died without unwinding are reclaimed, and never served
    as a cached result to an identical resubmission (#150)."""

    def setUp(self):
        self.client = pymongo.MongoClient(os.environ.get("TEST_MONGODB"))
        self.queue_config = QueueConfig()
        self.queue_config.QUEUE_SERVER, self.queue_config.QUEUE_PORT = getTestMongoServerAndPort()
        self.queue_config.QUEUE_MONGODB_DBNAME = "test_queue"
        self.queue_config.QUEUE_MONGODB_COLLECTION_NAME = "queue_liveness"
        self.timeout = 5
        self.worker_a = self._worker("Worker-a")
        self.worker_b = self._worker("Worker-b")
        self.server = self._worker("index")

    def tearDown(self):
        for queue in (self.worker_a, self.worker_b, self.server):
            queue._stopHeartbeatThread()
        self.client.drop_database("test_queue")

    def _worker(self, consumer_id):
        return MongoQueue(self.queue_config, consumer_id, timeout=self.timeout)

    def _registration(self):
        return self.worker_a._getQueueCounters().find_one({"name": "workers"}, {"_id": 0}) or {}

    def _document(self, job_id):
        document = self.worker_a._getCollection().find_one({"_id": job_id})
        assert document is not None
        return document

    def _age_heartbeat(self, consumer_id, seconds):
        self.worker_a._getQueueCounters().update_one({"name": "workers"}, {"$set": {f"heartbeats.{consumer_id}": datetime.now() - timedelta(seconds=seconds)}})

    def _claimed_by(self, queue, descriptor="d"):
        queue.put({"method": "test_method", "descriptor": descriptor})
        job = queue.next()
        assert job is not None
        return job

    def test_registering_records_a_heartbeat_and_unregistering_removes_it(self):
        self.worker_a._getCollection()
        registration = self._registration()
        self.assertIn("Worker-a", registration["workers"])
        self.assertIsInstance(registration["heartbeats"]["Worker-a"], datetime)
        self.server._getCollection()
        self.assertNotIn("index", self._registration()["workers"])
        self.worker_a.unregisterWorker()
        registration = self._registration()
        self.assertNotIn("Worker-a", registration["workers"])
        self.assertNotIn("Worker-a", registration.get("heartbeats", {}))

    def test_a_worker_is_live_only_with_a_fresh_heartbeat(self):
        self.worker_a._getCollection()
        self.worker_b._getCollection()
        self.assertEqual({"Worker-a", "Worker-b"}, self.server._live_worker_ids())
        self._age_heartbeat("Worker-b", self.timeout + 1)
        self.assertEqual({"Worker-a"}, self.server._live_worker_ids())
        # a registration without any heartbeat is a process from before heartbeats existed
        # (a rolling upgrade): it is stamped now and gets one timeout of grace before it is
        # judged like everybody else
        self.worker_a._getQueueCounters().update_one({"name": "workers"}, {"$unset": {"heartbeats.Worker-a": ""}})
        self.worker_a._stopHeartbeatThread()
        self.assertEqual({"Worker-a"}, self.server._live_worker_ids())
        self.assertIsInstance(self._registration()["heartbeats"]["Worker-a"], datetime)
        self.assertEqual({"Worker-a"}, self.server._live_worker_ids(now=datetime.now() + timedelta(seconds=self.timeout - 1)))
        self.assertEqual(set(), self.server._live_worker_ids(now=datetime.now() + timedelta(seconds=self.timeout + 1)))

    def test_the_heartbeat_keeps_going_while_a_job_runs(self):
        """jobs run synchronously in the poll loop, so a job longer than the timeout would look
        like a dead worker without the heartbeat thread"""
        self.worker_a._getCollection()
        self.assertTrue(self.worker_a._heartbeat_thread is not None and self.worker_a._heartbeat_thread.is_alive())
        self._age_heartbeat("Worker-a", self.timeout + 1)
        self.assertEqual(set(), self.server._live_worker_ids())
        # no poll happens here - the thread alone brings the heartbeat back within one interval
        time.sleep(self.worker_a.heartbeat_interval + 1)
        self.assertEqual({"Worker-a"}, self.server._live_worker_ids())
        # a worker judged dead by mistake was unregistered by the reclaim; its next heartbeat
        # registers it again, so it keeps serving jobs
        self.server.release_orphaned_jobs()
        self._age_heartbeat("Worker-a", self.timeout + 1)
        self.server.release_orphaned_jobs()
        self.assertNotIn("Worker-a", self._registration().get("workers", []))
        time.sleep(self.worker_a.heartbeat_interval + 1)
        self.assertIn("Worker-a", self._registration()["workers"])
        self.assertEqual({"Worker-a"}, self.server._live_worker_ids())
        self.worker_a.unregisterWorker()
        self.assertIsNone(self.worker_a._heartbeat_thread)

    def test_a_dead_workers_job_is_reclaimed_and_a_live_ones_is_kept(self):
        dead_job = self._claimed_by(self.worker_a, "dead")
        live_job = self._claimed_by(self.worker_b, "live")
        self._age_heartbeat("Worker-a", self.timeout + 1)  # Worker-a was SIGKILLed: still registered, no heartbeat
        self.server.release_orphaned_jobs()
        reclaimed = self._document(dead_job.job_id)
        self.assertIsNone(reclaimed["locked_by"])
        self.assertIsNone(reclaimed["locked_at"])
        self.assertEqual(self.worker_a.max_attempts - 1, reclaimed["attempts_left"])
        kept = self._document(live_job.job_id)
        self.assertEqual("Worker-b", kept["locked_by"])
        self.assertEqual(self.worker_b.max_attempts, kept["attempts_left"])
        # the dead registration is gone, the live one stays
        registration = self._registration()
        self.assertEqual(["Worker-b"], registration["workers"])
        self.assertEqual(["Worker-b"], list(registration["heartbeats"]))
        # and another worker picks the reclaimed job up
        self.assertEqual(dead_job.job_id, self.worker_b.next().job_id)

    def test_a_job_never_registered_for_is_reclaimed_too(self):
        job = self._claimed_by(self.worker_a)
        self.worker_a.unregisterWorker()
        self.server.release_orphaned_jobs()
        self.assertIsNone(self._document(job.job_id)["locked_by"])

    def test_reclaiming_the_last_attempt_fails_the_job_and_frees_its_dependents(self):
        job = self._claimed_by(self.worker_a, "last")
        self.worker_a._getCollection().update_one({"_id": job.job_id}, {"$set": {"attempts_left": 1}})
        self.worker_b.put({"method": "test_method", "descriptor": "waiting"}, await_jobs=[str(job.job_id)])
        self._age_heartbeat("Worker-a", self.timeout + 1)
        self.server.release_orphaned_jobs()
        failed = self._document(job.job_id)
        self.assertEqual(0, failed["attempts_left"])
        self.assertIsNone(failed["locked_by"])
        waiting = self.worker_b.next()
        assert waiting is not None
        self.assertEqual("waiting", waiting.payload["descriptor"])
        counters = {c["name"]: c for c in self.worker_a._getQueueCounters().find({"name": "test_method"})}
        self.assertEqual(1, counters["test_method"]["failed"])

    def test_a_stranded_job_is_not_served_as_a_cached_result(self):
        job = self._claimed_by(self.worker_a, "shared")
        payload = {"descriptor": "shared"}
        # in flight on a live worker: served
        self.assertEqual(job.job_id, self.server.get_cached_job_id(payload))
        self._age_heartbeat("Worker-a", self.timeout + 1)
        # the same job, its worker dead: not served
        self.assertIsNone(self.server.get_cached_job_id(payload))
        # once reclaimed it waits in the queue, and a waiting job is served again
        self.server.release_orphaned_jobs()
        self.assertEqual(job.job_id, self.server.get_cached_job_id(payload))
        # a finished job is served whatever its worker's state
        self.worker_b.next().complete()
        self.worker_b._getQueueCounters().update_one({"name": "workers"}, {"$set": {"heartbeats.Worker-b": datetime.now() - timedelta(seconds=self.timeout + 1)}})
        self.assertEqual(job.job_id, self.server.get_cached_job_id(payload))

    def test_polling_refreshes_the_heartbeat_and_reclaims_periodically(self):
        stranded = self._claimed_by(self.worker_a)
        self.worker_b._getCollection()  # registering reclaims too, so Worker-a dies only afterwards
        self._age_heartbeat("Worker-a", self.timeout + 1)
        before = self._registration()["heartbeats"]["Worker-b"]
        # polling right after registering is inside the heartbeat interval: no write
        self.worker_b._last_reclaim = time.monotonic()
        self.assertIsNone(self.worker_b.next())
        self.assertEqual(before, self._registration()["heartbeats"]["Worker-b"])
        self.assertEqual("Worker-a", self._document(stranded.job_id)["locked_by"])
        # past the interval it heartbeats, and past the timeout it reclaims: the stranded
        # job is released and claimed in the same poll
        self.worker_b._last_heartbeat = 0.0
        self.worker_b._last_reclaim = 0.0
        claimed = self.worker_b.next()
        assert claimed is not None
        self.assertEqual(stranded.job_id, claimed.job_id)
        self.assertGreater(self._registration()["heartbeats"]["Worker-b"], before)


if __name__ == "__main__":
    unittest.main()
