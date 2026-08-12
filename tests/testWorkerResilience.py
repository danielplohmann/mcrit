#!/usr/bin/python

import threading
import unittest
from unittest.mock import MagicMock, patch

import pymongo.errors

from mcrit.SpawningWorker import SpawningWorker

from .context import config


class WorkerResilienceTestSuite(unittest.TestCase):
    """#106: a transient database outage must suspend the worker loop, not kill it, and a
    child that dies without producing a result must fail the job instead of completing it."""

    def _makeWorker(self):
        queue = MagicMock()
        queue.clean_interval = 10**9
        worker = SpawningWorker(queue=queue, config=config, storage=MagicMock())
        return worker, queue

    def testRunLoopSurvivesPollingErrors(self):
        worker, queue = self._makeWorker()
        calls = []

        def next_side_effect():
            calls.append(len(calls))
            if len(calls) == 1:
                raise pymongo.errors.ServerSelectionTimeoutError("mongod restarting")
            if len(calls) == 2:
                raise pymongo.errors.NotPrimaryError("interrupted at shutdown")
            worker.terminate()
            return None

        queue.next.side_effect = next_side_effect
        with patch("mcrit.SpawningWorker.time.sleep"):
            run_thread = threading.Thread(target=worker.run)
            run_thread.start()
            run_thread.join(timeout=10)
        self.assertFalse(run_thread.is_alive(), "run loop must terminate cleanly")
        self.assertEqual(len(calls), 3, "polling must continue across transient errors")

    def testDeadChildFailsJobInsteadOfCompleting(self):
        worker, queue = self._makeWorker()
        worker.t_last_cleanup = 10**12  # keep clean() out of this test
        job = MagicMock()
        job.__enter__ = MagicMock(return_value={"payload": {}})
        # capture what exception (if any) reaches the job context manager's __exit__
        exit_types = []
        job.__exit__ = MagicMock(side_effect=lambda t, v, tb: exit_types.append(t))
        with patch.object(SpawningWorker, "_executeJobPayload", return_value=(None, 1)):
            worker._executeJob(job)
        self.assertEqual(len(exit_types), 1)
        self.assertIsNotNone(exit_types[0], "a dead child must route the job through the error path, not complete()")
        self.assertTrue(issubclass(exit_types[0], RuntimeError))

    def testSuccessfulChildStillCompletes(self):
        worker, queue = self._makeWorker()
        worker.t_last_cleanup = 10**12
        job = MagicMock()
        job.__enter__ = MagicMock(return_value={"payload": {}})
        exit_types = []
        job.__exit__ = MagicMock(side_effect=lambda t, v, tb: exit_types.append(t))
        with patch.object(SpawningWorker, "_executeJobPayload", return_value=("aabbccddeeff001122334455", 0)):
            worker._executeJob(job)
        self.assertEqual(exit_types, [None], "a child that produced a result_id must complete the job")


if __name__ == "__main__":
    unittest.main()
