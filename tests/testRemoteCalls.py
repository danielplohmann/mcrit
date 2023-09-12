import logging
import os
import time
from threading import Thread
from unittest import TestCase

import pymongo
from bson.json_util import dumps, loads
from mcrit.config.QueueConfig import QueueConfig
from mcrit.libs.mongoqueue import MongoQueue
from mcrit.queue.LocalQueue import LocalQueue
from mcrit.queue.QueueRemoteCalls import (
    NoProgressReporter,
    QueueRemoteCallee,
    QueueRemoteCaller,
    Remote,
    _createJobPayload,
    get_descriptor,
    upload_file_params,
)
#For test marks
import pytest

from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class myWorker(QueueRemoteCallee):
    @Remote(
        file_locations=[0, 2, 1],
        json_locations=[3, 4],
        kwfile_locations=["eggs"],
        kwjson_locations=["foo"],
    )
    def test(self, *params, **kwparams):
        if "force_recalculation" in kwparams:
            raise AttributeError
        return {"args": dumps(params, sort_keys=True), "kwargs": dumps(kwparams, sort_keys=True)}

    @Remote(progress=True)
    def test_progress(self, progress_reporter=NoProgressReporter()):
        # if not progress_reporter:
        #    progress_reporter = NoProgressReporter()
        l = 100

        # raise Exception("The job received a terminatation message while reporting progress")
        progress_reporter._report_interval = 0

        progress_reporter.set_total(l)
        for i in range(l):
            print(l)
            time.sleep(0.01)
            progress_reporter.step()
        return 0x42

    def function_that_isnt_remote(self, a, b, c):
        pass

    @Remote()
    def child_job(self, i):
        time.sleep(0.2)
        return i*i
    
    @Remote()
    def parent_job(self, child_jobs):
        results = []
        for id in child_jobs:
            results.append(self.getResultForJob(id))
        results = [i for i in results if i is not None]
        return sum(results)

    

# Define Caller Class
class Caller(QueueRemoteCaller(myWorker)):
    def start_child_and_parent_job(self):
        child_job_ids = []
        for i in range(9):
            child_job_ids.append(self.child_job(i, force_recalculation=True))
        # await_jobs param is managed by queue and not passed to function.
        # Maybe call it job_dependencies?
        # parent job will only be executed after all await_jobs were finished, terminated or failed.
        parent_job_id = self.parent_job(child_job_ids, await_jobs=child_job_ids)
        return parent_job_id	



class RemoteCalleeTest(TestCase):
    def setUp(self):
        self.queue = LocalQueue()
        self.worker = myWorker(self.queue)

    def test_progress_local(self):
        self.worker.test_progress()


class LocalQueueRemoteCallTest(TestCase):
    def setUp(self):
        self.queue = LocalQueue()
        self.worker = myWorker(self.queue)
        self.queue.set_worker(self.worker)
        self.caller = Caller(self.queue)
        self.queue.clean_interval = 1e100

    # TODO do a real test here
    @pytest.mark.sleep
    def test_progress(self):
        id = self.caller.test_progress()
        time.sleep(0.2)
        job = self.queue.get_job(id)
        self.assertGreater(job._data["progress"], 0)

    @pytest.mark.sleep
    def test_termination(self):
        id = self.caller.test_progress()
        job = self.queue.get_job(id)
        status_termination = job.terminate()
        print("termination:", status_termination)
        print()
        time.sleep(0.1)
        self.assertTrue(job._is_terminated())

    def test_remote_calls(self):
        params_list = [[], [b"bim", b"bam", b"bum", ["hi", {"ha": "ho"}], {"answer": 42}, {"universe": "exists"}]]
        kwparams_list = [{}, dict(foo={"bar": False}, spam={19: "hi"}, orange=[2, 3, {5: "deep thought"}], eggs=b"bar")]
        for params in params_list:
            for kwparams in kwparams_list:
                job_id = self.caller.test(*params, **kwparams)
                result_id = self.caller.awaitResult(job_id)
                print("RID", result_id, job_id)
                result = self.queue._grid_to_dicts(result_id)
                self.assertEqual(result, self.worker.test(*params, **kwparams))
                self.assertEqual(str(self.queue._grid_to_meta(result_id)["job"]), job_id)
        self.queue.clear()

    @pytest.mark.sleep
    def test_clean_period(self):
        old_cache_time = self.queue.cache_time
        old_clean_interval = self.queue.clean_interval
        self.queue.cache_time = 0.0
        self.queue.clean()
        self.queue.clean_interval = 0.8

        params = []
        kwparams = {"foo": {"test_clean_period": True}}

        time.sleep(self.queue.clean_interval * 1.2)
        job_id_1 = self.caller.test(*params, force_recalculation=True, **kwparams)
        self.caller.awaitResult(job_id_1)

        job_id_2 = self.caller.test(*params, force_recalculation=True, **kwparams)
        self.caller.awaitResult(job_id_2)

        self.assertNotEqual(self.queue.get_job(job_id_1), None)

        time.sleep(self.queue.clean_interval * 1.2)
        job_id_1 = self.caller.test(*params, force_recalculation=True, **kwparams)
        self.caller.awaitResult(job_id_1)

        time.sleep(self.queue.clean_interval * 1.2)

        job_id_2 = self.caller.test(*params, force_recalculation=True, **kwparams)
        self.caller.awaitResult(job_id_2)

        self.assertEqual(self.queue.get_job(job_id_1), None)

        self.queue.cache_time = old_cache_time
        self.queue.clean_interval = old_clean_interval

    def test_multiple_cleans(self):
        params = [b"cde"]
        kwparams = {"test_queue_clean": True, "foo": "abc"}

        # start job 2 times
        job_id = self.caller.test(*params, force_recalculation=True, **kwparams)
        self.caller.awaitResult(job_id)

        job_id_2 = self.caller.test(*params, force_recalculation=True, **kwparams)
        self.caller.awaitResult(job_id_2)

        self.queue.clean()
        self.queue.clean()
        self.queue.clean()

    def test_file_cache(self):
        def get_file_id(job_id):
            payload = self.queue.get_job(job_id).payload
            file_params = loads(payload["file_params"])
            return file_params["foo"]

        params = []
        kwparams = {"foo": {"test_file_cache": True}}
        job_id_1 = self.caller.test(*params, force_recalculation=False, **kwparams)
        job_id_2 = self.caller.test(*params, force_recalculation=True, **kwparams)

        file_1 = get_file_id(job_id_1)
        file_2 = get_file_id(job_id_2)

        self.assertEqual(file_1, file_2)

    def test_job_cache(self):
        params_list = [[], [b"bim", b"bam", b"bum", ["hi", {"ha": "ho"}], {"answer": 42}, {"universe": "exists"}]]
        kwparams_list = [{}, dict(foo={"bar": False}, spam={19: "hi"}, orange=[2, 3, {5: "deep mind"}], eggs=b"bar")]
        for params in params_list:
            for kwparams in kwparams_list:
                job_id_1 = self.caller.test(*params, **kwparams)
                job_id_2 = self.caller.test(*params, **kwparams)
                self.assertEqual(job_id_1, job_id_2)
        self.queue.clear()
        for params in params_list:
            for kwparams in kwparams_list:
                job_id_1 = self.caller.test(*params, **kwparams)
                job_id_2 = self.caller.test(*params, force_recalculation=True, **kwparams)
                self.assertNotEqual(job_id_1, job_id_2)
        self.queue.clear()

    def test_function_access(self):
        params = {0: 1, 1: 2, 2: 3}
        payload1 = _createJobPayload(
            "function_that_isnt_remote", params, {}, get_descriptor("function_that_isnt_remote", params, {})
        )
        payload2 = _createJobPayload(
            "function_that_doesnt_exist", params, {}, get_descriptor("function_that_doesnt_exist", params, {})
        )
        job_id = self.queue.put(payload1)
        # self.caller.awaitResult(job_id)
        error_message = self.caller.getJob(job_id).last_error
        # self.assertTrue("NotImplementedError" in error_message)
        # with self.assertRaises(AttributeError):
        #    self.queue.put(payload2)

        # This is also done for mongo
        with self.assertRaises(AttributeError):
            self.caller.function_that_isnt_remote(1, 2, 3)
        with self.assertRaises(AttributeError):
            self.caller.function_that_doesnt_exist(1, 2, 3)

    def test_file_access(self):
        params = []
        kwparams = {"foo": {"test_file_access": True}}
        job_id = self.caller.test(*params, force_recalculation=False, **kwparams)
        payload = self.queue.get_job(job_id).payload
        file_params = loads(payload["file_params"])
        file = file_params["foo"]
        result = self.queue._grid_to_dicts(file)
        self.assertEqual("Access Not Allowed", result)

    def test_file_job_ref(self):
        params = []
        kwparams = {"foo": {"test_file_job_ref": True}}
        job_ids = []
        for i in range(5):
            kwparams["tested_job"] = i
            job_id = self.caller.test(*params, force_recalculation=False, **kwparams)
            job_ids.append(job_id)
            payload = self.queue.get_job(job_id).payload
            file_params = loads(payload["file_params"])
            file = file_params["foo"]
            meta = self.queue._grid_to_meta(file)
            print(meta)
            self.assertEqual(job_ids, meta["jobs"])
            self.assertEqual(0, meta["tmp_lock"])

    def test_file_tmp_lock(self):
        params = []
        kwparams = {"foo": {"test_tmp_lock": True}}
        job_id = self.caller.test(*params, force_recalculation=False, **kwparams)
        payload = self.queue.get_job(job_id).payload
        file_params = loads(payload["file_params"])
        hashes = loads(payload["descriptor"])[2]
        upload_file_params(self.caller, file_params, hashes)
        # lock should be 1 now
        file = file_params["foo"]
        meta = self.queue._grid_to_meta(file)
        self.assertEqual(1, meta["tmp_lock"])

    @pytest.mark.sleep
    def test_queue_clean(self):
        self.queue.cache_time = 0.1
        self.queue.clean_interval = 1e100

        params = [b"cde"]
        kwparams = {"test_queue_clean": True, "foo": "abc"}

        # start job 2 times
        job_id = self.caller.test(*params, force_recalculation=True, **kwparams)
        result_id = self.caller.awaitResult(job_id)

        job_id_2 = self.caller.test(*params, force_recalculation=True, **kwparams)
        result_id_2 = self.caller.awaitResult(job_id_2)

        # extract file ids
        files = loads(self.queue.get_job(job_id).payload["file_params"])

        # start job again but with changed params
        time.sleep(self.queue.cache_time)
        params = []
        job_id_3 = self.caller.test(*params, force_recalculation=True, **kwparams)
        result_id_3 = self.caller.awaitResult(job_id_3)

        # clean. This should impact job 1 and 2, but not 3.
        # we expect parameter 0 to be deleted, but not foo
        self.queue.clean()

        # Check jobs
        self.assertEqual(self.queue.get_job(job_id), None)
        self.assertEqual(self.queue.get_job(job_id_2), None)
        self.assertNotEqual(self.queue.get_job(job_id_3), None)

        # check results
        self.assertEqual(self.queue._grid_to_file(result_id), None)
        self.assertEqual(self.queue._grid_to_file(result_id_2), None)
        self.assertNotEqual(self.queue._grid_to_file(result_id_3), None)

        # Check params
        self.assertNotEqual(self.queue._grid_to_file(files["foo"], results_only=False), None)
        self.assertEqual(self.queue._grid_to_file(files["0"], results_only=False), None)

        # Check foo, if jobs were cleaned:
        self.assertEqual(self.queue._grid_to_meta(files["foo"])["jobs"], [job_id_3])

    def test_job_dependencies(self):
        self.queue.clear()
        additional_worker = myWorker(self.queue)
        additional_worker_thread = Thread(target=additional_worker.run)
        additional_worker_thread.start()

        job_id = self.caller.start_child_and_parent_job()
        result_id = self.caller.awaitResult(job_id)
        result = self.caller.getResult(result_id)
        job = self.caller.getJob(job_id)
        self.assertEqual(result, sum([i*i for i in range(9)]))
        
        additional_worker.terminate()
        self.queue.clear()


### Added mongo attribute
@pytest.mark.mongo
class MongoQueueRemoteCallTest(LocalQueueRemoteCallTest):
    def setUp(self):
        self.client = pymongo.MongoClient(os.environ.get("TEST_MONGODB"))
        queue_config = QueueConfig()
        queue_config.QUEUE_MONGODB_DBNAME = "test_queue_remote_calls"
        queue_config.QUEUE_MONGODB_COLLECTION_NAME = "queue_1"
        self.queue = MongoQueue(queue_config, "consumer_1")
        self.caller = Caller(self.queue)
        self.queue.clean_interval = 1e100
        self.worker = myWorker(self.queue)
        self.worker_thread = Thread(target=self.worker.run)
        self.worker_thread.start()

    @pytest.mark.sleep
    def test_termination(self):
        id = self.caller.test_progress()
        job = self.queue.get_job(id)
        time.sleep(0.1)
        status_termination = job.terminate()
        print("termination:", status_termination)
        print()
        time.sleep(0.5)
        self.assertTrue(job._is_terminated())
        job = self.queue.get_job(id)
        print(job._data)
        self.assertTrue("The job received a terminatation message while reporting progress" in job.last_error)
        result_id = self.caller.awaitResult(id)
        self.assertEqual(result_id, None)

    def test_job_cache_prio(self):
        params = []
        kwparams = {"test_cache_prio": True}

        job_id = self.caller.test(*params, **kwparams)
        self.caller.awaitResult(job_id)

        job_id_2 = self.caller.test(*params, force_recalculation=True, **kwparams)
        self.caller.awaitResult(job_id_2)

        job_id_3 = self.caller.test(*params, force_recalculation=False, **kwparams)
        self.assertEqual(job_id_2, job_id_3)

        self.worker.terminate()
        self.worker_thread.join()
        job_id_4 = self.caller.test(*params, force_recalculation=True, **kwparams)
        job_id_5 = self.caller.test(*params, force_recalculation=False, **kwparams)
        print(self.queue.get_job(job_id_4)._data)
        print(self.queue.get_job(job_id_2)._data)
        self.assertNotEqual(job_id_2, job_id_5)
        self.assertEqual(job_id_4, job_id_5)

        self.worker_thread = Thread(target=self.worker.run)
        self.worker_thread.start()

    def test_function_access(self):
        with self.assertRaises(AttributeError):
            self.caller.function_that_isnt_remote(1, 2, 3)
        with self.assertRaises(AttributeError):
            self.caller.function_that_doesnt_exist(1, 2, 3)

    def tearDown(self):
        self.worker.terminate()
        self.worker_thread.join()
        self.client.drop_database("test_queue_remote_calls")


if __name__ == "__main__":
    unittest.main()
