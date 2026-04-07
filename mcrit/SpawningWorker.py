#!/usr/bin/env python3

import logging
import os
import re
import subprocess
import time
import uuid
from typing import TYPE_CHECKING, Optional

from mcrit.config.McritConfig import McritConfig
from mcrit.minhash.MinHasher import MinHasher
from mcrit.queue.QueueFactory import QueueFactory
from mcrit.storage.StorageFactory import StorageFactory
from mcrit.Worker import Worker

if TYPE_CHECKING:
    from mcrit.storage.StorageInterface import StorageInterface

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)


class SpawningWorker(Worker):
    def __init__(self, queue=None, config=None, storage: Optional["StorageInterface"] = None, profiling=False):
        self._worker_id = f"Worker-{uuid.uuid4()}"
        LOGGER.info(f"Starting as spawning worker: {self._worker_id}")
        if config is None:
            config = McritConfig()

        if not queue:
            queue = QueueFactory().getQueue(config, consumer_id=self._worker_id)

        if profiling:
            print("[!] Running as profiled application.")
            profiling_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "profiler"))
            os.makedirs(profiling_path, exist_ok=True)
        else:
            profiling_path = None
        super().__init__(queue=queue, config=config, storage=storage, profiling=profiling)

        self.config = config
        self._storage_config = config.STORAGE_CONFIG
        self._minhash_config = config.MINHASH_CONFIG
        self._shingler_config = config.SHINGLER_CONFIG
        self._queue_config = config.QUEUE_CONFIG
        self.minhasher = MinHasher(config.MINHASH_CONFIG, config.SHINGLER_CONFIG)
        if storage:
            self._storage = storage
        else:
            self._storage = StorageFactory.getStorage(config)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        # TODO unregister our worker_id from all in-progress jobs found in the queue
        self.queue.unregisterWorker()
        self.queue.release_all_jobs()

    #### NO REDIRECTION: SPAWM SINGLE JOB WORKERS INSTEAD ###

    def _executeJobPayload(self, job_payload, job):
        # instead of execution within our own context, spawn a new process as worker for this job payload
        console_handle = subprocess.Popen(["python", "-m", "mcrit", "singlejobworker", "--job_id", str(job.job_id)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # extract result_id from console_output
        result_id = None
        try:
            stdout_result, stderr_result = console_handle.communicate(timeout=self._queue_config.QUEUE_SPAWNINGWORKER_CHILDREN_TIMEOUT)
            stdout_result = stdout_result.strip().decode("utf-8")
            # TODO: log output from subprocess in the order it arrived
            # instead of the split to stdout, stderr
            if stdout_result:
                LOGGER.info("STDOUT logs from subprocess: %s", stdout_result)
            if stderr_result:
                stderr_result = stderr_result.strip().decode("utf-8")
                LOGGER.info("STDERR logs from subprocess: %s", stderr_result)

            last_line = stdout_result.split("\n")[-1]
            # successful output should be just the result_id in a single line
            match = re.match("(?P<result_id>[0-9a-fA-F]{24})", last_line)
            if match:
                result_id = match.group("result_id")
        except subprocess.TimeoutExpired:
            LOGGER.error(f"Job {str(job.job_id)} running as child from SpawningWorker timed out during processing.")
        return result_id

    def _executeJob(self, job):
        if time.time() - self.t_last_cleanup >= self.queue.clean_interval:
            self.queue.clean()
            self.t_last_cleanup = time.time()
        try:
            result_id = None
            with job as j:
                LOGGER.info("Processing Remote Job: %s", job)
                result_id = self._executeJobPayload(j["payload"], job)
                if result_id:
                    # result should have already been persisted by the child process, we repeat it here to close the job for the queue
                    job.result = result_id
                    LOGGER.info("Finished Remote Job with result_id: %s", result_id)
                else:
                    LOGGER.info("Failed Running Remote Job: %s", job)
        except Exception:
            LOGGER.error("Error occurred while executing job: %s", job, exc_info=True)

    def run(self):
        self._alive = True
        while self._alive:
            job = self.queue.next()
            if job:
                LOGGER.debug("Found job")
                self._executeJob(job)
            else:
                time.sleep(0.1)
