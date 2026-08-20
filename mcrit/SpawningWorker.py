#!/usr/bin/env python3

import logging
import os
import re
import subprocess
import threading
import time
import uuid
from typing import TYPE_CHECKING, Optional

import pymongo.errors

from mcrit.config.McritConfig import McritConfig
from mcrit.minhash.MinHasher import MinHasher
from mcrit.queue.QueueFactory import QueueFactory
from mcrit.storage.StorageFactory import StorageFactory
from mcrit.Worker import Worker

if TYPE_CHECKING:
    from mcrit.storage.StorageInterface import StorageInterface

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

# Grace period for the stdout/stderr reader threads to drain their pipes after the child has
# exited. They see EOF as soon as the last writer closes, so this only expires if something
# still holds the inherited descriptors (e.g. a surviving grandchild of the job process) - in
# which case the worker must give up on the output rather than block its poll loop forever.
OUTPUT_READER_JOIN_TIMEOUT = 30


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
        try:
            self.queue.unregisterWorker()
            self.queue.release_all_jobs()
        except pymongo.errors.PyMongoError:
            # best-effort teardown: if the database is unreachable while we exit, orphaned
            # locks are reclaimed later by release_orphaned_jobs/clean rather than turning
            # the shutdown itself into a crash
            LOGGER.error("Could not release jobs on shutdown, queue cleanup will reclaim them.", exc_info=True)

    #### NO REDIRECTION: SPAWM SINGLE JOB WORKERS INSTEAD ###

    def _executeJobPayload(self, job_payload, job):
        # instead of execution within our own context, spawn a new process as worker for this job payload
        console_handle = subprocess.Popen(["python", "-m", "mcrit", "singlejobworker", "--job_id", str(job.job_id)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # extract result_id from console_output
        result_id = None
        stdout_lines = []

        def reader(pipe, label, accum):
            try:
                for line in iter(pipe.readline, b""):
                    decoded_line = line.decode("utf-8", errors="replace").rstrip()
                    if decoded_line:
                        LOGGER.info("%s logs from subprocess: %s", label, decoded_line)
                    if accum is not None:
                        accum.append(decoded_line)
            except Exception:
                LOGGER.exception("Exception in subprocess reader thread")
            finally:
                pipe.close()

        t1 = threading.Thread(target=reader, args=(console_handle.stdout, "STDOUT", stdout_lines))
        t2 = threading.Thread(target=reader, args=(console_handle.stderr, "STDERR", None))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()

        try:
            # the reader threads own the pipes; communicate() would race them for the same
            # file descriptors (observed as OSError EBADF when a child dies mid-read), so
            # only wait for the exit code here and let the readers drain the output
            console_handle.wait(timeout=self._queue_config.QUEUE_SPAWNINGWORKER_CHILDREN_TIMEOUT)
        except subprocess.TimeoutExpired:
            LOGGER.error(f"Job {str(job.job_id)} running as child from SpawningWorker timed out during processing.")
            console_handle.kill()
            console_handle.wait()

        t1.join(timeout=OUTPUT_READER_JOIN_TIMEOUT)
        t2.join(timeout=OUTPUT_READER_JOIN_TIMEOUT)
        if t1.is_alive() or t2.is_alive():
            # proceeding with a possibly truncated stdout can cost us the result_id, which routes
            # the job through the error path and retries it - the right trade against hanging here
            LOGGER.error(
                "Output readers for job %s did not finish within %d s after the child exited; continuing with the output collected so far.",
                str(job.job_id),
                OUTPUT_READER_JOIN_TIMEOUT,
            )

        if stdout_lines:
            # Search backwards for result_id in case there are trailing empty lines or other output
            for line in reversed(stdout_lines):
                if line.strip():
                    match = re.match("(?P<result_id>[0-9a-fA-F]{24})", line.strip())
                    if match:
                        result_id = match.group("result_id")
                        break
        return result_id, console_handle.returncode

    def _executeJob(self, job):
        if time.time() - self.t_last_cleanup >= self.queue.clean_interval:
            try:
                self.queue.clean()
            except pymongo.errors.PyMongoError:
                # periodic housekeeping must not take the worker down with it; the next
                # interval retries once the database is reachable again
                LOGGER.error("Queue cleanup failed, deferring to next interval.", exc_info=True)
            self.t_last_cleanup = time.time()
        try:
            result_id = None
            with job as j:
                LOGGER.info("Processing Remote Job: %s", job)
                result_id, child_returncode = self._executeJobPayload(j["payload"], job)
                if result_id:
                    # result should have already been persisted by the child process, we repeat it here to close the job for the queue
                    job.result = result_id
                    LOGGER.info("Finished Remote Job with result_id: %s", result_id)
                else:
                    # raising routes the job through Job.__exit__'s error path, which returns
                    # it to the queue with attempts_left decremented - falling through would
                    # have __exit__ complete() it, reporting a dead child as a finished job
                    raise RuntimeError(f"child worker exited (returncode {child_returncode}) without producing a result_id")
        except Exception:
            # the failure may include the Job.__exit__ error() write itself (e.g. the
            # database went away mid-job), in which case the job is still locked by us
            # with its release lost - reconcile before the next claim
            self._needs_lock_reconcile = True
            LOGGER.error("Error occurred while executing job: %s", job, exc_info=True)

    def run(self):
        self._alive = True
        self._needs_lock_reconcile = False
        backoff_seconds = 1
        while self._alive:
            try:
                if self._needs_lock_reconcile:
                    # a previous failure may have left a job locked by this consumer with
                    # its error() release lost; nothing else reclaims a live worker's locks
                    # (orphan release only covers unregistered consumers), so release our
                    # own before claiming anew. Runs BEFORE next() so it can never release
                    # a job we just claimed. No-op when the release already landed.
                    self.queue.release_all_jobs()
                    self._needs_lock_reconcile = False
                job = self.queue.next()
                if job:
                    LOGGER.debug("Found job")
                    self._executeJob(job)
                else:
                    time.sleep(0.1)
                backoff_seconds = 1
            except pymongo.errors.PyMongoError:
                # a transient database outage (e.g. mongod restart during maintenance) must
                # suspend the worker, not kill it: pymongo re-establishes the connection on
                # its own once the server is back, so keep polling with a capped backoff
                LOGGER.error("Queue polling failed, retrying in %d s.", backoff_seconds, exc_info=True)
                time.sleep(backoff_seconds)
                backoff_seconds = min(backoff_seconds * 2, 30)
