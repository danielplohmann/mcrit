#!/usr/bin/env python3

import os
import re
import uuid
import json
import time
import logging
import hashlib
from random import sample
from datetime import datetime, timedelta
from collections import defaultdict
from itertools import zip_longest
from multiprocessing import Pool, cpu_count
from typing import Dict, List, Optional, TYPE_CHECKING, Tuple

import tqdm
from smda.common.BinaryInfo import BinaryInfo
from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.common.SmdaInstruction import SmdaInstruction
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

from mcrit.Worker import Worker
from mcrit.config.McritConfig import McritConfig
from mcrit.config.MinHashConfig import MinHashConfig
from mcrit.config.ShinglerConfig import ShinglerConfig
from mcrit.config.QueueConfig import QueueConfig
from mcrit.config.McritConfig import McritConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.matchers.MatcherCross import MatcherCross
from mcrit.matchers.MatcherQuery import MatcherQuery
from mcrit.matchers.MatcherSample import MatcherSample
from mcrit.matchers.MatcherVs import MatcherVs
from mcrit.minhash.MinHasher import MinHasher
from mcrit.queue.LocalQueue import Job
from mcrit.queue.QueueFactory import QueueFactory
from mcrit.queue.QueueRemoteCalls import NoProgressReporter, QueueRemoteCallee, Remote, JobProgressReporter
from mcrit.storage.SampleEntry import SampleEntry
from mcrit.storage.StorageFactory import StorageFactory

if TYPE_CHECKING:
    from mcrit.storage.StorageInterface import StorageInterface

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)


class SingleJobWorker(Worker):
    def __init__(self, job_id, queue=None, config=None, storage: Optional["StorageInterface"] = None, profiling=False):
        self.job_id = job_id
        self._worker_id = f"Worker-{uuid.uuid4()}"
        LOGGER.info(f"Starting as worker: {self._worker_id}")
        if config is None:
            config = McritConfig()

        if not queue:
            queue = QueueFactory().getQueue(config, consumer_id=self._worker_id)

        if profiling:
            print("[!] Running as profiled application.")
            profiling_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__ )), "..", "profiler"))
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

    def  __enter__(self):
        return self

    def  __exit__(self, *args):
        # TODO unregister our worker_id from all in-progress jobs found in the queue
        self.queue.unregisterWorker()
        self.queue.release_all_jobs()

    #### Overwrite inherited methods to achive execution of a single job ####
        
    def _executeJobPayload(self, job_payload, job):
        LOGGER.debug("DECODE JOB: %s", job_payload)
        method, params, kwparams = self._decodeJobPayload(job_payload)
        # Add progress reporter if necessary:
        if method.progressor:
            LOGGER.debug("kwparams: %s", kwparams)
            kwparams["progress_reporter"] = JobProgressReporter(job, 0.1)
        LOGGER.debug("EXECUTE JOB: %s", job_payload)
        result = method(*params, **kwparams)
        LOGGER.debug("FINISHED JOB: %s", job_payload)
        return result

    def _executeJob(self, job):
        try:
            with job as j:
                LOGGER.info("Processing Remote Job: %s", job)
                result = self._executeJobPayload(j["payload"], job)
                LOGGER.debug("Remote Job Result: %s", result)
                # ensure we always have a job_id for finished job payloads
                result_id = self.queue._dicts_to_grid(result, metadata={"result": True, "job": job.job_id})
                print(str(result_id))
                job.result = result_id
                LOGGER.info("Finished Remote Job producing result_id: %s", result_id)
        except Exception as exc:
            pass

    def run(self):
        self._alive = True
        job = self.queue.get_job(self.job_id)
        LOGGER.debug("Found job")
        self._executeJob(job)

    def terminate(self):
        self._alive = False
