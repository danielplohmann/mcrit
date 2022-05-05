#!/usr/bin/env python3

import uuid
import json
import logging
import hashlib
from random import sample
from collections import defaultdict
from multiprocessing import Pool, cpu_count
from typing import Dict, List, Optional, TYPE_CHECKING, Tuple

import tqdm
from smda.common.BinaryInfo import BinaryInfo
from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

from mcrit.config.McritConfig import McritConfig
from mcrit.config.MinHashConfig import MinHashConfig
from mcrit.config.ShinglerConfig import ShinglerConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.matchers.MatcherQuery import MatcherQuery
from mcrit.matchers.MatcherSample import MatcherSample
from mcrit.matchers.MatcherVs import MatcherVs
from mcrit.minhash.MinHasher import MinHasher
from mcrit.queue.QueueFactory import QueueFactory
from mcrit.queue.QueueRemoteCalls import NoProgressReporter, QueueRemoteCallee, Remote
from mcrit.storage.SampleEntry import SampleEntry
from mcrit.storage.StorageFactory import StorageFactory

if TYPE_CHECKING:
    from mcrit.storage.StorageInterface import StorageInterface

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)


class Worker(QueueRemoteCallee):
    def __init__(self, queue=None, config=None, storage: Optional["StorageInterface"] = None):
        if config is None:
            config = McritConfig()

        if not queue:
            queue = QueueFactory().getQueue(config, consumer_id="Worker-" + str(uuid.uuid4()))
        super().__init__(queue)

        self.config = config
        self._storage_config = config.STORAGE_CONFIG
        self._minhash_config = config.MINHASH_CONFIG
        self._shingler_config = config.SHINGLER_CONFIG
        self.minhasher = MinHasher(config.MINHASH_CONFIG, config.SHINGLER_CONFIG)
        if storage:
            self._storage = storage
        else:
            self._storage = StorageFactory.getStorage(config.STORAGE_CONFIG)

    #### STORAGE IO ####
    def getStorage(self):
        """Get an interface to the storage"""
        return self._storage

    def getStorageData(self):
        """Warning: This is intended for local debugging runs - storage may become huge"""
        results = {
            "config": {
                "minhash_config": self._minhash_config.toDict(),
                "shingler_config": self._shingler_config.toDict(),
                "storage_config": self._storage_config.toDict(),
            },
            "stats": self._storage.getStats(),
            "storage": self._storage.getContent(),
        }
        return results

    def setStorageData(self, storage_data):
        self._minhash_config = MinHashConfig.fromDict(storage_data["config"]["minhash_config"])
        self._shingler_config = ShinglerConfig.fromDict(storage_data["config"]["shingler_config"])
        self._storage_config = StorageConfig.fromDict(storage_data["config"]["storage_config"])
        # reinitialize
        self.minhasher = MinHasher(self._minhash_config, self._shingler_config)
        self._storage = StorageFactory.getStorage(self._storage_config)
        self._storage.setContent(storage_data["storage"])

    #### REDIRECTED FROM INDEX: MAIN WORKER FUNKTIONALITY ###

    def _addReport(self, smda_report, calculate_hashes=True, calculate_matches=False) -> "SampleEntry":
        sample_entry = self._storage.getSampleBySha256(smda_report.sha256)
        if sample_entry:
            LOGGER.info("Sample is already present in database: %s", sample_entry)
            return sample_entry
        sample_entry = self._storage.addSmdaReport(smda_report)
        if not sample_entry:
            return None
        LOGGER.info("Added %s", sample_entry)
        function_entries = self._storage.getFunctionsBySampleId(sample_entry.sample_id)
        LOGGER.info("Added %d function entries.", len(function_entries))
        job_id = None
        if calculate_hashes:
            self.updateMinHashesForSample(sample_entry.sample_id)
        return sample_entry

    # Reports PROGRESS
    @Remote(progress=True, file_locations=[0])
    def addBinarySample(self, binary, filename, family, version, is_dump, base_address, bitness, progress_reporter=NoProgressReporter()):
        binary_sha256 = hashlib.sha256(binary).hexdigest()
        sample_entry = self._storage.getSampleBySha256(binary_sha256)
        if sample_entry:
            LOGGER.info("Sample is already known with ID: %d", sample_entry.sample_id)
            return {"sample_info": sample_entry.toDict()}
        config = SmdaConfig()
        SMDA_REPORT = None
        DISASSEMBLER = Disassembler(config)
        LOGGER.info("Disassembling...")
        if is_dump:
            SMDA_REPORT = DISASSEMBLER.disassembleBuffer(binary, base_addr=base_address, bitness=bitness)
        else:
            SMDA_REPORT = DISASSEMBLER.disassembleUnmappedBuffer(binary)
        if filename is not None:
            SMDA_REPORT.filename = filename
        if family is not None:
            SMDA_REPORT.family = family
        if version is not None:
            SMDA_REPORT.version = version
        sample_entry = self._addReport(SMDA_REPORT)
        LOGGER.info("Disassembled and indexed sample: %s", sample_entry)
        if sample_entry is not None:
            return {"sample_info": sample_entry.toDict()}
        else:
            return None

    # Reports PROGRESS
    @Remote(progress=True)
    def updateMinHashes(self, function_ids, progress_reporter=NoProgressReporter()):
        """Find unhashed functions in storage and calculate their MinHashes, optionally filter by function_ids or get function_entries passed directly"""
        unhashed_functions = self._storage.getUnhashedFunctions(function_ids)
        LOGGER.info("Updating MinHashes: %d function entries (from %d functions) have no MinHash yet.", len(unhashed_functions), len(function_ids))
        minhashes = self.calculateMinHashes(unhashed_functions, progress_reporter=progress_reporter)
        if minhashes:
            self._storage.addMinHashes(minhashes)
            LOGGER.info("Updated minhashes for %d function entries.", len(minhashes))
        # TODO if we do deferred calculation for a batch of minhashes, we might have to clear them here or address this where else updateMinHashes is used
        return len(minhashes)

    # Reports PROGRESS
    @Remote(progress=True)
    def updateMinHashesForSample(self, sample_id, progress_reporter=NoProgressReporter()):
        """Find unhashed functions in storage and calculate their MinHashes, optionally filter by function_ids or get function_entries passed directly"""
        function_entries = self._storage.getFunctionsBySampleId(sample_id)
        if function_entries:
            update_result = self.updateMinHashes([fe.function_id for fe in function_entries], progress_reporter=progress_reporter)
        else:
            LOGGER.info("Sample %d did not have any functions, proceeding.", sample_id)
            return 0
        self._storage.deleteXcfgForSampleId(sample_id)
        return update_result

    # Reports PROGRESS
    @Remote(progress=True, json_locations=[0])
    def getMatchesForSmdaReport(
        self, report_json, minhash_threshold=None, pichash_size=None, progress_reporter=NoProgressReporter()
    ):
        matcher = MatcherQuery(
            self, minhash_threshold=minhash_threshold, pichash_size=pichash_size, progress_reporter=progress_reporter
        )
        smda_report = SmdaReport.fromDict(report_json)
        match_report = matcher.getMatchesForSmdaReport(smda_report)
        return match_report

    # Reports PROGRESS
    @Remote(progress=True, file_locations=[0])
    def getMatchesForMappedBinary(
        self, binary, base_address, minhash_threshold=None, pichash_size=None, progress_reporter=NoProgressReporter()
    ):
        config = SmdaConfig()
        SMDA_REPORT = None
        DISASSEMBLER = Disassembler(config)
        SMDA_REPORT = DISASSEMBLER.disassembleBuffer(binary, base_address)
        matcher = MatcherQuery(
            self, minhash_threshold=minhash_threshold, pichash_size=pichash_size, progress_reporter=progress_reporter
        )
        match_report = matcher.getMatchesForSmdaReport(SMDA_REPORT)
        return match_report

    # Reports PROGRESS
    @Remote(progress=True, file_locations=[0])
    def getMatchesForUnmappedBinary(
        self, binary, minhash_threshold=None, pichash_size=None, progress_reporter=NoProgressReporter()
    ):
        config = SmdaConfig()
        SMDA_REPORT = None
        DISASSEMBLER = Disassembler(config)
        SMDA_REPORT = DISASSEMBLER.disassembleUnmappedBuffer(binary)
        matcher = MatcherQuery(
            self, minhash_threshold=minhash_threshold, pichash_size=pichash_size, progress_reporter=progress_reporter
        )
        match_report = matcher.getMatchesForSmdaReport(SMDA_REPORT)
        return match_report

    # Reports PROGRESS
    @Remote(progress=True)
    def getMatchesForSample(
        self, sample_id, minhash_threshold=None, pichash_size=None, progress_reporter=NoProgressReporter()
    ):
        matcher = MatcherSample(
            self, minhash_threshold=minhash_threshold, pichash_size=pichash_size, progress_reporter=progress_reporter
        )
        match_report = matcher.getMatchesForSample(sample_id)
        return match_report

    # Reports PROGRESS
    @Remote(progress=True)
    def getMatchesForSampleVs(
        self,
        sample_id,
        other_sample_id,
        minhash_threshold=None,
        pichash_size=None,
        progress_reporter=NoProgressReporter(),
    ):
        matcher = MatcherVs(
            self, minhash_threshold=minhash_threshold, pichash_size=pichash_size, progress_reporter=progress_reporter
        )
        match_report = matcher.getMatchesForSample(sample_id, other_sample_id)
        return match_report

    def _groupItems(self, items, packsize=500):
        packed_items = []
        for lower_index in range(0, len(items) + packsize, packsize):
            sliced = items[lower_index : lower_index + packsize]
            if sliced:
                packed_items.append(sliced)
        return packed_items

    #### used by Worker(updateMinHashes) and MatcherQuery #####

    # Reports PROGRESS
    def calculateMinHashes(self, function_entries, progress_reporter=NoProgressReporter()):
        minhashes = []
        smda_functions = []
        LOGGER.info("Calculating MinHashes: hashing for %d function entries requested.", len(function_entries))
        for func in function_entries:
            binary_info = BinaryInfo(b"")
            binary_info.architecture = func.architecture
            smda_functions.append((func.function_id, SmdaFunction.fromDict(func.xcfg, binary_info=binary_info)))
        # filter down to functions that fulfill size requirements
        smda_functions = [
            (function_id, smda_function)
            for function_id, smda_function in smda_functions
            if self.minhasher.isMinHashableFunction(smda_function)
        ]
        LOGGER.info("Calculating MinHashes: %d function entries are indexable.", len(smda_functions))
        if smda_functions:
            if self._minhash_config.MINHASH_POOL_INDEXING:
                packed_smda_functions = self._groupItems(smda_functions)
                progress_reporter.set_total(len(packed_smda_functions))
                with Pool(cpu_count()) as pool:
                    for result in tqdm.tqdm(
                        pool.imap_unordered(self.minhasher.calculateMinHashesFromStorage, packed_smda_functions),
                        total=len(packed_smda_functions),
                    ):
                        minhashes.extend(result)
                        progress_reporter.step()
            else:
                progress_reporter.set_total(len(smda_functions))
                for smda_function in tqdm.tqdm(smda_functions, total=len(smda_functions)):
                    minhashes.append(self.minhasher.calculateMinHashFromStorage(smda_function))
                    progress_reporter.step()
            LOGGER.info("Calculated minhashes for %d function entries!", len(minhashes))
        return minhashes

    ##### CONFIG CHANGES ####
    def updateMinHashThreshold(self, threshold):
        self.config.MINHASH_CONFIG.MINHASH_MATCHING_THRESHOLD = threshold
        self._minhash_config.MINHASH_MATCHING_THRESHOLD = threshold
        self.minhasher._minhash_config.MINHASH_MATCHING_THRESHOLD = threshold

    def updatePicHashSize(self, size):
        self.config.MINHASH_CONFIG.PICHASH_SIZE = size
        self._minhash_config.PICHASH_SIZE = size
        self.minhasher._minhash_config.PICHASH_SIZE = size

    def updateMinHasherConfig(self, config):
        self._storage_config = config.STORAGE_CONFIG
        self._minhash_config = config.MINHASH_CONFIG
        self._shingler_config = config.SHINGLER_CONFIG
        self.minhasher = MinHasher(config.MINHASH_CONFIG, config.SHINGLER_CONFIG)
