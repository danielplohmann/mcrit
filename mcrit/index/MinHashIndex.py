#!/usr/bin/env python3
import re
import json
import time
import logging

from smda.common.SmdaReport import SmdaReport

from mcrit.config.McritConfig import McritConfig
from mcrit.config.MinHashConfig import MinHashConfig
from mcrit.config.ShinglerConfig import ShinglerConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.libs.utility import compress_encode, decompress_decode
from mcrit.queue.QueueFactory import QueueFactory
from mcrit.queue.QueueRemoteCalls import QueueRemoteCaller, NoProgressReporter
from mcrit.storage.FunctionEntry import FunctionEntry
from mcrit.storage.SampleEntry import SampleEntry
from mcrit.storage.StorageFactory import StorageFactory
from mcrit.minhash.MinHash import MinHash
from mcrit.Worker import Worker

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)


class MinHashIndex(QueueRemoteCaller(Worker)):
    def __init__(self, config=None, base_url=None):
        if config is None:
            config = McritConfig()
        self.config = config
        self._storage_config = config.STORAGE_CONFIG
        self._minhash_config = config.MINHASH_CONFIG
        self._shingler_config = config.SHINGLER_CONFIG
        self._storage = StorageFactory.getStorage(config.STORAGE_CONFIG)
        # config.QUEUE_CONFIG.QUEUE_METHOD = QueueFactory.QUEUE_METHOD_FAKE
        queue = QueueFactory().getQueue(config, storage=self._storage, consumer_id="index")
        super().__init__(queue)

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
        self._storage = StorageFactory.getStorage(self._storage_config)
        self._storage.setContent(storage_data["storage"])

    def getExportData(self, sample_ids=None, compress_data=False):
        exported_data = {
            "content": {
                "is_compressed": compress_data,
                "num_families": 0,
                "num_samples": 0,
                "num_functions": 0
            },
            # config hashes need to be identical in order for minhashes to be reusable
            "config": {
                "version": self.config.VERSION,
                "shingler": self._shingler_config.getConfigHash(),
                "minhash": self._minhash_config.getConfigHash(),
            },
            # family mapping is needed for function_entries as they only contain family_ids
            "family_mapping": {},
            # organize by sha256 to simplify avoiding redundancy during import
            "sample_entries": {},
            # organize by sha256 as well, to easily access functions of a sample
            "function_entries": {}
        }
        family_mapping = {}
        exported_sample_entries = {}
        exported_function_entries = {}
        # iterate over sample_ids and transform respective data
        for sample_id in self._storage.getSampleIds():
            if sample_ids and sample_id not in sample_ids:
                continue
            sample_entry = self._storage.getSampleById(sample_id)
            family_mapping[sample_entry.family_id] = sample_entry.family
            exported_sample_entries[sample_entry.sha256] = sample_entry.toDict()
            function_entries = self._storage.getFunctionsBySampleId(sample_id)
            functions_dict = {function_entry.function_id: function_entry.toDict() for function_entry in function_entries}
            exported_function_entries[sample_entry.sha256] = functions_dict
            if compress_data:
                exported_function_entries[sample_entry.sha256] = compress_encode(json.dumps(functions_dict))
            exported_data["content"]["num_samples"] += 1
            exported_data["content"]["num_functions"] += len(function_entries)
        exported_data["content"]["num_families"] = len(family_mapping)
        exported_data["family_mapping"] = family_mapping
        exported_data["sample_entries"] = exported_sample_entries
        exported_data["function_entries"] = exported_function_entries
        return exported_data

    def addImportData(self, export_data):
        import_report = {
            "num_samples_imported": 0,
            "num_samples_skipped": 0,
            "num_functions_imported": 0,
            "num_functions_skipped": 0,
            "num_families_imported": 0,
            "num_families_skipped": 0
        }
        # TODO adjust minimum required MCRIT version if we ever extend in a way that objects become incompatible
        if export_data["config"]["version"] <= "0.0.0":
            LOGGER.error("Cannot import data, version of export is incompatible / too old.")
            return 
        if export_data["config"]["shingler"] != self._shingler_config.getConfigHash():
            LOGGER.error("Cannot import data, shingler configuration hash is incompatible.")
            return 
        if export_data["config"]["minhash"] != self._minhash_config.getConfigHash():
            LOGGER.error("Cannot import data, MinHash configuration hash is incompatible.")
            return 
        is_compressed = export_data["content"]["is_compressed"]
        # create a dictionary for pointing family_ids as contained in the export to family_ids as used in this instance
        family_id_remapping = {}
        max_family_id_in_storage = max(self._storage.getFamilyIds())
        for exported_family_id, exported_family in export_data["family_mapping"].items():
            exported_family_id = int(exported_family_id)
            remapped_family_id = self._storage.addFamily(exported_family)
            if remapped_family_id > max_family_id_in_storage:
                import_report["num_families_imported"] += 1
                max_family_id_in_storage = remapped_family_id
            else:
                import_report["num_families_skipped"] += 1
            family_id_remapping[exported_family_id] = remapped_family_id
        LOGGER.info("Family remapping created...")
        # iterate samples
        for sample_sha256, sample_entry_dict in export_data["sample_entries"].items():
            # check if sample is already present, and skip if yes
            if self._storage.getSampleBySha256(sample_sha256):
                LOGGER.info(f"Sample with SHA256 {sample_sha256} already present in database, skipping...")
                import_report["num_samples_skipped"] += 1
                import_report["num_functions_skipped"] += sample_entry_dict["statistics"]["num_functions"]
                continue
            import_report["num_samples_imported"] += 1
            sample_entry = SampleEntry.fromDict(sample_entry_dict)
            # adjust family_id in sample_entry using our remapping
            sample_entry.family_id = family_id_remapping[sample_entry.family_id]
            # add sample_entry to storage and receive new sample_id
            remapped_sample_entry = self._storage.importSampleEntry(sample_entry)
            if sample_sha256 in export_data["function_entries"]:
                function_entries = export_data["function_entries"][sample_sha256]
                # decompress function_entries if necessary
                if is_compressed:
                    function_entries = json.loads(decompress_decode(function_entries))
                # iterate functions and add them, adjusting family_id and sample_id
                minhashes = []
                for old_function_id, function_entry_dict in function_entries.items():
                    function_entry = FunctionEntry.fromDict(function_entry_dict)
                    function_entry.sample_id = remapped_sample_entry.sample_id
                    function_entry.family_id = remapped_sample_entry.family_id
                    remapped_function_entry = self._storage.importFunctionEntry(function_entry)
                    # delaying minhash insertion speeds up the procedure dramatically
                    if function_entry.minhash:
                        minhash = MinHash(function_entry.function_id, function_entry.minhash, minhash_bits=self._minhash_config.MINHASH_SIGNATURE_BITS)
                        minhashes.append(minhash)
                    import_report["num_functions_imported"] += 1
                # ensure that their minhashes / pichashes are added to the respective indices
                self._storage.addMinHashes(minhashes)
            LOGGER.info(f"Sample with SHA256 {sample_sha256} added...")
        return import_report

    def respawn(self):
        """Get an interface to the storage"""
        self.queue.clear()
        return self._storage.clearStorage()

    #### REDIRECTED TO WORKER ####
    """
    def updateMinHashes(self, function_ids):
    def getMatchesForReport(self, report):
    def getMatchesForSmdaReport(self, report_json, minhash_threshold=None):
    def getMatchesForMappedBinary(self, binary, base_address, minhash_threshold=None):
    def getMatchesForUnmappedBinary(self, binary, minhash_threshold=None):
    def getMatchesForSample(self, sample_id, minhash_threshold=None):
    def getMatchesForSampleVs(self, sample_id, other_sample_id, minhash_threshold=None):
    def getAggregatedMatchesForSample(self, sample_id, minhash_threshold=None):
    addBinarySample(self, binary, is_dump, bitness, base_address, progress_reporter=NoProgressReporter()):
    """

    #### NOT REDIRECTED ####
    def addReport(self, smda_report, calculate_hashes=True, calculate_matches=False):
        sample_entry = self._storage.getSampleBySha256(smda_report.sha256)
        if sample_entry:
            return {"sample_info": sample_entry.toDict()}
        sample_entry = self._storage.addSmdaReport(smda_report)
        if not sample_entry:
            return None
        LOGGER.info("Added %s", sample_entry)
        function_entries = self._storage.getFunctionsBySampleId(sample_entry.sample_id)
        LOGGER.info("Added %d function entries.", len(function_entries))
        job_id = None
        if calculate_hashes:
            job_id = self.updateMinHashesForSample(sample_entry.sample_id)
        return {"sample_info": sample_entry.toDict(), "job_id": job_id}

    def addReportJson(self, report_json, calculate_hashes=True, calculate_matches=False):
        report = SmdaReport.fromDict(report_json)
        return self.addReport(report, calculate_hashes=calculate_hashes, calculate_matches=calculate_matches)

    def addReportFile(self, report_filepath, calculate_hashes=True, calculate_matches=False):
        with open(report_filepath, "r") as fin:
            report_json = json.load(fin)
        report = SmdaReport.fromDict(report_json)
        return self.addReport(report, calculate_hashes=calculate_hashes, calculate_matches=calculate_matches)

    #### SIMPLE LOOKUPS ####
    def getFamily(self, family_id):
        return self._storage.getFamily(family_id)

    def getFunctionsBySampleId(self, sample_id):
        return self._storage.getFunctionsBySampleId(sample_id)

    def isFunctionId(self, function_id):
        return self._storage.isFunctionId(function_id)

    def isSampleId(self, sample_id):
        return self._storage.isSampleId(sample_id)

    def deleteSample(self, sample_id):
        return self._storage.deleteSample(sample_id)

    def getFunctionById(self, function_id):
        return self._storage.getFunctionById(function_id)

    def getFunctions(self, start_index, limit):
        return self._storage.getFunctions(start_index, limit)

    def getSamplesByFamilyId(self, family_id):
        return self._storage.getSamplesByFamilyId(family_id)

    def getSampleById(self, sample_id):
        return self._storage.getSampleById(sample_id)

    def getSamples(self, start_index, limit):
        return self._storage.getSamples(start_index, limit)

    def getFamilies(self):
        family_overview = {}
        for family_id in self._storage.getFamilyIds():
            family_is_library = False
            overview_entry = {
                "family_id": family_id,
                "family": self._storage.getFamily(family_id),
                "num_samples": 0,
                "num_functions": 0,
                "is_library": family_is_library
            }
            sample_entries = self._storage.getSamplesByFamilyId(family_id)
            if sample_entries:
                family_is_library = True
            for sample_entry in sample_entries:
                overview_entry["num_samples"] += 1
                overview_entry["num_functions"] += sample_entry.statistics["num_functions"]
                family_is_library &= sample_entry.is_library
            overview_entry["is_library"] = family_is_library
            family_overview[family_id] = overview_entry
        return family_overview

    def getFunctionGraph(self, function_id):
        # NOTE: Does not work at the moment, as xcfg might be deleted.
        raise NotImplementedError
        function_entry = self._storage.getFunctionById(function_id)
        function_info = {"cfg": function_entry.xcfg}
        return function_info

    def getAllSampleInfos(self):
        infos = []
        for sample_id in sorted(self._storage.getSampleIds()):
            infos.append(self.getSampleById(sample_id))
        return infos

    def getStatus(self):
        storage_stats = self._storage.getStats()
        status = {
            "status": {
                "storage_type": self._storage_config.STORAGE_METHOD,
                "storage_bands": len(storage_stats["bands"]),
                "num_samples": storage_stats["num_samples"],
                "num_families": storage_stats["num_families"],
                "num_functions": storage_stats["num_functions"],
                "num_pichashes": storage_stats["num_pichashes"],
            }
        }
        return status

    def getSearchResults(self, search_term, max_num_results=100):
        """ Recognize characteristics of search term and conduct applicable searches across compatible fields """
        results = {
            "families": {},
            "samples": {},
            "functions": {},
            # TODO decide whether jobs/results makes more sense here
            "jobs": {},
            "stats": {
                "max_num_results": max_num_results,
                "num_families_found": 0,
                "num_samples_found": 0,
                "num_functions_found": 0,
                "num_jobs_found": 0,
                }
        }
        # try to regex as sha256 hash: sample_id
        if re.match("^[a-fA-F0-9]{64}$", search_term) is not None:
            sample_entry = self._storage.getSampleBySha256(search_term)
            results["samples"][sample_entry.sample_id] = sample_entry.toDict()
            results["stats"]["num_samples_found"] = 1
            return results
        # try to parse as int: family_id, sample_id, function_id, function_address, pic_hash
        term_as_int = None
        try:
            if search_term.startswith("0x"):
                term_as_int = int(search_term, 16)
            else:
                term_as_int = int(search_term)
            if term_as_int <= 0xFFFFFFFF:
                if self._storage.isFamilyId(term_as_int):
                    results["families"][term_as_int] = self._storage.getFamily(term_as_int)
                    results["stats"]["num_families_found"] = 1
                if self._storage.isSampleId(term_as_int):
                    results["samples"][term_as_int] = self._storage.getSampleById(term_as_int).toDict()
                    results["stats"]["num_samples_found"] = 1
                if self._storage.isFunctionId(term_as_int):
                    results["functions"][term_as_int] = self._storage.getFunctionById(term_as_int).toDict()
                    results["stats"]["num_functions_found"] = 1
            else:
                LOGGER.warn("Can only handle family/sample/function IDs up to 0xFFFFFFFF.")
            if self._storage.isPicHash(term_as_int):
                pic_matches = self._storage.getMatchesForPicHash(term_as_int)
                results["stats"]["num_functions_found"] += len(pic_matches)
                for match in pic_matches:
                    sample_id, function_id = match
                    if len(results["functions"]) < max_num_results:
                        results["functions"][function_id] = self._storage.getFunctionById(function_id).toDict()
            return results
        except:
            pass
        # as regular string, refer to storage implementation of searching
        results["families"].update(self._storage.findFamilyByString(search_term, max_num_results=max_num_results))
        results["samples"].update({k: v.toDict() for k, v in self._storage.findSampleByString(search_term, max_num_results=max_num_results).items()})
        results["functions"].update({k: v.toDict() for k, v in self._storage.findFunctionByString(search_term, max_num_results=max_num_results).items()})
        # NOTE right now, we cap the count to 100 due to Storage implementation, could also count all and just limit returned results
        results["stats"]["num_families_found"] = len(results["families"])
        results["stats"]["num_samples_found"] = len(results["samples"])
        results["stats"]["num_functions_found"] = len(results["functions"])
        return results

    ##### CONFIG CHANGES ####
    def updateMinHashThreshold(self, threshold):
        self.config.MINHASH_CONFIG.MINHASH_MATCHING_THRESHOLD = threshold
        self._minhash_config.MINHASH_MATCHING_THRESHOLD = threshold

    def updatePicHashSize(self, size):
        self.config.MINHASH_CONFIG.PICHASH_SIZE = size
        self._minhash_config.PICHASH_SIZE = size

    def updateMinHasherConfig(self, config):
        self._storage_config = config.STORAGE_CONFIG
        self._minhash_config = config.MINHASH_CONFIG
        self._shingler_config = config.SHINGLER_CONFIG
