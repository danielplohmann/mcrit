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
from mcrit.storage.SearchCursor import MinimalSearchCursor, FullSearchCursor
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
        LOGGER.info("Family remapping created: %d families, %d samples.", 
                len(family_id_remapping), 
                len(export_data["sample_entries"]))
        # iterate samples
        index = 0
        for sample_sha256, sample_entry_dict in export_data["sample_entries"].items():
            index += 1
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
            LOGGER.info(f"Sample %d with SHA256 %s added...", index, sample_sha256)
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
            return {"existed": True, "sample_info": sample_entry.toDict()}
        sample_entry = self._storage.addSmdaReport(smda_report)
        if not sample_entry:
            return None
        LOGGER.info("Added %s", sample_entry)
        function_entries = self._storage.getFunctionsBySampleId(sample_entry.sample_id)
        LOGGER.info("Added %d function entries.", len(function_entries))
        job_id = None
        if calculate_hashes:
            job_id = self.updateMinHashesForSample(sample_entry.sample_id)
        return {"existed": False, "sample_info": sample_entry.toDict(), "job_id": job_id}

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

    def deleteFamily(self, family_id, keep_samples=False):
        return self._storage.deleteFamily(family_id, keep_samples=keep_samples)

    def getFunctionById(self, function_id, with_xcfg=False):
        return self._storage.getFunctionById(function_id, with_xcfg=with_xcfg)

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
                "db_state": storage_stats["db_state"],
                "storage_type": self._storage_config.STORAGE_METHOD,
                "storage_bands": len(storage_stats["bands"]),
                "num_samples": storage_stats["num_samples"],
                "num_families": storage_stats["num_families"],
                "num_functions": storage_stats["num_functions"],
                "num_pichashes": storage_stats["num_pichashes"],
            }
        }
        return status

    #### SEARCH ####

    # When performing an initial search, the cursor should be set to None.
    # Search results are of the following form:
    # {
    #     "search_results": {
    #         id1: found_entry1,
    #         id2: found_entry2,
    #         ...
    #     },
    #     "cursor": {
    #         "forward": forward cursor,
    #         "backward": backward cursor,
    #     } 
    # }
    # To get further results, perform a search using the forward cursor.
    # To get back to the previous search results, use the backward cursor.
    # If no further or previous results are available, the forward or backward cursor will be None.
    #
    # IMPORTANT: A cursor shall only be used in combination with the same
    # search_term and sort_by_list that were used when the cursor was returned from mcrit.
    # If those parameters are altered, mcrit's behavior is undefined.

    def _getSearchResultTemplate(self, search_function, search_term, sort_by_list, cursor_str, limit, to_dict=True):
        assert isinstance(search_term, str) or isinstance(search_term, int)

        sort_fields = [sort_info[0] for sort_info in sort_by_list]

        is_backward_search = False
        cursor = MinimalSearchCursor.fromStr(cursor_str)

        full_cursor = FullSearchCursor(cursor, sort_by_list)
        is_backward_search = not full_cursor.is_forward_search

        search_results_objects = search_function(search_term, cursor=full_cursor, max_num_results=limit+1)

        # Find last last_element_key, which is used for the forward cursor
        search_results_keys = list(search_results_objects.keys())
        if len(search_results_objects) >= limit + 1:
            search_results_objects.pop(search_results_keys[-1])
            search_results_keys.pop()
            last_element_key = search_results_keys[-1]
        else:
            last_element_key = None
        
        forward_cursor_str = None
        if last_element_key:
            last_result = search_results_objects[last_element_key]
            forward_cursor = MinimalSearchCursor()
            forward_cursor.is_forward_search = True ^ is_backward_search # switch for backward search, because of swap
            if to_dict:
                forward_cursor.record_values = [getattr(last_result, field) for field in sort_fields]
            else:
                forward_cursor.record_values = [last_result[field] for field in sort_fields]
            forward_cursor_str = forward_cursor.toStr()

        backward_cursor_str = None
        if len(search_results_objects) > 0 and cursor is not None:
            first_result = search_results_objects[search_results_keys[0]]
            backward_cursor = MinimalSearchCursor()
            backward_cursor.is_forward_search = False ^ is_backward_search # switch for backward search, because of swap
            if to_dict:
                backward_cursor.record_values = [getattr(first_result, field) for field in sort_fields]
            else:
                backward_cursor.record_values = [first_result[field] for field in sort_fields]
            backward_cursor_str = backward_cursor.toStr()

        if to_dict:
            transformation = lambda x: x.toDict()
        else:
            transformation = lambda x: x

        if is_backward_search:
            # reverse order
            backward_cursor_str, forward_cursor_str = forward_cursor_str, backward_cursor_str
            search_results = {k: transformation(v) for k, v in reversed(search_results_objects.items())}
        else:
            search_results = {k: transformation(v) for k, v in search_results_objects.items()}

        return {
            "search_results": search_results,
            "cursor": {
                "forward": forward_cursor_str,
                "backward": backward_cursor_str,
            }
        }

    def _get_sort_data(self, standard_sort, sort_by, is_ascending):
        if sort_by == standard_sort or sort_by is None:
            sort_by_list = [(standard_sort, is_ascending),]
        else:
            sort_by_list = [
                (sort_by, is_ascending),
                (standard_sort, True),
            ]
        return sort_by_list 

    def getFamilySearchResults(self, search_term, sort_by="family_id", is_ascending=True, cursor=None, limit=100):
        term_as_int = None
        id_match = None
        try:
            if search_term.startswith("0x"):
                term_as_int = int(search_term, 16)
            else:
                term_as_int = int(search_term)
            if term_as_int <= 0xFFFFFFFF:
                if self._storage.isFamilyId(term_as_int):
                    id_match = {
                        "family_id": term_as_int,
                        "family": self._storage.getFamily(term_as_int),
                    }
            else:
                LOGGER.warn("Can only handle family/sample/function IDs up to 0xFFFFFFFF.")
        except Exception:
            pass

        assert sort_by in (
            None,
            "family_id",
            "family_name",
            "num_samples",
            "num_library_samples",
            "num_functions",
        )

        sort_data = self._get_sort_data("family_id", sort_by, is_ascending)
        result = self._getSearchResultTemplate(
            self._storage.findFamilyByString,
            search_term,
            sort_data,
            cursor,
            limit,
        )
        result["id_match"] = id_match
        return result

    def getPichashSearchResults(self, search_term, sort_by="function_id", is_ascending=True, cursor=None, limit=100):
        # TODO: consider sort_by, is_ascending, start_cursor
        term_as_int = None
        try:
            if search_term.startswith("0x"):
                term_as_int = int(search_term, 16)
            else:
                term_as_int = int(search_term)
        except:
            pass
        
        if term_as_int is None or not self._storage.isPicHash(term_as_int):
            return {
                "search_results": {},
                "cursor": {
                    "forward": None,
                    "backward": None,
                }
            }

        assert sort_by in (
            None,
            "function_id",
            "sample_id",
            "family_id",
            "pichash",
            "function_name",
            "offset",
            "num_instructions",
            "num_blocks",
        )
        
        sort_data = self._get_sort_data("function_id", sort_by, is_ascending)
        result = self._getSearchResultTemplate(
            self._storage.findFunctionByPichash,
            term_as_int,
            sort_data,
            cursor,
            limit,
        )
        return result

    def getFunctionSearchResults(self, search_term, sort_by="function_id", is_ascending=True, cursor=None, limit=100):
        term_as_int = None
        id_match = None
        try:
            if search_term.startswith("0x"):
                term_as_int = int(search_term, 16)
            else:
                term_as_int = int(search_term)
            if term_as_int <= 0xFFFFFFFF:
                if self._storage.isFunctionId(term_as_int):
                    id_match = self._storage.getFunctionById(term_as_int).toDict()
            else:
                LOGGER.warn("Can only handle family/sample/function IDs up to 0xFFFFFFFF.")
        except Exception:
            pass

        assert sort_by in (
            None,
            "function_id",
            "sample_id",
            "family_id",
            "pichash",
            "function_name",
            "offset",
            "num_instructions",
            "num_blocks",
        )
        
        sort_data = self._get_sort_data("function_id", sort_by, is_ascending)
        result = self._getSearchResultTemplate(
            self._storage.findFunctionByString,
            search_term,
            sort_data,
            cursor,
            limit,
        )
        result["id_match"] = id_match
        return result

    def getSampleSearchResults(self, search_term, sort_by="sample_id", is_ascending=True, cursor=None, limit=100):
        term_as_int = None
        id_match = None
        try:
            if search_term.startswith("0x"):
                term_as_int = int(search_term, 16)
            else:
                term_as_int = int(search_term)
            if term_as_int <= 0xFFFFFFFF:
                if self._storage.isSampleId(term_as_int):
                    id_match = self._storage.getSampleById(term_as_int).toDict()
            else:
                LOGGER.warn("Can only handle family/sample/function IDs up to 0xFFFFFFFF.")
        except Exception:
            pass

        if re.match("^[a-fA-F0-9]{64}$", search_term) is not None:
            sample_entry = self._storage.getSampleBySha256(search_term)
            sha_match = sample_entry.toDict()
        else:
            sha_match = None

        assert sort_by in (
            None,
            "filename",
            "function_id",
            "sample_id",
            "family_id",
            "family",
            "architecture",
            "base_addr",
            "binary_size",
            "binweight",
            "bitness",
            "component",
            "is_library",
            "sha256",
            "timestamp",
        )
        
        sort_data = self._get_sort_data("sample_id", sort_by, is_ascending)
        result = self._getSearchResultTemplate(
            self._storage.findSampleByString,
            search_term,
            sort_data,
            cursor,
            limit,
        )
        result["id_match"] = id_match
        result["sha_match"] = sha_match
        return result


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
