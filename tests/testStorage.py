import json
import logging
import os
from unittest import TestCase, main

import pytest
from smda.common.SmdaReport import SmdaReport

from mcrit.config.McritConfig import McritConfig
from mcrit.config.MinHashConfig import MinHashConfig
from mcrit.config.QueueConfig import QueueConfig
from mcrit.config.ShinglerConfig import ShinglerConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.minhash.MinHash import MinHash
from mcrit.storage.FunctionEntry import FunctionEntry
from mcrit.storage.SampleEntry import SampleEntry
from mcrit.storage.StorageFactory import StorageFactory

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class MemoryStorageTest(TestCase):
    def setUp(self):
        self._storage_config = StorageConfig(
            STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MEMORY,
            STORAGE_DROP_DISASSEMBLY=False,
        )
        mcrit_config = McritConfig()
        mcrit_config.STORAGE_CONFIG = self._storage_config
        mcrit_config.MINHASH_CONFIG = MinHashConfig()
        mcrit_config.MINHASH_CONFIG.MINHASH_SIGNATURE_LENGTH = 10
        mcrit_config.MINHASH_CONFIG.MINHASH_SIGNATURE_BITS = 8
        mcrit_config.SHINGLER_CONFIG = ShinglerConfig()
        mcrit_config.QUEUE_CONFIG = QueueConfig()
        self.storage = StorageFactory.getStorage(mcrit_config)
        # get example_file_path
        THIS_FILE_PATH = str(os.path.abspath(__file__))
        PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
        self.example_file_path = os.sep.join([PROJECT_ROOT, "tests", "example_report.smda"])

    def tearDown(self):
        self.storage.clearStorage()

    def testBasicStorageUsage(self):
        self.storage.clearStorage()
        smda_report = SmdaReport.fromFile(self.example_file_path)
        self.storage.addSmdaReport(smda_report)
        stats = self.storage.getStats()
        self.assertEqual(1, stats["num_samples"])
        self.assertEqual(10, stats["num_functions"])
        self.assertEqual(10, stats["num_pichashes"])
        # without pichash aggregation, the field is reported as None instead of a misleading 0
        stats_without_pichash = self.storage.getStats(with_pichash=False)
        self.assertEqual(1, stats_without_pichash["num_samples"])
        self.assertEqual(10, stats_without_pichash["num_functions"])
        self.assertIsNone(stats_without_pichash["num_pichashes"])

    def testFamilyHandling(self):
        self.storage.clearStorage()
        self.storage.addFamily("family_1")
        self.storage.addFamily("family_2")
        id_3 = self.storage.addFamily("family_3")
        id_3_again = self.storage.addFamily("family_3")
        self.assertEqual(id_3, 3)
        self.assertEqual(id_3_again, 3)

        # family 0 is default: ""
        self.assertEqual(0, self.storage.getFamilyId(""))
        self.assertEqual("", self.storage.getFamily(0).family_name)
        self.assertEqual(4, len(self.storage.getFamilyIds()))
        self.assertEqual("family_1", self.storage.getFamily(1).family_name)
        self.assertEqual(3, self.storage.getFamilyId("family_3"))
        self.assertIsNone(self.storage.getFamily(1000))
        self.assertIsNone(self.storage.getFamilyId("nonexistent"))

        # family modification
        self.storage.modifyFamily(1, {"family_name": "family_1a"})
        self.assertEqual(None, self.storage.getFamilyId("family_1"))
        self.assertEqual(4, self.storage.getFamilyId("family_1a"))
        # family deletion
        self.storage.deleteFamily(4)
        self.assertEqual(None, self.storage.getFamilyId("family_1a"))

    def testSampleHandling(self):
        self.storage.clearStorage()
        # TODO: different samples required, because addSmdaReport wont accept identical hashes
        with open(self.example_file_path) as fjson:
            smda_json = json.load(fjson)
        smda_report_a = SmdaReport.fromDict(smda_json)
        smda_report_a.family = "family_1"
        smda_report_a.is_library = False
        smda_report_a.sha256 = 64 * "a"
        smda_report_b = SmdaReport.fromDict(smda_json)
        smda_report_b.family = "family_1"
        smda_report_b.is_library = False
        smda_report_b.sha256 = 64 * "b"
        smda_report_c = SmdaReport.fromDict(smda_json)
        smda_report_c.family = "family_2"
        smda_report_c.is_library = False
        smda_report_c.sha256 = 64 * "c"
        smda_report_d = SmdaReport.fromDict(smda_json)
        smda_report_d.family = "family_3"
        smda_report_d.is_library = True
        smda_report_d.version = "3.42"
        smda_report_d.sha256 = 64 * "d"
        self.storage.addSmdaReport(smda_report_a)
        self.storage.addSmdaReport(smda_report_b)
        self.storage.addSmdaReport(smda_report_c)
        sample_entry_d = self.storage.addSmdaReport(smda_report_d)
        # produce minhashes for  later testing of clean deletion
        unhashed_function_ids = self.storage.getUnhashedFunctions(None, only_function_ids=True)
        unhashed_functions = self.storage.getUnhashedFunctions(unhashed_function_ids)
        # minhashes = self.calculateMinHashes(unhashed_functions)
        from smda.common.BinaryInfo import BinaryInfo
        from smda.common.SmdaFunction import SmdaFunction

        from mcrit.minhash.MinHasher import MinHasher

        minhasher = MinHasher(MinHashConfig(), ShinglerConfig())
        minhashes = []
        smda_functions = []
        for func in unhashed_functions:
            binary_info = BinaryInfo(b"")
            binary_info.architecture = func.architecture
            smda_functions.append((func.function_id, SmdaFunction.fromDict(func.xcfg, binary_info=binary_info)))
        smda_functions = [(function_id, smda_function) for function_id, smda_function in smda_functions if minhasher.isMinHashableFunction(smda_function)]
        for smda_function in smda_functions:
            minhashes.append(minhasher.calculateMinHashFromStorage(smda_function))
        if minhashes:
            self.storage.addMinHashes(minhashes)
        # start tests
        self.assertIsInstance(sample_entry_d, SampleEntry)
        self.assertEqual(sample_entry_d.sample_id, 3)
        self.assertEqual(None, self.storage.addSmdaReport(smda_report_d))

        self.assertEqual([0, 1, 2, 3], self.storage.getSampleIds())
        self.assertTrue(self.storage.isSampleId(0))
        self.assertFalse(self.storage.isSampleId(4))
        self.assertEqual(None, self.storage.getSampleById(4))
        self.assertEqual(2, self.storage.getSampleById(2).sample_id)
        self.assertEqual(None, self.storage.getSampleIdByFunctionId(40))
        self.assertEqual(3, self.storage.getSampleIdByFunctionId(30))
        self.assertEqual(None, self.storage.getSamplesByFamilyId(4))
        self.assertEqual([0, 1], [s.sample_id for s in self.storage.getSamplesByFamilyId(1)])
        self.assertEqual(None, self.storage.getLibraryInfoForSampleId(2))
        self.assertEqual({"family": "family_3", "version": "3.42"}, self.storage.getLibraryInfoForSampleId(3))

        self.assertEqual(None, self.storage.getLibraryInfoForSampleId(1000))

        self.assertEqual(0, self.storage.getSampleBySha256(64 * "a").sample_id)
        self.assertEqual(None, self.storage.getSampleBySha256(64 * "z"))

        # test modifications
        self.storage.modifySample(3, {"family_name": "changed_family", "version": "new_version", "component": "new_component", "is_library": True})
        self.assertEqual("changed_family", self.storage.getSampleById(3).family)
        self.assertEqual("new_version", self.storage.getSampleById(3).version)
        self.assertEqual("new_component", self.storage.getSampleById(3).component)
        self.assertEqual(True, self.storage.getSampleById(3).is_library)

        # test deletions
        self.assertFalse(self.storage.deleteSample(1000))
        functions_to_be_deleted = self.storage.getFunctionsBySampleId(3)
        function_ids_to_be_deleted = [f.function_id for f in functions_to_be_deleted]
        minhashes_of_deleted_functions = [f.getMinHash(minhash_bits=MinHashConfig.MINHASH_SIGNATURE_BITS) for f in functions_to_be_deleted if f.minhash]
        delete_result = self.storage.deleteSample(3)
        self.assertTrue(delete_result)
        self.assertEqual(None, self.storage.getSampleById(3))
        # functions, minhashes will be cascadically deleted
        self.assertEqual(None, self.storage.getSampleIdByFunctionId(30))
        # no function id should be contained in minhash bands
        for minhash in minhashes_of_deleted_functions:
            candidates = self.storage.getCandidatesForMinHash(minhash)
            self.assertTrue(len(set(candidates).intersection(set(function_ids_to_be_deleted))) == 0)
        new_report_d = self.storage.addSmdaReport(smda_report_d)
        self.assertIsNotNone(new_report_d)
        self.assertEqual(new_report_d.sample_id, 4)
        self.assertTrue(self.storage.isFunctionId(49))

    def testGetSampleBySha256(self):
        self.storage.clearStorage()
        # an empty collection must yield None straight from the lookup, without a count-based emptiness guard
        self.assertEqual(None, self.storage.getSampleBySha256(64 * "0"))
        smda_report = SmdaReport.fromFile(self.example_file_path)
        sample_entry = self.storage.addSmdaReport(smda_report)
        self.assertEqual(sample_entry.sample_id, self.storage.getSampleBySha256(smda_report.sha256).sample_id)
        self.assertEqual(None, self.storage.getSampleBySha256(64 * "0"))

    def testFunctionHandling(self):
        self.storage.clearStorage()
        # TODO use SmdaReport.fromFile
        with open(self.example_file_path) as fjson:
            smda_json = json.load(fjson)
        smda_report_a = SmdaReport.fromDict(smda_json)
        smda_report_a.sha256 = 64 * "a"
        smda_report_a.family = "family_1"
        smda_report_b = SmdaReport.fromDict(smda_json)
        smda_report_b.family = "family_1"
        smda_report_b.sha256 = 64 * "b"
        self.storage.addSmdaReport(smda_report_a)
        self.storage.addSmdaReport(smda_report_b)

        self.assertTrue(self.storage.isFunctionId(0))
        self.assertTrue(self.storage.isFunctionId(1))
        self.assertFalse(self.storage.isFunctionId(30))
        functions = self.storage.getFunctionsBySampleId(1)
        self.assertIsNotNone(functions)
        self.assertEqual(list(range(10, 20)), [entry.function_id for entry in functions])

        function = self.storage.getFunctionById(1, with_xcfg=False)
        self.assertIsNone(function.xcfg)
        function = self.storage.getFunctionById(1, with_xcfg=True)
        self.assertEqual(1, function.function_id)
        self.assertNotEqual({}, function.xcfg)
        self.storage.deleteXcfgForSampleId(function.sample_id)
        function = self.storage.getFunctionById(1, with_xcfg=True)
        self.assertEqual({}, function.xcfg)
        function2 = self.storage.getFunctionById(15, with_xcfg=True)
        self.assertNotEqual({}, function2.xcfg)
        self.storage.deleteXcfgData()
        function2 = self.storage.getFunctionById(15, with_xcfg=True)
        self.assertEqual({}, function2.xcfg)

        self.assertIsNone(self.storage.getFunctionById(1000))
        functions = self.storage.getFunctionsBySampleId(1000)
        self.assertIsNone(functions)

        self.storage.deleteXcfgForSampleId(1000)

    def testHashHandling(self):
        storage_config = StorageConfig()
        storage_config.STORAGE_BANDS = {2: 2, 3: 8}
        storage_config.STORAGE_BAND_SEED = 0

        self.storage.clearStorage()
        with open(self.example_file_path) as fjson:
            smda_json = json.load(fjson)
        smda_report_a = SmdaReport.fromDict(smda_json)
        smda_report_a.sha256 = 64 * "a"
        smda_report_a.family = "family_1"
        smda_report_b = SmdaReport.fromDict(smda_json)
        smda_report_b.family = "family_1"
        smda_report_b.sha256 = 64 * "b"
        self.storage.addSmdaReport(smda_report_a)
        self.storage.addSmdaReport(smda_report_b)

        # pichash tests
        sample_entry = SampleEntry(smda_report_a, sample_id=1, family_id=1)
        function_entry = FunctionEntry(sample_entry, smda_report_a.getFunction(356), 1)
        # Will this work?
        initial_pichash = function_entry.pichash
        pichashes = self.storage.getPicHashMatchesByFunctionId(1)
        self.assertTrue(initial_pichash in pichashes)
        family_sample_and_function_ids = self.storage.getMatchesForPicHash(initial_pichash)
        self.assertTrue(self.storage.isPicHash(initial_pichash))
        self.assertEqual(set([(1, 0, 1), (1, 1, 11)]), family_sample_and_function_ids)

        not_a_pichash = 0
        self.assertEqual(set(), self.storage.getMatchesForPicHash(not_a_pichash))

        pichashes_by_function_ids = self.storage.getPicHashMatchesByFunctionIds(list(range(10, 20)))
        pichashes_by_sample_id = self.storage.getPicHashMatchesBySampleId(1)
        self.assertEqual(pichashes_by_function_ids, pichashes_by_sample_id)

        self.assertIsNone(self.storage.getPicHashMatchesBySampleId(1000))
        self.assertIsNone(self.storage.getPicHashMatchesByFunctionId(1000))
        self.assertEqual(pichashes, self.storage.getPicHashMatchesByFunctionIds([1, 1, 1000]))

        # minhash tests
        # TODO check if MinHash initialization works
        minhash_a = MinHash(function_id=1, minhash_signature=[0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39], minhash_bits=8)
        minhash_b = MinHash(function_id=3, minhash_signature=[0x30, 0x31, 0x30, 0x33, 0x30, 0x30, 0x30, 0x37, 0x38, 0x39], minhash_bits=8)
        function_entry = self.storage.getFunctionById(1)
        self.assertEqual(b"", function_entry.minhash)
        status = self.storage.addMinHash(minhash_a)
        self.assertTrue(status)
        self.storage.addMinHash(minhash_b)
        function_entry = self.storage.getFunctionById(1)
        minhash_queried = self.storage.getMinHashByFunctionId(1)
        self.assertEqual(minhash_a.getMinHash(), minhash_queried)
        minhash_queried = self.storage.getMinHashByFunctionId(3)
        self.assertEqual(minhash_b.getMinHash(), minhash_queried)

        self.assertFalse(self.storage.addMinHash(MinHash(function_id=1000)))
        self.assertFalse(self.storage.addMinHash(MinHash(function_id=None)))

        self.assertEqual(None, self.storage.getMinHashByFunctionId(1000))

        # minhash band tests
        candidates = self.storage.getCandidatesForMinHash(minhash_a)
        self.assertEqual(set([1, 3]), candidates)

        candidates = self.storage.getCandidatesForMinHashes({1000: minhash_a})
        self.assertEqual({1000: set([1, 3])}, candidates)

        # band rebuild test
        self.storage.rebuildMinhashBandIndex()
        minhash_c = MinHash(function_id=1000, minhash_signature=[0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39], minhash_bits=8)
        candidates_after = self.storage.getCandidatesForMinHashes({1000: minhash_c})
        self.assertEqual(candidates, candidates_after)

    def testMatchingCache(self):
        cache = self.storage.createMatchingCache([])
        self.assertTrue(hasattr(cache, "getMinHashByFunctionId"))
        self.assertTrue(hasattr(cache, "getSampleIdByFunctionId"))

    def testMatchingCacheAllowSelfReturnDoesNotMutateStorage(self):
        self.storage.clearStorage()
        smda_report = SmdaReport.fromFile(self.example_file_path)
        self.storage.addSmdaReport(smda_report)

        cache = self.storage.createMatchingCache([0], allow_self_return=True)
        cache_only_entry = self.storage.getFunctionById(0, with_xcfg=True)
        cache_only_entry.sample_id = 999
        cache_only_entry.minhash = b"cache-only-minhash"
        cache.addFunctionEntriesToCache([cache_only_entry])

        self.assertEqual(0, self.storage.getSampleIdByFunctionId(0))
        self.assertNotEqual(b"cache-only-minhash", self.storage.getMinHashByFunctionId(0))
        self.assertEqual(999, cache.getSampleIdByFunctionId(0))
        self.assertEqual(b"cache-only-minhash", cache.getMinHashByFunctionId(0))
        self.assertEqual(set([0]), cache.getFunctionIdsBySampleId(999))

    def testMatchingCacheSupportsQueryFunctions(self):
        self.storage.clearStorage()
        smda_report = SmdaReport.fromFile(self.example_file_path)
        query_sample = self.storage.addSmdaReport(smda_report, isQuery=True)
        assert query_sample is not None
        query_function_ids = self.storage.getFunctionIdsBySampleId(query_sample.sample_id)
        assert query_function_ids is not None
        query_function_id = query_function_ids[0]
        query_function = self.storage.getFunctionById(query_function_id)
        assert query_function is not None

        for allow_self_return in (False, True):
            cache = self.storage.createMatchingCache([query_function_id], allow_self_return=allow_self_return)
            self.assertEqual(query_sample.sample_id, cache.getSampleIdByFunctionId(query_function_id))
            self.assertEqual(query_function.minhash, cache.getMinHashByFunctionId(query_function_id))
            self.assertEqual(set([query_function_id]), set(cache.getFunctionIdsBySampleId(query_sample.sample_id)))


@pytest.mark.mongo
class MongoDbStorageTest(MemoryStorageTest):
    def setUp(self):
        mongodb_server = os.environ.get("TEST_MONGODB", "127.0.0.1")
        # split host:port when the env var contains both
        if ":" in mongodb_server:
            server, port = mongodb_server.rsplit(":", 1)
        else:
            server, port = mongodb_server, "27017"
        self._storage_config = StorageConfig(
            STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MONGODB,
            STORAGE_SERVER=server,
            STORAGE_PORT=port,
            STORAGE_MONGODB_DBNAME="test_mongodbstorage_mcrit",
            STORAGE_DROP_DISASSEMBLY=False,
        )
        mcrit_config = McritConfig()
        mcrit_config.STORAGE_CONFIG = self._storage_config
        mcrit_config.MINHASH_CONFIG = MinHashConfig()
        mcrit_config.MINHASH_CONFIG.MINHASH_SIGNATURE_LENGTH = 10
        mcrit_config.MINHASH_CONFIG.MINHASH_SIGNATURE_BITS = 8
        mcrit_config.SHINGLER_CONFIG = ShinglerConfig()
        mcrit_config.QUEUE_CONFIG = QueueConfig()
        self.storage = StorageFactory.getStorage(mcrit_config)
        # get example_file_path
        THIS_FILE_PATH = str(os.path.abspath(__file__))
        PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
        self.example_file_path = os.sep.join([PROJECT_ROOT, "tests", "example_report.smda"])

    def _createSecondStorage(self):
        mcrit_config = McritConfig()
        mcrit_config.STORAGE_CONFIG = self._storage_config
        mcrit_config.MINHASH_CONFIG = MinHashConfig()
        mcrit_config.SHINGLER_CONFIG = ShinglerConfig()
        mcrit_config.QUEUE_CONFIG = QueueConfig()
        return StorageFactory.getStorage(mcrit_config)

    def testCounterInitIsIdempotent(self):
        # constructing storage repeatedly against the same database must not add counter documents (#105)
        self.storage.clearStorage()
        second_storage = self._createSecondStorage()
        second_storage._getDb()
        counters = self.storage._getDb().counters
        for name in ["query_samples", "query_functions"]:
            self.assertEqual(1, counters.count_documents({"name": name}))

    def testCounterDuplicateCleanupAndUniqueIndex(self):
        self.storage.clearStorage()
        counters = self.storage._getDb().counters
        # recreate the pre-fix state: non-unique index, one real counter and several {value: 1} duplicates (#105)
        counters.drop()
        counters.create_index("name")
        counters.insert_one({"name": "query_samples", "value": 242})
        counters.insert_many([{"name": "query_samples", "value": 1} for _ in range(5)])
        counters.insert_one({"name": "query_functions", "value": 77})
        counters.insert_many([{"name": "query_functions", "value": 1} for _ in range(5)])
        second_storage = self._createSecondStorage()
        second_storage._getDb()
        # only the highest-valued document survives per name and the index is unique afterwards
        self.assertEqual(1, counters.count_documents({"name": "query_samples"}))
        self.assertEqual(242, counters.find_one({"name": "query_samples"})["value"])
        self.assertEqual(1, counters.count_documents({"name": "query_functions"}))
        self.assertEqual(77, counters.find_one({"name": "query_functions"})["value"])
        self.assertTrue(counters.index_information()["name_1"].get("unique", False))
        # counter increments continue from the real value
        self.assertEqual(242, self.storage._useCounter("query_samples"))
        self.assertEqual(243, counters.find_one({"name": "query_samples"})["value"])

    def testCounterDuplicateCleanupCoversEveryName(self):
        # the unique index is built over the whole collection, so the cleanup has to be too: duplicates under any
        # other counter name (all of them are written by name-only upserts, and mongoqueue's "job" counter shares
        # this collection) would otherwise fail the index build and take storage initialisation down with it (#105)
        self.storage.clearStorage()
        counters = self.storage._getDb().counters
        counters.drop()
        counters.create_index("name")
        counters.insert_one({"name": "functions", "value": 500})
        counters.insert_many([{"name": "functions", "value": 1} for _ in range(3)])
        counters.insert_one({"name": "job", "value": 17})
        counters.insert_one({"name": "job", "value": 1})
        second_storage = self._createSecondStorage()
        # initialisation has to succeed rather than raise DuplicateKeyError while building the unique index
        second_storage._getDb()
        self.assertEqual(1, counters.count_documents({"name": "functions"}))
        self.assertEqual(500, counters.find_one({"name": "functions"})["value"])
        self.assertEqual(1, counters.count_documents({"name": "job"}))
        self.assertEqual(17, counters.find_one({"name": "job"})["value"])
        self.assertTrue(counters.index_information()["name_1"].get("unique", False))

    def testStorageInitializationCreatesIndexes(self):
        expected_indexed_fields = {
            "samples": {"sample_id", "sha256", "family_id"},
            "families": {"family_id", "family_name"},
            "functions": {"function_id", "sample_id", "family_id", "function_name", "_pichash", "_picblockhashes.hash", "_picblockhashes.offset"},
            "query_samples": {"sample_id", "sha256"},
        }
        for collection, expected_fields in expected_indexed_fields.items():
            index_information = self.storage._getDb()[collection].index_information()
            indexed_fields = set(key for index in index_information.values() for key, _direction in index["key"])
            self.assertTrue(expected_fields.issubset(indexed_fields), f"missing indexes on {collection}: {expected_fields - indexed_fields}")

    def testGetSampleBySha256ForQuerySamples(self):
        self.storage.clearStorage()
        self.assertEqual(None, self.storage.getSampleBySha256(64 * "0", is_query=True))
        smda_report = SmdaReport.fromFile(self.example_file_path)
        query_entry = self.storage.addSmdaReport(smda_report, isQuery=True)
        self.assertEqual(query_entry.sample_id, self.storage.getSampleBySha256(smda_report.sha256, is_query=True).sample_id)
        # the regular sample collection must remain unaffected
        self.assertEqual(None, self.storage.getSampleBySha256(smda_report.sha256))

    def testRebuildMinhashBandIndexMatchesIncrementalBands(self):
        self.storage.clearStorage()
        smda_report = SmdaReport.fromFile(self.example_file_path)
        self.storage.addSmdaReport(smda_report)
        # give a subset of the 10 functions minhashes, leave the others unhashed
        minhashes = [MinHash(function_id=function_id, minhash_signature=[0x30 + function_id + index for index in range(10)], minhash_bits=8) for function_id in [0, 2, 3, 5, 7, 8]]
        self.storage.addMinHashes(minhashes)
        band_collections = ["band_%d" % band_id for band_id in range(self._storage_config.STORAGE_NUM_BANDS)]

        def dumpBands():
            return {
                collection: sorted((document["band_hash"], sorted(document["function_ids"])) for document in self.storage._getDb()[collection].find({}, {"_id": 0}))
                for collection in band_collections
            }

        bands_before = dumpBands()
        # a batch size of 2 forces the rebuild through multiple keyset pages
        self.storage._minhash_config.MINHASH_BAND_REBUILD_WORK_PACKAGE_SIZE = 2
        rebuild_result = self.storage.rebuildMinhashBandIndex()
        self.assertEqual(len(minhashes), rebuild_result["minhash_functions_indexed"])
        self.assertEqual(bands_before, dumpBands())


@pytest.mark.mongo
class MongoDbXcfgSplitTest(TestCase):
    """The disassembly split (#137): `_xcfg` lives in its own collection keyed by function id,
    and every reader that carried it before must still hand callers the same shape."""

    @classmethod
    def setUpClass(cls):
        cls.example_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "example_report.smda")

    def setUp(self):
        config = McritConfig()
        config.STORAGE_CONFIG = StorageConfig(STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MONGODB, STORAGE_MONGODB_DBNAME="test_xcfg_split_mcrit")
        config.MINHASH_CONFIG = MinHashConfig()
        config.SHINGLER_CONFIG = ShinglerConfig()
        self.storage = StorageFactory.getStorage(config)
        self.storage.clearStorage()
        report = SmdaReport.fromFile(self.example_file_path)
        report.family = "xcfg_split"
        self.sample_entry = self.storage.addSmdaReport(report)

    def testBlobsLiveOutsideTheFunctionDocuments(self):
        db = self.storage._getDb()
        self.assertEqual(db.functions.count_documents({}), db.xcfg.count_documents({}))
        for function_document in db.functions.find({}, {"_id": 0}):
            self.assertNotIn("_xcfg", function_document)
        # keyed by function id, so no secondary index is needed for the lookup
        self.assertEqual(
            sorted(document["_id"] for document in db.xcfg.find({}, {"_id": 1})),
            sorted(document["function_id"] for document in db.functions.find({}, {"function_id": 1, "_id": 0})),
        )

    def testReadersThatCarriedTheBlobStillDo(self):
        functions = self.storage.getFunctionsBySampleId(self.sample_entry.sample_id)
        self.assertTrue(functions)
        # feeds Worker.calculateMinHashes and the code-reference extraction in match reports
        self.assertTrue(all(entry.xcfg for entry in functions))
        unhashed = self.storage.getUnhashedFunctions()
        self.assertTrue(unhashed)
        self.assertTrue(all(entry.xcfg for entry in unhashed))
        paged = self.storage.getFunctions(0, 5)
        self.assertTrue(paged)
        self.assertTrue(all(entry.xcfg for entry in paged))

    def testWithXcfgFlagStillGatesTheBlob(self):
        function_id = self.storage.getFunctionsBySampleId(self.sample_entry.sample_id)[0].function_id
        self.assertIsNone(self.storage.getFunctionById(function_id).xcfg)
        self.assertNotEqual({}, self.storage.getFunctionById(function_id, with_xcfg=True).xcfg)

    def testHasInlineXcfgRemainingTracksTheSplitState(self):
        # False on the split shape, True once blobs sit inline again - this is the /status
        # signal for a half-migrated instance, so both transitions must be reported
        self.assertFalse(self.storage.hasInlineXcfgRemaining())
        self._revertToInlineBlobs()
        self.assertTrue(self.storage.hasInlineXcfgRemaining())

    def testFinishedInplaceMarkerDecidesWithoutScanning(self):
        # the terminal marker migrate_xcfg_split writes on completion is authoritative for
        # "migrated" and must win over the bounded probe (which could not prove a negative here)
        db = self.storage._getDb()
        self._revertToInlineBlobs()
        db.c1_migration_state.insert_one({"_id": "inplace:functions:xcfg", "finished_at": "2026-08-24T00:00:00+00:00"})
        try:
            self.assertFalse(self.storage.hasInlineXcfgRemaining())
        finally:
            db.c1_migration_state.drop()

    def testCopyModeMarkerDoesNotDecide(self):
        # a rehearsal copy completing says nothing about this instance's functions collection -
        # only an inplace completion is authoritative for "no inline blobs remain"
        db = self.storage._getDb()
        self._revertToInlineBlobs()
        db.c1_migration_state.insert_one({"_id": "copy:functions:xcfg", "finished_at": "2026-08-24T00:00:00+00:00"})
        try:
            self.assertTrue(self.storage.hasInlineXcfgRemaining())
        finally:
            db.c1_migration_state.drop()

    def testStatusSurfacesTheInlineXcfgSignal(self):
        mcrit_config = McritConfig()
        mcrit_config.STORAGE_CONFIG = StorageConfig(STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MONGODB, STORAGE_MONGODB_DBNAME="test_xcfg_split_mcrit")
        status = MinHashIndex(mcrit_config).getStatus(with_pichash=False)["status"]
        self.assertFalse(status["inline_xcfg_remaining"])
        self._revertToInlineBlobs()
        status = MinHashIndex(mcrit_config).getStatus(with_pichash=False)["status"]
        self.assertTrue(status["inline_xcfg_remaining"])

    def _revertToInlineBlobs(self):
        """Rewind a sample into the pre-split shape: blobs back inside the function documents,
        blob collection gone. This is exactly what an instance looks like between deploying the
        split code and finishing migrate_xcfg_split."""
        db = self.storage._getDb()
        for blob_document in db.xcfg.find({}):
            db.functions.update_one({"function_id": blob_document["_id"]}, {"$set": {"_xcfg": blob_document["_xcfg"]}})
        db.xcfg.drop()

    def testReadersFallBackToInlineBlobsBeforeMigration(self):
        """This code ships before the migration runs, so readers must serve inline `_xcfg`
        instead of reporting empty disassembly - calculateMinHashes and match reports would
        otherwise silently compute from nothing on an un-migrated instance."""
        self._revertToInlineBlobs()
        db = self.storage._getDb()
        self.assertGreater(db.functions.count_documents({"_xcfg": {"$exists": True}}), 0)
        functions = self.storage.getFunctionsBySampleId(self.sample_entry.sample_id)
        self.assertTrue(all(entry.xcfg for entry in functions))
        function_id = functions[0].function_id
        self.assertNotEqual({}, self.storage.getFunctionById(function_id, with_xcfg=True).xcfg)
        unhashed = self.storage.getUnhashedFunctions()
        self.assertTrue(unhashed)
        self.assertTrue(all(entry.xcfg for entry in unhashed))

    def testBlobWinsOverStaleInlineCopy(self):
        """Once a blob exists it is the source of truth; a leftover inline copy (e.g. after a
        rollback to the pre-$unset state) must not shadow it."""
        db = self.storage._getDb()
        function_id = self.storage.getFunctionsBySampleId(self.sample_entry.sample_id)[0].function_id
        fresh = self.storage.getFunctionById(function_id, with_xcfg=True).xcfg
        db.functions.update_one({"function_id": function_id}, {"$set": {"_xcfg": "{}"}})
        served = self.storage.getFunctionById(function_id, with_xcfg=True).xcfg
        self.assertEqual(fresh, served)

    def testDroppedDisassemblyReadsAsEmptyDictNotNone(self):
        # None means "not requested", {} means "dropped" - the distinction the pre-split code
        # preserved by blanking the field in place instead of removing it
        function_id = self.storage.getFunctionsBySampleId(self.sample_entry.sample_id)[0].function_id
        self.storage.deleteXcfgForSampleId(self.sample_entry.sample_id)
        self.assertEqual(0, self.storage._getDb().xcfg.count_documents({}))
        self.assertEqual({}, self.storage.getFunctionById(function_id, with_xcfg=True).xcfg)

    def testDeleteXcfgDataDropsTheCollection(self):
        self.assertGreater(self.storage._getDb().xcfg.count_documents({}), 0)
        self.storage.deleteXcfgData()
        self.assertEqual(0, self.storage._getDb().xcfg.count_documents({}))

    def testDeleteSampleTakesItsBlobsWithIt(self):
        self.assertGreater(self.storage._getDb().xcfg.count_documents({}), 0)
        self.storage.deleteSample(self.sample_entry.sample_id)
        self.assertEqual(0, self.storage._getDb().functions.count_documents({}))
        self.assertEqual(0, self.storage._getDb().xcfg.count_documents({}))

    def testQueryFunctionsUseTheirOwnBlobCollection(self):
        report = SmdaReport.fromFile(self.example_file_path)
        report.sha256 = 64 * "e"
        query_entry = self.storage.addSmdaReport(report, isQuery=True)
        db = self.storage._getDb()
        self.assertGreater(db.query_xcfg.count_documents({}), 0)
        self.assertTrue(all(document["_id"] < 0 for document in db.query_xcfg.find({}, {"_id": 1})))
        query_function_id = self.storage.getFunctionsBySampleId(query_entry.sample_id)[0].function_id
        self.assertNotEqual({}, self.storage.getFunctionById(query_function_id, with_xcfg=True).xcfg)
        self.storage.deleteSample(query_entry.sample_id)
        self.assertEqual(0, db.query_xcfg.count_documents({}))


if __name__ == "__main__":
    main()
