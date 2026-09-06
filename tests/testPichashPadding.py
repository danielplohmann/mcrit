import json
import logging
import os
from unittest import TestCase

import pymongo
import pytest
from smda.common.SmdaReport import SmdaReport

from mcrit.config.McritConfig import McritConfig
from mcrit.config.MinHashConfig import MinHashConfig
from mcrit.config.QueueConfig import QueueConfig
from mcrit.config.ShinglerConfig import ShinglerConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.index.SearchCursor import FullSearchCursor, MinimalSearchCursor
from mcrit.index.SearchQueryParser import SearchQueryParser
from mcrit.migrations import migrate_pichash_padding
from mcrit.storage.MongoDbStorage import PICHASH_HEX_DIGITS, encode_pichash_value
from mcrit.storage.StorageFactory import StorageFactory

from .context import getTestMongoServerAndPort

logging.disable(logging.CRITICAL)

THIS_FILE_PATH = str(os.path.abspath(__file__))
PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
EXAMPLE_REPORT = os.sep.join([PROJECT_ROOT, "tests", "example_report.smda"])
DB_NAME = "test_pichash_padding_mcrit"


def build_config():
    server, port = getTestMongoServerAndPort()
    mcrit_config = McritConfig()
    mcrit_config.STORAGE_CONFIG = StorageConfig(
        STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MONGODB,
        STORAGE_SERVER=server,
        STORAGE_PORT=port,
        STORAGE_MONGODB_DBNAME=DB_NAME,
        STORAGE_DROP_DISASSEMBLY=False,
    )
    mcrit_config.MINHASH_CONFIG = MinHashConfig()
    mcrit_config.MINHASH_CONFIG.MINHASH_SIGNATURE_LENGTH = 10
    mcrit_config.MINHASH_CONFIG.MINHASH_SIGNATURE_BITS = 8
    mcrit_config.SHINGLER_CONFIG = ShinglerConfig()
    mcrit_config.QUEUE_CONFIG = QueueConfig()
    return mcrit_config


def is_padded(value):
    return isinstance(value, str) and value.startswith("0x") and len(value) == 2 + PICHASH_HEX_DIGITS


def short_form(value):
    """The pre-#145 encoding; identical to the padded one unless the value has a leading zero."""
    return hex(int(value, 16))


@pytest.mark.mongo
class PichashPaddingTest(TestCase):
    """#145: pichashes are stored 16 digits wide so that their hex order is their numeric order"""

    def setUp(self):
        server, port = getTestMongoServerAndPort()
        self.client = pymongo.MongoClient(server, int(port))
        # a dropped database makes the storage create its settings from scratch: a fresh instance
        self.client.drop_database(DB_NAME)
        self.db = self.client[DB_NAME]
        self.config = build_config()
        self.storage = StorageFactory.getStorage(self.config)
        with open(EXAMPLE_REPORT) as fjson:
            report = SmdaReport.fromDict(json.load(fjson))
        assert report is not None
        sample_entry = self.storage.addSmdaReport(report)
        assert sample_entry is not None
        self.sample_id = sample_entry.sample_id
        # the example report's pichashes all use 16 digits; give two of them leading zeros so
        # that the two encodings differ for pichashes as well as for block hashes
        first, second = [d["function_id"] for d in self.db.functions.find({}, {"function_id": 1}).sort("function_id", 1).limit(2)]
        self.db.functions.update_one({"function_id": first}, {"$set": {"_pichash": encode_pichash_value(0x4D2, padded=True)}})
        self.db.functions.update_one({"function_id": second}, {"$set": {"_pichash": encode_pichash_value(0x99, padded=True)}})
        self.functions = list(self.db.functions.find({}, {"_id": 0, "function_id": 1, "_pichash": 1, "_picblockhashes": 1}))
        self.assertGreaterEqual(len(self.functions), 10)
        # the documents whose values differ between the two encodings (a leading zero somewhere)
        self.differing = [d for d in self.functions if short_form(d["_pichash"]) != d["_pichash"] or any(short_form(e["hash"]) != e["hash"] for e in d.get("_picblockhashes", []))]
        self.assertGreater(len(self.differing), 0)
        self.assertLess(len(self.differing), len(self.functions))

    def tearDown(self):
        self.client.drop_database(DB_NAME)

    def _stored_pichashes(self):
        return [document["_pichash"] for document in self.db.functions.find({}, {"_pichash": 1})]

    def _stored_blockhashes(self):
        return [entry["hash"] for document in self.db.functions.find({}, {"_picblockhashes": 1}) for entry in document.get("_picblockhashes", [])]

    def _make_legacy(self):
        """Turn the instance into one created before #145: unpadded values, flag unset."""
        migrate_pichash_padding.run(self.db, "unpad")
        self.storage._pichash_padded = None

    def test_a_fresh_instance_stores_padded_values_and_says_so(self):
        settings = self.db.settings.find_one({})
        assert settings is not None
        self.assertTrue(settings["pichash_padded"])
        self.assertTrue(self.storage.isPichashPadded())
        self.assertTrue(self.storage.getStats(with_pichash=False)["pichash_padded"])
        self.assertTrue(all(is_padded(value) for value in self._stored_pichashes()))
        self.assertGreater(len(self._stored_blockhashes()), 0)
        self.assertTrue(all(is_padded(value) for value in self._stored_blockhashes()))
        self.assertTrue(MinHashIndex(self.config).getStatus(with_pichash=False)["status"]["pichash_padded"])

    def test_lookups_by_value_work_on_both_shapes(self):
        function_entries = self.storage.getFunctionsBySampleId(self.sample_id)
        with_blocks = next(fe for fe in function_entries if fe.picblockhashes)
        for legacy in (False, True):
            if legacy:
                self._make_legacy()
                self.assertFalse(self.storage.isPichashPadded())
                self.assertTrue(all(value == short_form(value) for value in self._stored_pichashes()))
            for function_entry in function_entries:
                self.assertTrue(self.storage.isPicHash(function_entry.pichash), (legacy, function_entry.function_id))
                self.assertIn((function_entry.family_id, self.sample_id, function_entry.function_id), self.storage.getMatchesForPicHash(function_entry.pichash))
                self.assertEqual(
                    {function_entry.pichash: {(function_entry.family_id, self.sample_id, function_entry.function_id)}},
                    self.storage.getPicHashMatchesByFunctionId(function_entry.function_id),
                )
            block = with_blocks.picblockhashes[0]
            self.assertIn((with_blocks.family_id, self.sample_id, with_blocks.function_id, block["offset"]), self.storage.getMatchesForPicBlockHash(block["hash"]))
            self.assertFalse(self.storage.isPicHash(0x1234567))
            self.assertEqual(set(), self.storage.getMatchesForPicHash(0x1234567))

    def test_the_aggregation_readers_see_both_widths_while_unpadded(self):
        """getPicHashMatchesByFunctionId(s) group functions by equal pichash; during a migration
        the same value may be stored in either width and must still land in one group"""
        self._make_legacy()
        first, second = self.differing[0]["function_id"], self.differing[1]["function_id"]
        # give both functions the same pichash, one in each width
        value = 0x4D2
        self.db.functions.update_one({"function_id": first}, {"$set": {"_pichash": hex(value)}})
        self.db.functions.update_one({"function_id": second}, {"$set": {"_pichash": encode_pichash_value(value, padded=True)}})
        by_one = self.storage.getPicHashMatchesByFunctionId(first)
        self.assertEqual({first, second}, {t[2] for t in by_one[value]})
        by_many = self.storage.getPicHashMatchesByFunctionIds([first, second])
        self.assertEqual({first, second}, {t[2] for t in by_many[value]})
        self.assertEqual(1, len(by_many))

    def test_the_migration_connects_with_the_configured_credentials(self):
        self.assertEqual("mongodb://h:27017/db", migrate_pichash_padding.build_mongo_uri("h", 27017, "db", None, None, ""))
        self.assertEqual(
            "mongodb://u%40x:p%3Aw@h:27017/db?authSource=admin&tls=true", migrate_pichash_padding.build_mongo_uri("h", 27017, "db", "u@x", "p:w", "authSource=admin&tls=true")
        )

    def test_a_legacy_instance_in_the_middle_of_a_migration_misses_nothing(self):
        self._make_legacy()
        # half the documents padded by hand: a `pad` run that was interrupted before the flag
        # one of the two leading-zero pichashes padded, the other still short
        rewritten = [d for d in self.differing if short_form(d["_pichash"]) != d["_pichash"]][:1]
        for document in rewritten:
            self.db.functions.update_one({"function_id": document["function_id"]}, {"$set": {"_pichash": encode_pichash_value(int(document["_pichash"], 16), padded=True)}})
        stored = self._stored_pichashes()
        self.assertTrue(any(value != short_form(value) for value in stored))
        self.assertTrue(any(value == short_form(value) and not is_padded(value) for value in stored))
        parser = SearchQueryParser()
        for function_entry in self.storage.getFunctionsBySampleId(self.sample_id):
            self.assertTrue(self.storage.isPicHash(function_entry.pichash))
            found = self.storage.findFunctionByString(parser.parse("pichash:%s" % hex(function_entry.pichash)))
            self.assertIn(function_entry.function_id, found)
        # ... but the answers that would be wrong on mixed widths stay refused
        with self.assertRaises(ValueError):
            self.storage.findFunctionByString(parser.parse("pichash:>0x10"))
        with self.assertRaises(ValueError):
            self.storage.findFunctionByString(parser.parse("function_id:>0"), cursor=FullSearchCursor(None, [("pichash", True), ("function_id", True)]))

    def test_range_conditions_answer_the_numeric_set_when_padded(self):
        parser = SearchQueryParser()
        pichashes = {document["function_id"]: int(document["_pichash"], 16) for document in self.functions}
        pivot = sorted(pichashes.values())[len(pichashes) // 2]
        expected_below = {function_id for function_id, pichash in pichashes.items() if pichash < pivot}
        self.assertGreater(len(expected_below), 0)
        found = self.storage.findFunctionByString(parser.parse("pichash:<%s" % hex(pivot)), max_num_results=1000)
        self.assertEqual(expected_below, set(found))
        # a small bound that variable-width strings would have ordered a wrong set for
        self.assertEqual(set(), set(self.storage.findFunctionByString(parser.parse("pichash:<0x99"), max_num_results=1000)))
        self.assertEqual(set(pichashes), set(self.storage.findFunctionByString(parser.parse("pichash:>=0x0"), max_num_results=1000)))

    def test_a_pichash_sorted_function_search_pages_in_numeric_order(self):
        index = MinHashIndex(self.config)
        expected = [document["function_id"] for document in sorted(self.functions, key=lambda d: (int(d["_pichash"], 16), d["function_id"]))]
        pages = []
        cursor = None
        for _ in range(100):
            result = index.getFunctionSearchResults("function_id:>=0", sort_by="pichash", is_ascending=True, cursor=cursor, limit=4)
            page = [entry["function_id"] for entry in result["search_results"].values()]
            self.assertLessEqual(len(page), 4)
            pages.append(page)
            cursor = result["cursor"]["forward"]
            if cursor is None:
                break
        self.assertEqual(expected, [function_id for page in pages for function_id in page])
        self.assertGreater(len(pages), 2)
        # the backward cursor of the last page reproduces the page before it
        last_backward = MinimalSearchCursor.fromStr(result["cursor"]["backward"])
        self.assertFalse(last_backward.is_forward_search)
        previous = index.getFunctionSearchResults("function_id:>=0", sort_by="pichash", is_ascending=True, cursor=result["cursor"]["backward"], limit=4)
        self.assertEqual(pages[-2], [entry["function_id"] for entry in previous["search_results"].values()])
        # descending order is the reverse walk
        descending = index.getFunctionSearchResults("function_id:>=0", sort_by="pichash", is_ascending=False, limit=1000)
        self.assertEqual(list(reversed(expected)), [entry["function_id"] for entry in descending["search_results"].values()])

    def test_the_migration_round_trips_and_verify_spots_leftovers(self):
        report = migrate_pichash_padding.run(self.db, "verify")
        self.assertTrue(report["pichash_padded"])
        self.assertEqual([], report["problems"])
        self.assertEqual(0, report["collections"]["functions"]["unpadded_pichashes"])
        # rollback
        report = migrate_pichash_padding.run(self.db, "unpad")
        self.assertFalse(report["pichash_padded"])
        self.assertEqual([], report["problems"])
        self.assertEqual(len(self.differing), report["functions"]["rewritten"])
        self.assertTrue(all(value == short_form(value) for value in self._stored_pichashes() + self._stored_blockhashes()))
        self.assertEqual([short_form(document["_pichash"]) for document in self.functions], self._stored_pichashes())
        # migrate: every value padded, flag set, values unchanged
        report = migrate_pichash_padding.run(self.db, "pad", batch_size=5)
        self.assertTrue(report["pichash_padded"])
        self.assertEqual([], report["problems"])
        self.assertEqual(len(self.differing), report["functions"]["rewritten"])
        self.assertTrue(all(is_padded(value) for value in self._stored_pichashes() + self._stored_blockhashes()))
        self.assertEqual(
            {document["function_id"]: document["_pichash"] for document in self.functions},
            {document["function_id"]: document["_pichash"] for document in self.db.functions.find({}, {"function_id": 1, "_pichash": 1})},
        )
        self.assertEqual(
            {document["function_id"]: document.get("_picblockhashes") for document in self.functions},
            {document["function_id"]: document.get("_picblockhashes") for document in self.db.functions.find({}, {"function_id": 1, "_picblockhashes": 1})},
        )
        # re-running is a no-op
        report = migrate_pichash_padding.run(self.db, "pad")
        self.assertEqual(0, report["functions"]["rewritten"] + report["functions"]["swept"])
        # a value a still-running server wrote unpadded after the flag: verify names it, pad sweeps it
        leading_zero = next(d for d in self.differing if short_form(d["_pichash"]) != d["_pichash"])
        self.db.functions.update_one({"function_id": leading_zero["function_id"]}, {"$set": {"_pichash": short_form(leading_zero["_pichash"])}})
        report = migrate_pichash_padding.run(self.db, "verify")
        self.assertEqual(1, len(report["problems"]))
        self.assertEqual(1, report["collections"]["functions"]["unpadded_pichashes"])
        report = migrate_pichash_padding.run(self.db, "pad")
        self.assertEqual([], report["problems"])
        self.assertEqual(1, report["functions"]["rewritten"] + report["functions"]["swept"])

    def test_the_command_line_entry_point(self):
        server, port = getTestMongoServerAndPort()
        self.assertEqual(0, migrate_pichash_padding.main(["--mode", "verify", "--host", server, "--port", str(port), "--db", DB_NAME]))
        self.db.settings.update_one({}, {"$set": {"pichash_padded": True}})
        self.db.functions.update_one({"function_id": self.functions[0]["function_id"]}, {"$set": {"_pichash": "0x1"}})
        self.assertEqual(1, migrate_pichash_padding.main(["--mode", "verify", "--host", server, "--port", str(port), "--db", DB_NAME]))
