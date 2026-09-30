import os
import unittest
from unittest.mock import patch

import pymongo
import pytest
from picblocks.blockhasher import BlockHasher
from smda.common.SmdaReport import SmdaReport
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper
from smda.SmdaConfig import SmdaConfig

from mcrit.config.McritConfig import McritConfig
from mcrit.config.QueueConfig import QueueConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.queue.QueueFactory import QueueFactory
from mcrit.storage.MongoDbStorage import PICBLOCKS_VERSION
from mcrit.storage.StorageFactory import StorageFactory

from .context import getTestMongoServerAndPort

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
DB_NAME = "test_pichash_recalculation_stamp"
# the smda that disassembled crossarch_intel_a.smda, older than the escaper compatibility threshold
OLD_SMDA_VERSION = "1.5.12"


@pytest.mark.mongo
class PicHashRecalculationStampTest(unittest.TestCase):
    """recalculatePicHashes records every sample it rehashed, so a second run has nothing left to pick (#249)."""

    def setUp(self):
        server, port = getTestMongoServerAndPort()
        self.addCleanup(lambda: pymongo.MongoClient(server, int(port)).drop_database(DB_NAME))
        config = McritConfig()
        config.STORAGE_CONFIG = StorageConfig(STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MONGODB, STORAGE_SERVER=server, STORAGE_PORT=port, STORAGE_MONGODB_DBNAME=DB_NAME)
        config.QUEUE_CONFIG = QueueConfig(QUEUE_METHOD=QueueFactory.QUEUE_METHOD_FAKE)
        self.index = MinHashIndex(config=config)
        self.storage = self.index._storage
        self.storage.clearStorage()
        self.samples = self.storage._database.samples
        self.functions = self.storage._database.functions

    def _load(self, name):
        report = SmdaReport.fromFile(os.path.join(FIXTURES, name))
        assert report is not None
        return report

    def _add(self, name):
        """A sample as stored before #249: no record of the smda its PicHashes were computed with."""
        entry = self.storage.addSmdaReport(self._load(name))
        self.samples.update_one({"sample_id": entry.sample_id}, {"$unset": {"pichash_smda_version": ""}})
        return entry

    def _recalculate(self):
        return self.index.queue._worker.recalculatePicHashes()

    def _stale_count(self):
        return self.index.getStatus()["status"]["num_samples_with_stale_pichashes"]

    def _sample(self, sample_id):
        return self.samples.find_one({"sample_id": sample_id})

    def test_an_unchanged_sample_is_not_picked_again(self):
        entry = self._add("crossarch_intel_a.smda")
        self.assertEqual(OLD_SMDA_VERSION, self._sample(entry.sample_id)["smda_version"])

        first = self._recalculate()
        second = self._recalculate()

        self.assertEqual(1, first["outdated_samples"])
        self.assertEqual(0, first["functions_updated"])
        self.assertEqual(0, second["outdated_samples"])
        self.assertEqual(SmdaConfig().VERSION, self._sample(entry.sample_id)["pichash_smda_version"])

    def test_a_freshly_added_sample_is_current(self):
        entry = self.storage.addSmdaReport(self._load("crossarch_intel_a.smda"))
        self.assertEqual(SmdaConfig().VERSION, self._sample(entry.sample_id)["pichash_smda_version"])
        self.assertEqual(0, self._stale_count())
        self.assertEqual(0, self._recalculate()["outdated_samples"])

    def test_a_sample_without_a_report_version_is_picked_once(self):
        entry = self._add("crossarch_intel_a.smda")
        self.samples.update_one({"sample_id": entry.sample_id}, {"$unset": {"smda_version": ""}})

        first = self._recalculate()
        second = self._recalculate()

        self.assertEqual(1, first["outdated_samples"])
        self.assertEqual(SmdaConfig().VERSION, self._sample(entry.sample_id)["pichash_smda_version"])
        self.assertEqual(0, second["outdated_samples"])

    def test_status_counts_a_sample_until_it_was_rehashed(self):
        self._add("crossarch_intel_a.smda")
        self.assertEqual(1, self._stale_count())
        self._recalculate()
        self.assertEqual(0, self._stale_count())

    def test_a_changed_sample_is_stamped_and_keeps_its_report_version(self):
        entry = self._add("crossarch_intel_a.smda")
        function_id = self.functions.find_one({"sample_id": entry.sample_id}, sort=[("function_id", 1)])["function_id"]
        self.functions.update_one({"function_id": function_id}, {"$set": {"_pichash": hex(0x1234)}})

        first = self._recalculate()

        self.assertEqual(1, first["functions_updated"])
        self.assertNotEqual(hex(0x1234), self.functions.find_one({"function_id": function_id})["_pichash"])
        sample = self._sample(entry.sample_id)
        # smda_version keeps naming the smda that produced the report
        self.assertEqual(OLD_SMDA_VERSION, sample["smda_version"])
        self.assertEqual(SmdaConfig().VERSION, sample["pichash_smda_version"])
        self.assertEqual(0, self._stale_count())
        self.assertEqual(0, self._recalculate()["outdated_samples"])

    def test_a_sample_bumped_by_an_earlier_run_is_not_picked(self):
        # the old recalculation marked a changed sample done by overwriting its smda_version
        entry = self._add("crossarch_intel_a.smda")
        self.samples.update_one({"sample_id": entry.sample_id}, {"$set": {"smda_version": SmdaConfig().VERSION}})
        self.assertNotIn("pichash_smda_version", self._sample(entry.sample_id))
        self.assertEqual(0, self._stale_count())
        self.assertEqual(0, self._recalculate()["outdated_samples"])

    def test_a_mcrit4ida_report_version_is_compared_by_its_smda_version(self):
        old = self._add("crossarch_intel_a.smda")
        self.samples.update_one({"sample_id": old.sample_id}, {"$set": {"smda_version": f"MCRIT4IDA {OLD_SMDA_VERSION}"}})
        current = self._add("crossarch_aarch64_a.smda")
        self.samples.update_one({"sample_id": current.sample_id}, {"$set": {"smda_version": f"MCRIT4IDA {SmdaConfig().VERSION}"}})
        self.assertEqual(1, self._stale_count())

        self.assertEqual(1, self._recalculate()["outdated_samples"])

        self.assertEqual(SmdaConfig().VERSION, self._sample(old.sample_id)["pichash_smda_version"])
        self.assertNotIn("pichash_smda_version", self._sample(current.sample_id))
        self.assertEqual(0, self._stale_count())
        self.assertEqual(0, self._recalculate()["outdated_samples"])

    def test_a_sample_missing_disassembly_stays_pending_and_is_reported(self):
        entry = self._add("crossarch_intel_a.smda")
        function_id = self.functions.find_one({"sample_id": entry.sample_id}, sort=[("function_id", 1)])["function_id"]
        # a function whose disassembly is gone (e.g. dropped with STORAGE_DROP_DISASSEMBLY) cannot be rehashed
        self.storage._database.xcfg.delete_one({"_id": function_id})
        self.functions.update_one({"function_id": function_id}, {"$unset": {"_xcfg": ""}})

        result = self._recalculate()

        self.assertEqual(1, result["xcfg_missing"])
        self.assertEqual(1, result["samples_skipped_xcfg_missing"])
        self.assertNotIn("pichash_smda_version", self._sample(entry.sample_id))
        self.assertEqual(1, self._stale_count())
        self.assertEqual(1, self._recalculate()["samples_skipped_xcfg_missing"])

    def test_a_current_stamp_does_not_hide_stale_non_intel_block_hashes(self):
        # a non-Intel sample hashed before #240, whose PicHashes are otherwise current
        report = self._load("crossarch_aarch64_a.smda")
        with patch.object(BlockHasher, "_getInstructionEscaper", lambda self, block: IntelInstructionEscaper):
            entry = self.storage.addSmdaReport(report)
        self.samples.update_one(
            {"sample_id": entry.sample_id},
            {"$set": {"pichash_smda_version": SmdaConfig().VERSION}, "$unset": {"picblockhash_version": ""}},
        )
        self.assertEqual(0, self._stale_count())

        result = self._recalculate()

        self.assertEqual(1, result["outdated_samples"])
        self.assertEqual(1, result["stale_picblockhash_samples"])
        self.assertEqual(PICBLOCKS_VERSION, self._sample(entry.sample_id)["picblockhash_version"])
        self.assertEqual(0, self._recalculate()["outdated_samples"])


if __name__ == "__main__":
    unittest.main()
