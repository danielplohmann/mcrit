#!/usr/bin/python

import json
import logging
import os
import unittest

from smda.common.BinaryInfo import BinaryInfo
from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaReport import SmdaReport

from mcrit.config.McritConfig import McritConfig
from mcrit.config.MinHashConfig import MinHashConfig
from mcrit.config.QueueConfig import QueueConfig
from mcrit.config.ShinglerConfig import ShinglerConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.minhash.MinHasher import MinHasher
from mcrit.storage.StorageFactory import StorageFactory

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)

THIS_FILE_PATH = str(os.path.abspath(__file__))
PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
EXAMPLE_REPORT = os.sep.join([PROJECT_ROOT, "tests", "example_report.smda"])


def loadExampleReport():
    with open(EXAMPLE_REPORT) as handle:
        report = SmdaReport.fromDict(json.load(handle))
    assert report is not None, "example report failed to parse"
    return report


def buildMemoryStorage(min_instructions=10, min_blocks=0):
    config = McritConfig()
    config.STORAGE_CONFIG = StorageConfig(STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MEMORY)
    config.MINHASH_CONFIG = MinHashConfig()
    config.MINHASH_CONFIG.MINHASH_FN_MIN_INS = min_instructions
    config.MINHASH_CONFIG.MINHASH_FN_MIN_BLOCKS = min_blocks
    config.SHINGLER_CONFIG = ShinglerConfig()
    config.QUEUE_CONFIG = QueueConfig()
    return StorageFactory.getStorage(config), config


class HashableBySizeTestSuite(unittest.TestCase):
    """isHashableBySize has to agree with MinHasher.isMinHashableFunction, because it exists to let
    a caller skip work the hasher would discard anyway."""

    def testAgreesWithTheHasherOnRealFunctions(self):
        storage, config = buildMemoryStorage()
        hasher = MinHasher(config.MINHASH_CONFIG, config.SHINGLER_CONFIG)
        report = loadExampleReport()
        checked = 0
        for function in report.getFunctions():
            checked += 1
            self.assertEqual(
                hasher.isMinHashableFunction(function),
                storage.isHashableBySize(function.num_instructions, function.num_blocks),
                "disagreement on a function with %d instructions / %d blocks" % (function.num_instructions, function.num_blocks),
            )
        self.assertGreater(checked, 0)

    def testThresholdOfZeroDisablesItsClause(self):
        """A threshold of 0 is falsy and switches its clause off rather than meaning "no minimum" -
        the same quirk isMinHashableFunction has. With both at 0 nothing is hashable."""
        storage, _ = buildMemoryStorage(min_instructions=0, min_blocks=0)
        self.assertFalse(storage.isHashableBySize(1000, 1000))
        storage, _ = buildMemoryStorage(min_instructions=0, min_blocks=5)
        self.assertTrue(storage.isHashableBySize(1, 6))
        self.assertFalse(storage.isHashableBySize(1000, 5))

    def testEitherThresholdSuffices(self):
        storage, _ = buildMemoryStorage(min_instructions=10, min_blocks=5)
        self.assertTrue(storage.isHashableBySize(11, 1))
        self.assertTrue(storage.isHashableBySize(1, 6))
        self.assertFalse(storage.isHashableBySize(10, 5))


class UnhashedFunctionSelectionTestSuite(unittest.TestCase):
    """getUnhashedFunctions feeds minhash generation, so returning functions that can never be
    hashed makes every caller load their disassembly to rediscover that."""

    def setUp(self):
        self.storage, self.config = buildMemoryStorage()
        self.storage.addSmdaReport(loadExampleReport())

    def testSubThresholdFunctionsAreNotReturned(self):
        unhashed = self.storage.getUnhashedFunctions()
        self.assertTrue(unhashed)
        for entry in unhashed:
            self.assertTrue(
                self.storage.isHashableBySize(entry.num_instructions, entry.num_blocks),
                "returned a function of %d instructions, which can never be hashed" % entry.num_instructions,
            )

    def testTheCorpusActuallyContainsSubThresholdFunctions(self):
        """Otherwise the test above proves nothing."""
        every = [entry for _, entry in self.storage._functions.items()]
        too_small = [entry for entry in every if not self.storage.isHashableBySize(entry.num_instructions, entry.num_blocks)]
        self.assertTrue(too_small, "example report has no sub-threshold functions to exclude")
        returned_ids = {entry.function_id for entry in self.storage.getUnhashedFunctions()}
        for entry in too_small:
            self.assertNotIn(entry.function_id, returned_ids)

    def testOnlyFunctionIdsAgreesWithTheFullForm(self):
        ids = self.storage.getUnhashedFunctions(None, only_function_ids=True)
        entries = self.storage.getUnhashedFunctions()
        self.assertEqual(sorted(ids), sorted(entry.function_id for entry in entries))
        self.assertTrue(all(isinstance(function_id, int) for function_id in ids))

    def testFilteringByFunctionIdsStillAppliesTheSizeFilter(self):
        every_id = [entry.function_id for _, entry in self.storage._functions.items()]
        selected = self.storage.getUnhashedFunctions(every_id)
        for entry in selected:
            self.assertTrue(self.storage.isHashableBySize(entry.num_instructions, entry.num_blocks))

    def testHashedFunctionsAreNotReturned(self):
        hasher = MinHasher(self.config.MINHASH_CONFIG, self.config.SHINGLER_CONFIG)
        unhashed = self.storage.getUnhashedFunctions()
        self.assertTrue(unhashed)
        minhashes = []
        for entry in unhashed:
            binary_info = BinaryInfo(b"")
            binary_info.architecture = entry.architecture
            smda_function = SmdaFunction.fromDict(entry.xcfg, binary_info=binary_info)
            minhashes.append(hasher.calculateMinHashFromStorage((entry.function_id, smda_function)))
        self.storage.addMinHashes(minhashes)
        self.assertEqual([], self.storage.getUnhashedFunctions())


if __name__ == "__main__":
    unittest.main()
