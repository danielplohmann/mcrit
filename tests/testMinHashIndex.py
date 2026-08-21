#!/usr/bin/python

import logging
import unittest

from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.libs.utility import generate_unique_pairs
from mcrit.minhash.EscaperFingerprint import getEscaperFingerprint

from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class MinHashIndexTestSuite(unittest.TestCase):
    """Run a full example on a memory dump"""

    def testMinHashIndexInit(self):
        MinHashIndex(config)

    def testCandidatePairGenerator(self):
        test_data = [([], []), ([1, 2, 3, 4], [(1, 2), (1, 3), (1, 4), (2, 3), (2, 4), (3, 4)])]
        for data in test_data:
            generated_all_candidates = [pair for pair in generate_unique_pairs(data[0])]
            self.assertEqual(data[1], generated_all_candidates)


class EscaperProvenanceTestSuite(unittest.TestCase):
    """MinHashes are derived from smda's escaped instructions, so an export has to say which
    escaper produced them - otherwise incompatible signatures merge silently on import."""

    def testStatusReportsEscaperProvenance(self):
        index = MinHashIndex(config)
        status = index.getStatus(with_pichash=False)["status"]
        self.assertIn("smda_version", status)
        self.assertIn("escaper_fingerprint", status)
        self.assertEqual(getEscaperFingerprint(), status["escaper_fingerprint"])

    def testExportRecordsEscaperProvenance(self):
        index = MinHashIndex(config)
        export_config = index.getExportData()["config"]
        self.assertEqual(getEscaperFingerprint(), export_config["escaper"])
        self.assertIn("smda_version", export_config)

    def _minimalExport(self, index, **config_overrides):
        export_data = index.getExportData()
        export_data["config"].update(config_overrides)
        return export_data

    def testImportOfMatchingEscaperIsNotFlagged(self):
        index = MinHashIndex(config)
        report = index.addImportData(self._minimalExport(index))
        self.assertFalse(report["escaper_mismatch"])

    def testImportOfDifferingEscaperIsFlaggedButAccepted(self):
        index = MinHashIndex(config)
        report = index.addImportData(self._minimalExport(index, escaper="0000000000000000"))
        # the data is still imported: a given escaper change affects only a share of functions
        self.assertIsNotNone(report)
        self.assertTrue(report["escaper_mismatch"])

    def testImportOfLegacyExportWithoutEscaperIsNotFlagged(self):
        # exports predating this field carry no escaper information, so there is nothing to compare
        index = MinHashIndex(config)
        export_data = index.getExportData()
        del export_data["config"]["escaper"]
        report = index.addImportData(export_data)
        self.assertFalse(report["escaper_mismatch"])


if __name__ == "__main__":
    unittest.main()
