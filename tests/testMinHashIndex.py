#!/usr/bin/python

import logging
import os
import unittest

from smda.common.SmdaReport import SmdaReport

from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.index.SearchQueryParser import SearchQueryParser
from mcrit.libs.utility import generate_unique_pairs
from mcrit.minhash.EscaperFingerprint import getEscaperFingerprint

from .context import config

EXAMPLE_REPORT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "example_report.smda")

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


MALFORMED_QUERIES = ["foo)", "(foo", "a AND", "family:(foo"]


class MalformedSearchQueryTestSuite(unittest.TestCase):
    """A query the parser cannot read is bad input, not a server fault (#146)"""

    def testParserReportsMalformedQueryAsValueError(self):
        parser = SearchQueryParser()
        for query in MALFORMED_QUERIES:
            with self.subTest(query=query):
                with self.assertRaises(ValueError) as context:
                    parser.parse(query)
                # pyparsing names the offending position, which is worth passing on to the user
                self.assertIn("char", str(context.exception))

    def testSearchResultsRejectMalformedQuery(self):
        index = MinHashIndex(config)
        searches = [index.getFamilySearchResults, index.getSampleSearchResults, index.getFunctionSearchResults]
        for search in searches:
            for query in MALFORMED_QUERIES:
                with self.subTest(search=search.__name__, query=query):
                    # ValueError is what StatusResource._respond_search answers with a 400
                    with self.assertRaises(ValueError):
                        search(query)

    def testWellFormedQueryStillSearches(self):
        index = MinHashIndex(config)
        self.assertIn("search_results", index.getFamilySearchResults("foo"))
        self.assertIn("search_results", index.getSampleSearchResults("family:foo"))
        self.assertIn("search_results", index.getFunctionSearchResults("offset:>0x100"))


class UniqueBlocksCoverTestSuite(unittest.TestCase):
    """yara_covers used to be written once as 0 and never assigned again (#144)"""

    def testYaraCoversReportsTheAchievedCover(self):
        index = MinHashIndex(config)
        worker = index.queue._worker
        report = SmdaReport.fromFile(EXAMPLE_REPORT)
        assert report is not None
        sample_entry = index._storage.addSmdaReport(report)
        assert sample_entry is not None

        result = worker.getUniqueBlocks([sample_entry.sample_id])
        statistics = result["statistics"]
        # the only sample in storage owns every block, so the greedy cover reaches the full k of 10
        self.assertTrue(statistics["has_yara_rule"])
        self.assertTrue(statistics["has_complete_yara_rule"])
        self.assertEqual(1, statistics["num_samples_covered"])
        self.assertEqual(10, statistics["yara_covers"])
        self.assertEqual(len(result["yara_rule"]), statistics["yara_covers"])

    def testCoversRequiredShapesTheRule(self):
        index = MinHashIndex(config)
        worker = index.queue._worker
        report = SmdaReport.fromFile(EXAMPLE_REPORT)
        assert report is not None
        sample_entry = index._storage.addSmdaReport(report)
        assert sample_entry is not None

        # k of the k-of-n cover: with one sample in storage, every selected block covers it once,
        # so the rule is exactly k blocks long and the achieved cover equals what was asked for
        for covers_required in (1, 3, 10):
            with self.subTest(covers_required=covers_required):
                result = worker.getUniqueBlocks([sample_entry.sample_id], covers_required=covers_required)
                self.assertEqual(covers_required, result["statistics"]["covers_required"])
                self.assertEqual(covers_required, result["statistics"]["yara_covers"])
                self.assertEqual(covers_required, len(result["yara_rule"]))
                self.assertTrue(result["statistics"]["has_complete_yara_rule"])

    def testMinInstructionsFiltersBeforeTheCoverIsChosen(self):
        index = MinHashIndex(config)
        worker = index.queue._worker
        report = SmdaReport.fromFile(EXAMPLE_REPORT)
        assert report is not None
        sample_entry = index._storage.addSmdaReport(report)
        assert sample_entry is not None

        unfiltered = worker.getUniqueBlocks([sample_entry.sample_id])
        self.assertEqual(0, unfiltered["statistics"]["min_instructions"])
        self.assertEqual(len(unfiltered["unique_blocks"]), unfiltered["statistics"]["blocks_considered"])

        min_instructions = 5
        filtered = worker.getUniqueBlocks([sample_entry.sample_id], min_instructions=min_instructions)
        self.assertEqual(min_instructions, filtered["statistics"]["min_instructions"])
        # the short blocks are gone from the result, not merely skipped by the selection
        self.assertLess(len(filtered["unique_blocks"]), len(unfiltered["unique_blocks"]))
        self.assertEqual(len(filtered["unique_blocks"]), filtered["statistics"]["blocks_considered"])
        for block in filtered["unique_blocks"].values():
            self.assertGreaterEqual(block["length"], min_instructions)
        # and the cover is chosen from the survivors only
        for block_hash in filtered["yara_rule"]:
            self.assertIn(block_hash, filtered["unique_blocks"])
        # the counts from the storage layer still describe everything that was found
        self.assertEqual(unfiltered["statistics"]["unique_blocks_overall"], filtered["statistics"]["unique_blocks_overall"])

    def testYaraCoversStaysZeroWithoutASample(self):
        index = MinHashIndex(config)
        worker = index.queue._worker
        result = worker.getUniqueBlocks([])
        self.assertEqual(0, result["statistics"]["yara_covers"])
        self.assertFalse(result["statistics"]["has_yara_rule"])


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
        # persisted per architecture, so widening the probe later cannot invalidate exports
        # that are already in the wild (mcrit/minhash/EscaperFingerprint.py)
        self.assertEqual({"intel": getEscaperFingerprint()}, export_config["escaper"])
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
        report = index.addImportData(self._minimalExport(index, escaper={"intel": "0000000000000000"}))
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

    def testImportComparingOnlySharedArchitectures(self):
        """An export carrying an architecture this instance does not probe must not flip the
        flag for the architecture it does carry - intersection semantics, not equality."""
        index = MinHashIndex(config)
        export_data = self._minimalExport(index, escaper={"intel": getEscaperFingerprint(), "aarch64": "deadbeefdeadbeef"})
        report = index.addImportData(export_data)
        self.assertFalse(report["escaper_mismatch"])

    def testImportOfPartiallyDifferingEscaperFlagsOnlyTheMismatch(self):
        index = MinHashIndex(config)
        export_data = self._minimalExport(index, escaper={"intel": "0000000000000000", "aarch64": getEscaperFingerprint()})
        report = index.addImportData(export_data)
        self.assertIsNotNone(report)
        self.assertTrue(report["escaper_mismatch"])

    def testImportWithNoComparableArchitectureIsNotFlagged(self):
        """Nothing shared means nothing comparable - a skip with a warning, not a mismatch."""
        index = MinHashIndex(config)
        report = index.addImportData(self._minimalExport(index, escaper={"aarch64": "deadbeefdeadbeef"}))
        self.assertFalse(report["escaper_mismatch"])


if __name__ == "__main__":
    unittest.main()
