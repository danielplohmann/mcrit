#!/usr/bin/python

import json
import logging
import os
import unittest
from copy import deepcopy

from smda.common.SmdaReport import SmdaReport

from mcrit.minhash.MinHash import MinHash
from mcrit.storage.FunctionEntry import FunctionEntry
from mcrit.storage.MatchingResult import MatchingResult
from mcrit.storage.SampleEntry import SampleEntry

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class MinHashingTestSuite(unittest.TestCase):
    """Run a full example on a memory dump"""

    def testFunctionEntry(self):
        THIS_FILE_PATH = str(os.path.abspath(__file__))
        PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
        example_file_path = os.sep.join([PROJECT_ROOT, "tests", "example_report.smda"])
        with open(example_file_path) as fjson:
            smda_json = json.load(fjson)

        smda_report = SmdaReport.fromDict(smda_json)
        sample_entry = SampleEntry(smda_report, sample_id=0, family_id=0)
        minhash = MinHash(function_id=1, minhash_signature=[0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39])
        for smda_function in smda_report.getFunctions():
            function_entry = FunctionEntry(sample_entry, smda_function, 0, minhash=minhash)

            as_dict = function_entry.toDict()
            as_entry = FunctionEntry.fromDict(as_dict)

            # test text-friendly encoding of binary pichashes
            self.assertEqual(as_entry.minhash, function_entry.minhash)

    def testSampleEntry(self):
        THIS_FILE_PATH = str(os.path.abspath(__file__))
        PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
        example_file_path = os.sep.join([PROJECT_ROOT, "tests", "example_report.smda"])
        with open(example_file_path) as fjson:
            smda_json = json.load(fjson)

        smda_report = SmdaReport.fromDict(smda_json)
        sample_entry = SampleEntry(smda_report, sample_id=0, family_id=0)

        as_dict = sample_entry.toDict()
        as_entry = SampleEntry.fromDict(as_dict)
        self.assertEqual(as_entry.sample_id, sample_entry.sample_id)

    def testMatchingResult(self):
        THIS_FILE_PATH = str(os.path.abspath(__file__))
        PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
        example_file_path = os.sep.join([PROJECT_ROOT, "tests", "example_matching_report.json"])
        with open(example_file_path) as fjson:
            match_json = json.load(fjson)
        matching_result = MatchingResult.fromDict(match_json)
        assert len(matching_result.sample_matches) == 2
        assert len(matching_result.getFunctionMatches()) == 719
        assert len(set([match.function_id for match in matching_result.getFunctionMatches()])) == 515
        ### test filtering
        # test filtering by family and sample counts
        filtered_result = deepcopy(matching_result)
        filtered_result.filterToFamilyCount(1)
        assert len(filtered_result.getFunctionMatches()) == 414
        assert len(filtered_result.getFunctionMatches(unfiltered=True)) == 719
        filtered_result = deepcopy(matching_result)
        filtered_result.filterToSampleCount(max_samples=1)
        assert len(filtered_result.getFunctionMatches()) == 414
        filtered_result.filterToSampleCount(min_samples=2)
        assert len(filtered_result.getFunctionMatches()) == 0
        # filter by score / library
        filtered_result = deepcopy(matching_result)
        filtered_result.filterToFunctionScore(95)
        assert len(filtered_result.getFunctionMatches()) == 581
        filtered_result = deepcopy(matching_result)
        filtered_result.filterToFunctionScore(min_score=95, library_only=True)
        assert len(filtered_result.getFunctionMatches()) == 718
        filtered_result = deepcopy(matching_result)
        filtered_result.excludeLibraryMatches()
        assert len(filtered_result.getFunctionMatches()) == 715
        assert len(set([match.function_id for match in filtered_result.getFunctionMatches()])) == 513

    def testMatchingResultLazyFiltering(self):
        """The filtered_* lists are derived lazily and can be reset, so that a MatchingResult
        may be reused across several independent filter runs (e.g. from a cache)."""
        THIS_FILE_PATH = str(os.path.abspath(__file__))
        PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
        example_file_path = os.sep.join([PROJECT_ROOT, "tests", "example_matching_report.json"])
        with open(example_file_path) as fjson:
            match_json = json.load(fjson)

        # fromDict must not materialize the filtered_* lists up front
        matching_result = MatchingResult.fromDict(match_json)
        assert matching_result._filtered_function_matches is None
        assert matching_result._filtered_sample_matches is None

        # ... but reading them yields the full, unfiltered set
        assert len(matching_result.filtered_function_matches) == 719
        assert len(matching_result.filtered_sample_matches) == 2
        assert matching_result._filtered_function_matches is not None

        # the lazy copy is shallow: entries are shared, the list itself is not
        assert matching_result.filtered_function_matches is not matching_result.function_matches
        assert matching_result.filtered_function_matches[0] is matching_result.function_matches[0]

        # filtering rebinds the filtered list and must leave the originals untouched
        matching_result.filterToFamilyCount(1)
        assert len(matching_result.getFunctionMatches()) == 414
        assert len(matching_result.function_matches) == 719
        assert len(matching_result.getFunctionMatches(unfiltered=True)) == 719

        # resetFilters() restores the unfiltered view, so filters do not accumulate
        matching_result.resetFilters()
        assert len(matching_result.getFunctionMatches()) == 719
        assert len(matching_result.filtered_sample_matches) == 2

        # a second, independent filter run on the same object yields the same result as the
        # first - this is what makes caching a parsed MatchingResult safe
        matching_result.filterToFamilyCount(1)
        assert len(matching_result.getFunctionMatches()) == 414

        # without a reset, applyFilterValues-style filtering is cumulative (documented behaviour)
        matching_result.resetFilters()
        matching_result.filterToSampleCount(max_samples=1)
        assert len(matching_result.getFunctionMatches()) == 414
        matching_result.filterToSampleCount(min_samples=2)
        assert len(matching_result.getFunctionMatches()) == 0

    def testMatchingResultLinkHuntDoesNotLeakIntoWireFormat(self):
        """getLinkHuntResults writes matched_family / matched_link_score / matched_unique onto
        the original entries, which the filtered_* lists now share. Those fields are additive
        only and must stay absent from the serialized form."""
        THIS_FILE_PATH = str(os.path.abspath(__file__))
        PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
        example_file_path = os.sep.join([PROJECT_ROOT, "tests", "example_matching_report.json"])
        with open(example_file_path) as fjson:
            match_json = json.load(fjson)

        matching_result = MatchingResult.fromDict(match_json)
        before = matching_result.toDict()

        link_hunt_result = matching_result.getLinkHuntResults(min_score=50)
        assert len(link_hunt_result) > 0
        # the link-hunt specific fields have indeed been populated on shared entries
        assert any(match.matched_link_score > 0 for match in link_hunt_result)

        # ... yet the serialized report is byte-identical, and the counts are unchanged
        assert matching_result.toDict() == before
        assert len(matching_result.function_matches) == 719
        assert len(matching_result.filtered_function_matches) == 719


if __name__ == "__main__":
    unittest.main()
