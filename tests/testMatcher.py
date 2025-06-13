#!/usr/bin/python

import json
import logging
import os
import unittest
from copy import deepcopy
from unittest.mock import MagicMock

from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.matchers.MatcherInterface import IS_LIBRARY_FLAG, IS_MINHASH_FLAG, IS_PICHASH_FLAG
from mcrit.matchers.MatcherQuery import MatcherQuery
from mcrit.matchers.MatcherSample import MatcherSample

# from mcrit.storage.MemoryStorage import MemoryStorage
from mcrit.matchers.MatcherVs import MatcherVs
from mcrit.storage.SampleEntry import SampleEntry
from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaReport import SmdaReport

from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class MatcherTestSuite(unittest.TestCase):
    """Run a full example on a memory dump"""

    # pichash_expected = {'pichash_summary': {'num_own_functions_matched': 0, 'num_foreign_functions_matched': 0, 'num_own_functions_matched_as_library': 0, 'num_self_matches': 0, 'bytes_matched': 0}, 'pichash_matches': {}}

    def __init__(self, *args, **kwargs):
        super(MatcherTestSuite, self).__init__(*args, **kwargs)

        THIS_FILE_PATH = str(os.path.abspath(__file__))
        PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
        example_file_path_1 = os.sep.join([PROJECT_ROOT, "tests", "example_report.smda"])
        example_file_path_2 = os.sep.join([PROJECT_ROOT, "tests", "example_report_2.smda"])
        example_file_path_3 = os.sep.join([PROJECT_ROOT, "tests", "example_report_3.smda"])
        library_file_path = os.sep.join([PROJECT_ROOT, "tests", "library_report.smda"])
        self.smda_report_1 = SmdaReport.fromFile(example_file_path_1)
        self.smda_report_2 = SmdaReport.fromFile(example_file_path_2)
        self.smda_report_2.family = "test_family"
        self.smda_report_3 = SmdaReport.fromFile(example_file_path_3)
        self.smda_report_3.family = "test_family_b"
        self.library_report = SmdaReport.fromFile(library_file_path)

        function_1_selected = list(self.smda_report_1.getFunctions())[3]
        function_2_selected = list(self.smda_report_2.getFunctions())[5]
        offset = function_2_selected.offset
        # self.smda_report_2.xcfg[offset] = function_1_selected
        function_2_selected.pic_hash = function_1_selected.pic_hash

        # make a selfmatch
        self.smda_report_1.xcfg[list(self.smda_report_1.getFunctions())[1].offset] = list(
            self.smda_report_1.getFunctions()
        )[5]

    # from matchervs
    function_matches_expected = [
        {
            "fid": 9,
            "matches": [
                (0, 2, 19, 100.0, IS_MINHASH_FLAG + IS_PICHASH_FLAG + IS_LIBRARY_FLAG),
                (1, 0, 0, 84.375, IS_MINHASH_FLAG),
                (2, 3, 22, 84.375, IS_MINHASH_FLAG),
            ],
            "num_bytes": 354.0,
            "num_instructions": 120,
            "offset": 0,
        },
        {
                "num_bytes": 35.0,
                "num_instructions": 11,
                "offset": 2220,
                "matches": [],
                "fid": 10
        },
        {
            "fid": 11,
            "matches": [
                (0, 2, 20, 100.0, IS_MINHASH_FLAG + IS_PICHASH_FLAG + IS_LIBRARY_FLAG),
                (1, 0, 1, 92.1875, IS_MINHASH_FLAG),
            ],
            "num_bytes": 638.0,
            "num_instructions": 207,
            "offset": 364,
        },
        {
            "fid": 12,
            "matches": [
                (0, 2, 21, 100.0, IS_MINHASH_FLAG + IS_PICHASH_FLAG + IS_LIBRARY_FLAG),
                (1, 0, 5, 100.0, IS_MINHASH_FLAG + IS_PICHASH_FLAG)
            ],
            "num_bytes": 166.0,
            "num_instructions": 64,
            "offset": 1004,
        },
        {
            "fid": 13,
            "matches": [(1, 0, 3, 67.1875, IS_MINHASH_FLAG)],
            "num_bytes": 1047.0,
            "num_instructions": 365,
            "offset": 1172,
        },
        {
            "num_bytes": 35.0,
            "num_instructions": 11,
            "offset": 2220,
            "matches": [],
            "fid": 14
        },
        {
            "num_bytes": 524.0,
            "num_instructions": 159,
            "offset": 2256,
            "matches": [],
            "fid": 15
        },
        {
            "fid": 16,
            "matches": [(1, 0, 5, 84.375, IS_MINHASH_FLAG)],
            "num_bytes": 915.0,
            "num_instructions": 287,
            "offset": 2780,
        },
        {
            "fid": 17,
            "matches": [(1, 0, 6, 98.4375, IS_MINHASH_FLAG)],
            "num_bytes": 727.0,
            "num_instructions": 226,
            "offset": 3696,
        },
        {
            "fid": 18,
            "matches": [(1, 0, 7, 67.1875, IS_MINHASH_FLAG)],
            "num_bytes": 1850.0,
            "num_instructions": 543,
            "offset": 4424,
        },
    ]

    function_matches_expected_vs = [
        {
            "fid": 9,
            "matches": [
                (1, 0, 0, 84.375, IS_MINHASH_FLAG),
            ],
            "num_bytes": 354.0,
            "num_instructions": 120,
            "offset": 0,
        },
        {
            "num_bytes": 35.0,
            "num_instructions": 11,
            "offset": 2220,
            "matches": [],
            "fid": 10
        },
        {
            "fid": 11,
            "matches": [
                (1, 0, 1, 92.1875, IS_MINHASH_FLAG),
            ],
            "num_bytes": 638.0,
            "num_instructions": 207,
            "offset": 364,
        },
        {
            "fid": 12,
            "matches": [
                (1, 0, 5, 100.0, IS_MINHASH_FLAG + IS_PICHASH_FLAG),
            ],
            "num_bytes": 166.0,
            "num_instructions": 64,
            "offset": 1004,
        },
        {
            "fid": 13,
            "matches": [(1, 0, 3, 67.1875, IS_MINHASH_FLAG)],
            "num_bytes": 1047.0,
            "num_instructions": 365,
            "offset": 1172,
        },
        {
            "num_bytes": 35.0,
            "num_instructions": 11,
            "offset": 2220,
            "matches": [],
            "fid": 14
        },
        {
            "num_bytes": 524.0,
            "num_instructions": 159,
            "offset": 2256,
            "matches": [],
            "fid": 15
        },
        {
            "fid": 16,
            "matches": [(1, 0, 5, 84.375, IS_MINHASH_FLAG)],
            "num_bytes": 915.0,
            "num_instructions": 287,
            "offset": 2780,
        },
        {
            "fid": 17,
            "matches": [(1, 0, 6, 98.4375, IS_MINHASH_FLAG)],
            "num_bytes": 727.0,
            "num_instructions": 226,
            "offset": 3696,
        },
        {
            "fid": 18,
            "matches": [(1, 0, 7, 67.1875, IS_MINHASH_FLAG)],
            "num_bytes": 1850.0,
            "num_instructions": 543,
            "offset": 4424,
        },
    ]

    minhash_aggregation_expected = {
        "num_own_functions_matched": 7,
        "num_foreign_functions_matched": 10,
        "num_own_functions_matched_as_library": 3,
        "num_self_matches": 2,
        "bytes_matched": 5697.0,
    }

    minhash_aggregation_expected_vs = {
        "num_own_functions_matched": 7,
        "num_foreign_functions_matched": 6,
        "num_own_functions_matched_as_library": 0,
        "num_self_matches": 2,
        "bytes_matched": 5697.0,
    }

    minhash_aggregation_expected_query = deepcopy(minhash_aggregation_expected)
    minhash_aggregation_expected_query["num_self_matches"] = 0

    pichash_aggregation_expected = {
        "num_own_functions_matched": 3,
        "num_foreign_functions_matched": 4,
        "num_own_functions_matched_as_library": 3,
        "num_self_matches": 2,
        "bytes_matched": 1158.0,
    }

    pichash_aggregation_expected_query = deepcopy(pichash_aggregation_expected)
    pichash_aggregation_expected_query["num_self_matches"] = 0

    pichash_aggregation_expected_vs = {
        "num_own_functions_matched": 1,
        "num_foreign_functions_matched": 1,
        "num_own_functions_matched_as_library": 0,
        "num_self_matches": 2,
        "bytes_matched": 166.0,
    }
    maxDiff = None
    # sample2
    # TODO mark s.th as library,
    # TODO make s.th a pic+min match
    sample_summary_entry_2_expected = {
        "sample_id": 0,
        "family": "test_family",
        "family_id": 1,
        "version": "",
        "bitness": 32,
        "sha256": "39401c7f9518f9710bfd6d64e13a5bf4efdec42e54c9de363b4871e8f374b579",
        "filename": "",
        "num_bytes": 6158.0,
        "num_functions": 9,
        'is_library': False,
        "matched": {
            "functions": {
                "combined": 7,
                "library": 3,
                "minhashes": 7,
                "pichashes": 1,
            },
            "bytes": {
                "unweighted": 5697.0,
                "score_weighted": 4486.9375,
                "frequency_weighted": 4337.59375,
                "nonlib_unweighted": 4539.0,
                "nonlib_score_weighted": 3434.09375,
                "nonlib_frequency_weighted": 3434.09375
            },
            "percent": {
                "unweighted": 90.55793991416309,
                "score_weighted": 71.32312033063106,
                "frequency_weighted": 68.94919329200445,
                "nonlib_unweighted": 88.42781998831093,
                "nonlib_score_weighted": 66.90227449834404,
                "nonlib_frequency_weighted": 66.90227449834404,
            },
        },
    }

    sample_summary_entry_3_expected = {
        "sample_id": 3,
        "family": "test_family_b",
        "family_id": 2,
        "version": "",
        "bitness": 32,
        "sha256": "39401c7f9518f9710bfd6d64e13a5bf4efdec42e54c9de363b4871e8f374b57f",
        "filename": "",
        "num_bytes": 351.0,
        "num_functions": 9,
        'is_library': False,
        "matched": {
            "functions": {
                "combined": 1,
                "library": 1,
                "minhashes": 1,
                "pichashes": 0,
            },
            "bytes": {
                "unweighted": 354.0,
                "score_weighted": 298.6875,
                "frequency_weighted": 149.34375,
                "nonlib_unweighted": 0,
                "nonlib_score_weighted": 0,
                "nonlib_frequency_weighted": 0
            },
            "percent": {
                "unweighted": 5.627086313781593,
                "score_weighted": 4.747854077253219,
                "frequency_weighted": 2.3739270386266096,
                "nonlib_unweighted": 0.0,
                "nonlib_score_weighted": 0.0,
                "nonlib_frequency_weighted": 0.0
            },
        },
    }

    sample_summary_entry_expected_vs = {
        "sample_id": 0,
        "family": "test_family",
        "family_id": 1,
        "version": "",
        "bitness": 32,
        "sha256": "39401c7f9518f9710bfd6d64e13a5bf4efdec42e54c9de363b4871e8f374b579",
        "filename": "",
        "num_bytes": 6158.0,
        "num_functions": 9,
        'is_library': False,
        "matched": {
            "functions": {
                "combined": 7,
                "library": 0,
                "minhashes": 7,
                "pichashes": 1,
            },
            "bytes": {
                "unweighted": 5697.0,
                "score_weighted": 4486.9375,
                "frequency_weighted": 4486.9375,
                "nonlib_unweighted": 5697.0,
                "nonlib_score_weighted": 4486.9375,
                "nonlib_frequency_weighted": 4486.9375
            },
            "percent": {
                "unweighted": 90.55793991416309,
                "score_weighted": 71.32312033063106,
                "frequency_weighted": 71.32312033063106,
                "nonlib_unweighted": 90.55793991416309,
                "nonlib_score_weighted": 71.32312033063106,
                "nonlib_frequency_weighted": 71.32312033063106
            }
        },
    }

    sample_summary_lib_entry_expected = {
        "sample_id": 2,
        "family": "",
        "family_id": 0,
        "version": "",
        "bitness": 32,
        "sha256": "ae38ff0778fb8dfa1deb17301a15165934312648d232d167cd0c0034c24689e2",
        "filename": "",
        "num_bytes": 1158.0,
        "num_functions": 3,
        'is_library': True,
        "matched": {
            "functions": {
                "combined": 3,
                "library": 3,
                "minhashes": 3,
                "pichashes": 3,
            },
            "bytes": {
                "unweighted": 1158.0,
                "score_weighted": 1158.0,
                "frequency_weighted": 981.0,
                "nonlib_unweighted": 0,
                "nonlib_score_weighted": 0,
                "nonlib_frequency_weighted": 0,
            },
            "percent": {
                "unweighted": 18.407248450166904,
                "score_weighted": 18.407248450166904,
                "frequency_weighted": 15.593705293276109,
                "nonlib_unweighted": 0.0,
                "nonlib_score_weighted": 0.0,
                "nonlib_frequency_weighted": 0.0
            },
        },
    }

    def testMatcherVs(self):
        index = MinHashIndex(config=config)
        worker = index.queue._worker

        sampleEntry2 = index._storage.addSmdaReport(self.smda_report_2)
        id2 = sampleEntry2.sample_id

        sampleEntry1 = index._storage.addSmdaReport(self.smda_report_1)
        id1 = sampleEntry1.sample_id

        libraryEntry = index._storage.addSmdaReport(self.library_report)
        id_lib = libraryEntry.sample_id

        sampleEntry3 = index._storage.addSmdaReport(self.smda_report_3)
        id3 = sampleEntry3.sample_id

        worker.updateMinHashesForSample(id1)
        worker.updateMinHashesForSample(id2)
        worker.updateMinHashesForSample(id_lib)
        worker.updateMinHashesForSample(id3)

        matcher = MatcherVs(worker)
        result = matcher.getMatchesForSample(id1, id2)

        self.assertEqual(result["info"]["sample"], sampleEntry1.toDict())
        self.assertEqual(result["other_sample_info"], sampleEntry2.toDict())
        self.assertTrue("duration" in result["info"]["job"])
        self.assertTrue("timestamp" in result["info"]["job"])
        self.assertTrue(isinstance(result["info"]["job"]["timestamp"], str))
        self.assertTrue(len(result["info"]["job"]["timestamp"]) > 0)
        self.assertNotEqual(result["info"]["job"]["duration"], 0)

        self.assertEqual(result["matches"]["aggregation"]["pichash"], self.pichash_aggregation_expected_vs)
        self.assertEqual(result["matches"]["aggregation"]["minhash"], self.minhash_aggregation_expected_vs)
        self.assertEqual(result["matches"]["functions"], self.function_matches_expected_vs)
        self.assertEqual(result["matches"]["samples"], [self.sample_summary_entry_expected_vs])

    def testMatcherSample(self):
        index = MinHashIndex(config=config)
        worker = index.queue._worker

        sampleEntry2 = index._storage.addSmdaReport(self.smda_report_2)
        id2 = sampleEntry2.sample_id

        sampleEntry1 = index._storage.addSmdaReport(self.smda_report_1)
        id1 = sampleEntry1.sample_id

        libraryEntry = index._storage.addSmdaReport(self.library_report)
        id_lib = libraryEntry.sample_id

        sampleEntry3 = index._storage.addSmdaReport(self.smda_report_3)
        id3 = sampleEntry3.sample_id

        # a=set([fe.pichash for fe in function_entries_1])
        # b=set([fe.pichash for fe in function_entries_2])
        # print(set.intersection(a,b))

        worker.updateMinHashesForSample(id1)
        worker.updateMinHashesForSample(id2)
        worker.updateMinHashesForSample(id3)
        worker.updateMinHashesForSample(id_lib)

        matcher = MatcherSample(worker)
        result = matcher.getMatchesForSample(id1)

        print(json.dumps(result, indent=4))

        self.assertEqual(result["info"]["sample"], sampleEntry1.toDict())
        self.assertTrue("duration" in result["info"]["job"])
        self.assertNotEqual(result["info"]["job"]["duration"], 0)
        self.assertTrue("timestamp" in result["info"]["job"])
        self.assertTrue(isinstance(result["info"]["job"]["timestamp"], str))
        self.assertTrue(len(result["info"]["job"]["timestamp"]) > 0)

        self.assertEqual(result["matches"]["aggregation"]["minhash"], self.minhash_aggregation_expected)
        self.assertEqual(result["matches"]["aggregation"]["pichash"], self.pichash_aggregation_expected)
        self.assertEqual(result["matches"]["functions"], self.function_matches_expected)
        self.maxDiff = None
        self.assertEqual(
            result["matches"]["samples"],
            [
                self.sample_summary_lib_entry_expected,
                self.sample_summary_entry_2_expected,
                self.sample_summary_entry_3_expected,
            ],
        )

    def testMatcherQuery(self):
        index = MinHashIndex(config=config)
        worker = index.queue._worker

        # sampleEntry1 = index._storage.addSmdaReport(self.smda_report_1)
        # id1 = sampleEntry1.sample_id
        sampleEntry2 = index._storage.addSmdaReport(self.smda_report_2)
        id2 = sampleEntry2.sample_id

        sampleEntry1 = index._storage.addSmdaReport(self.smda_report_1)
        id1 = sampleEntry1.sample_id
        index._storage.deleteSample(id1)
        # TODO check if storage.deleteSample is broken

        libraryEntry = index._storage.addSmdaReport(self.library_report)
        id_lib = libraryEntry.sample_id

        sampleEntry3 = index._storage.addSmdaReport(self.smda_report_3)
        id3 = sampleEntry3.sample_id

        # function_entries_1 = index._storage.getFunctionsBySampleId(id1)
        # index.updateMinHashes(function_entries=function_entries_1)

        function_entries_2 = index._storage.getFunctionsBySampleId(id2)
        assert function_entries_2
        worker.updateMinHashesForSample(id2)
        worker.updateMinHashesForSample(id_lib)
        worker.updateMinHashesForSample(id3)

        matcher = MatcherQuery(worker)
        result = matcher.getMatchesForSmdaReport(self.smda_report_1)

        function_matches_expected = deepcopy(self.function_matches_expected)

        for function_data in function_matches_expected:
            matches = function_data["matches"]
            own_function_id = function_data["fid"]
            function_data["fid"] = len(function_entries_2) - own_function_id - 1

        sample_info_expected = SampleEntry(self.smda_report_1, sample_id=-1).toDict()

        self.assertEqual(result["info"]["sample"], sample_info_expected)
        self.assertTrue("duration" in result["info"]["job"])
        self.assertNotEqual(result["info"]["job"]["duration"], 0)
        self.assertTrue("timestamp" in result["info"]["job"])
        self.assertTrue(isinstance(result["info"]["job"]["timestamp"], str))
        self.assertTrue(len(result["info"]["job"]["timestamp"]) > 0)

        self.assertEqual(result["matches"]["aggregation"]["pichash"], self.pichash_aggregation_expected_query)
        self.assertEqual(result["matches"]["aggregation"]["minhash"], self.minhash_aggregation_expected_query)
        json.dumps(sorted(result["matches"]["functions"], key=lambda x: x["fid"]), indent=1)
        self.assertEqual(
            sorted(result["matches"]["functions"], key=lambda x: x["fid"]),
            sorted(function_matches_expected, key=lambda x: x["fid"]),
        )
        self.assertEqual(
            result["matches"]["samples"],
            [
                self.sample_summary_lib_entry_expected,
                self.sample_summary_entry_2_expected,
                self.sample_summary_entry_3_expected,
            ],
        )


if __name__ == "__main__":
    unittest.main()
