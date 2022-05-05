#!/usr/bin/python

import json
import logging
import os
import unittest

from smda.common.SmdaReport import SmdaReport

from mcrit.minhash.MinHash import MinHash
from mcrit.storage.FunctionEntry import FunctionEntry
from mcrit.storage.SampleEntry import SampleEntry

from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class MinHashingTestSuite(unittest.TestCase):
    """Run a full example on a memory dump"""

    def testFunctionEntry(self):
        THIS_FILE_PATH = str(os.path.abspath(__file__))
        PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
        example_file_path = os.sep.join([PROJECT_ROOT, "tests", "example_report.smda"])
        with open(example_file_path, "r") as fjson:
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
        with open(example_file_path, "r") as fjson:
            smda_json = json.load(fjson)

        smda_report = SmdaReport.fromDict(smda_json)
        sample_entry = SampleEntry(smda_report, sample_id=0, family_id=0)

        as_dict = sample_entry.toDict()
        as_entry = SampleEntry.fromDict(as_dict)
        self.assertEqual(as_entry.sample_id, sample_entry.sample_id)


if __name__ == "__main__":
    unittest.main()
