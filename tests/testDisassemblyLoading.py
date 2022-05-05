#!/usr/bin/python

import logging
import os
import unittest

from smda.common.SmdaInstruction import SmdaInstruction
from smda.common.SmdaReport import SmdaReport
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class DisassemblyTestSuite(unittest.TestCase):
    """Run a full example on a memory dump"""

    def testLoadReport(self):
        THIS_FILE_PATH = str(os.path.abspath(__file__))
        PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
        example_file_path = os.sep.join([PROJECT_ROOT, "tests", "example_report.smda"])
        report = SmdaReport.fromFile(example_file_path)
        self.assertEqual(report.architecture, "intel")
        self.assertEqual(report.bitness, 32)
        self.assertEqual(report.statistics.num_functions, 10)


if __name__ == "__main__":
    unittest.main()
