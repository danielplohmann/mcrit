#!/usr/bin/python

import logging
import unittest

from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.libs.utility import generate_unique_pairs

from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class MinHashIndexTestSuite(unittest.TestCase):
    """Run a full example on a memory dump"""

    def testMinHashIndexInit(self):
        index = MinHashIndex(config)

    def testCandidatePairGenerator(self):
        test_data = [([], []), ([1, 2, 3, 4], [(1, 2), (1, 3), (1, 4), (2, 3), (2, 4), (3, 4)])]
        for data in test_data:
            generated_all_candidates = [pair for pair in generate_unique_pairs(data[0])]
            self.assertEqual(data[1], generated_all_candidates)


if __name__ == "__main__":
    unittest.main()
