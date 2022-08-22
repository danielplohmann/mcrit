#!/usr/bin/python

import json
import logging
import os
import unittest

from mcrit.libs.utility import generate_unique_pairs, compress_encode, decompress_decode

from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class TestUtility(unittest.TestCase):
    """Run a full example on a memory dump"""

    def testUniquePairGenerator(self):
        input_data = [1, 2, 3, 4]
        expected_pairs = [(1, 2), (1, 3), (1, 4), (2, 3), (2, 4), (3, 4)]
        pairs = generate_unique_pairs(input_data)
        generated_pairs = [p for p in pairs]
        self.assertEqual(expected_pairs, generated_pairs)

    def testZip(self):
        content = {"test_key": "test data"}
        zip_b64 = compress_encode(json.dumps(content))
        decompressed = decompress_decode(zip_b64)
        self.assertEqual(content, json.loads(decompressed))


if __name__ == "__main__":
    unittest.main()
