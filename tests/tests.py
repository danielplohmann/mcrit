#!/usr/bin/python

import logging
import os
import unittest

from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class McritTestSuite(unittest.TestCase):
    """Template for test classes"""

    @classmethod
    def setUpClass(cls):
        super(McritTestSuite, cls).setUpClass()
        # perform any global initializations needed for all tests
        cls.tmp = None

    def testSomething(self):
        assert True


if __name__ == "__main__":
    unittest.main()
