#!/usr/bin/env python3

from collections import Counter

from AbstractShingler import AbstractShingler

class DomGroupHistShingler(AbstractShingler):
    """Build a histogram of all mnemonic groups in the function and hash that."""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _generateByteSequences(self, function_object):
        mnem_counter = Counter()
        for block_offset, _ in sorted(function_object.blocks.items()):
            mnem_counter[function_object.getDomGroupForBlock(block_offset)] += 1
        mnem_hist_string = ";".join(["%s%d" % (mnem, count) for mnem, count in sorted(dict(mnem_counter).items())])
        return [self._name + mnem_hist_string]
