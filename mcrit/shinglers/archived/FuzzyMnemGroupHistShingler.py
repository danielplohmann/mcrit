#!/usr/bin/env python3

from collections import Counter

from AbstractShingler import AbstractShingler

class FuzzyMnemGroupHistShingler(AbstractShingler):
    """Build a histogram of all mnemonic groups in the function and hash that."""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _generateByteSequences(self, function_object):
        mnem_counter = Counter()
        for ins in function_object.getInstructions():
            mnem_counter[ins.getMnemonicGroup()] += 1
        mnem_hist_string = ";".join(["%s%d" % (mnem, self._logbucket(count)) for mnem, count in sorted(dict(mnem_counter).items())])
        return [self._name + mnem_hist_string]
