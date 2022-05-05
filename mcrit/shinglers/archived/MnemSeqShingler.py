#!/usr/bin/env python3

from AbstractShingler import AbstractShingler


class MnemSeqShingler(AbstractShingler):
    """Take the first byte per instruction only and generate a shingle from the resulting sequence."""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _generateByteSequence(self, function_object):
        mnem_sequence = []
        for ins in function_object.getInstructions():
            mnem_sequence.append(ins.mnemonic)
        mnem_string = ";".join(mnem_sequence)
        return [self._name + mnem_string]
