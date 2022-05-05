#!/usr/bin/env python3

from AbstractShingler import AbstractShingler


class FirstByteShingler(AbstractShingler):
    """Take the first byte per instruction only and generate a shingle from the resulting sequence."""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _generateByteSequences(self, function_object):
        byte_sequence = ""
        for _, block in sorted(function_object.blocks.items()):
            byte_sequence += "".join([ins.bytes[0] for ins in block])
        return [self._name + byte_sequence]
