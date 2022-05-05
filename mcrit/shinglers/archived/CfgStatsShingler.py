#!/usr/bin/env python3

from AbstractShingler import AbstractShingler


class CfgStatsShingler(AbstractShingler):
    """Encode control flow graph properties into a byte sequence"""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _generateByteSequences(self, function_object):
        return [self._name + "ins_%08x;blocks_%08x;edges_%08x" % (function_object.num_instructions, function_object.num_blocks, function_object.num_edges)]
