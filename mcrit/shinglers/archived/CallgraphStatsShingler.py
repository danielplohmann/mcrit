#!/usr/bin/env python3

from AbstractShingler import AbstractShingler


class CallgraphStatsShingler(AbstractShingler):
    """Encode call graph properties into a byte sequence"""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _generateByteSequences(self, function_object):
        return [self._name + "inrefs_%08x;outrefs_%08x;api_%08x" % (function_object.num_inrefs, function_object.num_outrefs, len(function_object.apirefs))]
