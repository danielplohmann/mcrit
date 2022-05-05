#!/usr/bin/env python3

from AbstractShingler import AbstractShingler


class FuzzyCfgStatsShingler(AbstractShingler):
    """Use buckets to introduce fuzziness to CFG stats."""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _generateByteSequences(self, function_object):
        return [self._name + "ins_%d;blocks_%d;edges_%d" % (self._logbucket(function_object.num_instructions), self._logbucket(function_object.num_blocks), self._logbucket(function_object.num_edges))]
