#!/usr/bin/env python3

from mcrit.libs.AdjacentTreeBuilder import AdjacentTreeBuilder
from AbstractShingler import AbstractShingler


class TreeBfsShingler(AbstractShingler):
    """Encode call graph properties into a byte sequence"""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _generateByteSequences(self, function_object):
        adjtree = AdjacentTreeBuilder.generateAdjacentTreeFromGraph(function_object, self._config.SHINGLER_TREE_LABEL_STRATEGY)
        bfs_shingles = []
        for _, lvl in adjtree.tree_lvls.items():
            shingle = []
            for node in lvl:
                shingle.append(node.node_label)
            shingle.sort()
            bfs_shingles.append(self._name + ''.join(map(str, shingle)))
        return bfs_shingles
