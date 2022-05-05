#!/usr/bin/env python3

from mcrit.libs.AdjacentTreeBuilder import AdjacentTreeBuilder
from AbstractShingler import AbstractShingler


class TreeRootLeafShingler(AbstractShingler):
    """Encode call graph properties into a byte sequence"""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _generateByteSequences(self, function_object):
        adjtree = AdjacentTreeBuilder.generateAdjacentTreeFromGraph(function_object, self._config.SHINGLER_TREE_LABEL_STRATEGY)
        rl_shingles = []
        self._rlShingles(adjtree, rl_shingles)
        return rl_shingles

    def _rlShingles(self, node, rl_shingles, path=""):
        path += str(node.node_label)
        for _, child_node in node.children.items():
            if len(child_node.children) == 0:
                rl_shingles.append("treeRL-empty" + path + str(child_node.node_label))
            else:
                self._rlShingles(child_node, rl_shingles, path)

