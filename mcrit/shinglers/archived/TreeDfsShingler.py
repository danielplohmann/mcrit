#!/usr/bin/env python3

from mcrit.libs.AdjacentTreeBuilder import AdjacentTreeBuilder
from AbstractShingler import AbstractShingler

class TreeDfsShingler(AbstractShingler):
    """Encode call graph properties into a byte sequence"""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _generateByteSequences(self, function_object):
        adjtree = AdjacentTreeBuilder.generateAdjacentTreeFromGraph(function_object, self._config.SHINGLER_TREE_LABEL_STRATEGY)
        dfs_shingles = []
        shingle = []
        self._getDFSShingles(adjtree, dfs_shingles, shingle)
        return dfs_shingles

    def _getDFSShingles(self, node, dfs_shingles, shingle, in_leaf=False):
        if len(node.children) == 0:
            return True
        shingle.append(node.node_label)
        for _, child_node in node.children.items():
            in_leaf = self._getDFSShingles(child_node, dfs_shingles, shingle, in_leaf)
            if child_node.is_visited:
                shingle = []
                continue
            shingle.append(child_node.node_label)
            node.is_visited = True
            if in_leaf:
                dfs_shingles.append("treedfs-" + ''.join(map(str, shingle)))
                shingle = []
                in_leaf = False
        return False
