#!/usr/bin/env python3

from mcrit.libs.AdjacentTreeBuilder import AdjacentTreeBuilder
from AbstractShingler import AbstractShingler


class TreeSubgraphShingler(AbstractShingler):
    """Encode call graph properties into a byte sequence"""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _generateByteSequences(self, function_object):
        """:returns: subgraph shingles """
        adjtree = AdjacentTreeBuilder.generateAdjacentTreeFromGraph(function_object, self._config.SHINGLER_TREE_LABEL_STRATEGY)
        tmp_shingles = []
        subgraph_shingles = []
        br_not = self._getBracketNotation(adjtree)
        for s in br_not:
            if s == '{':
                for shingle in tmp_shingles:
                    if shingle[1] > 0:
                        shingle[0].append('{')
                        shingle[1] += 1
                tmp_shingles.append([[s], 1])
            elif s == '}':
                for shingle in tmp_shingles:
                    if shingle[1] > 0:
                        shingle[0].append('}')
                        shingle[1] -= 1
            else:
                for shingle in tmp_shingles:
                    if shingle[1] > 0:
                        shingle[0].append(s)
        for shingle in tmp_shingles:
            subgraph_shingles.append("treesubgraph-" + ''.join(shingle[0]))
        return subgraph_shingles

    def _getBracketNotation(self, tree, notation=""):
        notation += '{' + str(tree.node_label)
        for _, child_node in tree.children.items():
            notation = self._getBracketNotation(child_node, notation)
            notation += '}'
        if tree.tree_lvls is not None:
            notation += '}'
        return notation
