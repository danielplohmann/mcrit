#!/usr/bin/env python3

from mcrit.libs.AdjacentTreeBuilder import AdjacentTreeBuilder
from AbstractShingler import AbstractShingler


class TreeTwoTraceShingler(AbstractShingler):
    """Encode call graph properties into a byte sequence"""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _generateByteSequences(self, function_object):
        """:returns: 2 traces for tree """
        adjtree = AdjacentTreeBuilder.generateAdjacentTreeFromGraph(function_object, self._config.SHINGLER_TREE_LABEL_STRATEGY)
        trace_shingles = []
        for _, lvl in adjtree.tree_lvls.items():
            for node in lvl:
                if node.children == {}:
                    trace_shingles.append("tree2ts-" + str(node.node_label) + "!!")
                else:
                    for _, child in node.children.items():
                        trace_shingles.append("tree2ts-" + str(node.node_label) + str(child.node_label))
        return trace_shingles
