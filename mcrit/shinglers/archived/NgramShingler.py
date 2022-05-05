#!/usr/bin/env python3

from collections import Counter

from AbstractShingler import AbstractShingler

class NgramShingler(AbstractShingler):
    """Build a histogram of all mnemonic groups in the function and hash that."""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _generateByteSequences(self, function_object):
        # TODO scale with function size
        # maybe introduce mutation (duplicate sequences and prefix with some index)
        # maybe use both escaped and unescaped sequences
        # use scoring for ngrams to cap number of sequences
        byte_sequences = []
        part_size = 3
        for _, block in sorted(function_object.blocks.items()):
            if len(block) > part_size:
                # introduce some robustness vs. instruction reordering
                escaped_block = [ins.mnemonic + " " + ins.getEscapedOperands() for ins in block]
                for index in range(len(block) - part_size + 1):
                    sorted_sequence = escaped_block[index:index + part_size]
                    byte_sequences.append("{}-".format(self._name) + ";".join(sorted_sequence))
        return byte_sequences
