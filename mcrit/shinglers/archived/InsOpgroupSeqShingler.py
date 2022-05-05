#!/usr/bin/env python3

from AbstractShingler import AbstractShingler


class InsOpgroupSeqShingler(AbstractShingler):
    """Build a sequence of instructions but replace operands by their group."""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _generateByteSequences(self, function_object):
        opgroup_sequence = []
        for ins in function_object.getInstructions():
            opgroup_sequence.append(ins.mnemonic + " " + ins.getEscapedOperands())
        opgroup_string = ";".join(opgroup_sequence)
        return [self._name + opgroup_string]
