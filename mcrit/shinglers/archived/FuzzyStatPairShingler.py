#!/usr/bin/env python3

from AbstractShingler import AbstractShingler
from mcrit.libs.utility import generate_unique_pairs


class FuzzyStatPairShingler(AbstractShingler):
    """Use buckets to introduce fuzziness to CFG stats."""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _getStackSize(self, function_object):
        stack_size = 0
        trace = ""
        for ins in function_object.blocks[function_object.offset][:10]:
            if ins.mnemonic == "sub":
                operands = [op.strip() for op in ins.operands.split(",")]
                if len(operands) == 2 and operands[0] in ["esp", "rsp"]:
                    try:
                        stack_size = int(operands[1], 16)
                        break
                    except:
                        pass
                    try:
                        stack_size = int(operands[1])
                        break
                    except:
                        pass
        return stack_size

    def _generateByteSequences(self, function_object):
        byte_sequences = []
        num_loops = len([component for component in function_object.strongly_connected_components if len(component) > 1])
        stack_size = self._getStackSize(function_object)
        fields = {
            "num_instructions": function_object.num_instructions,
            "num_edges": function_object.num_edges,
            "num_calls": function_object.num_calls,
            "num_returns": function_object.num_returns,
            "num_loops": num_loops,
            "stack_size": stack_size
        }
        field_values = []
        for field_name, value in fields.items():
            for bucket in self._getLogBucketRange(value):
                field_values.append("{}:{}".format(field_name, bucket))
        for field_a, field_b in generate_unique_pairs(field_values):
            if field_a.split(":")[0] != field_b.split(":")[0]:
                byte_sequences.append("{}-{}-{}".format(self._name, field_a, field_b))
        return byte_sequences
