#!/usr/bin/env python3

from collections import Counter

from AbstractShingler import AbstractShingler
from LogBucket import LogBucket
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

from mcrit.libs.utility import generate_unique_pairs


class FuzzyStatPairShingler(AbstractShingler):
    """Use buckets to introduce fuzziness to CFG stats."""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight
        self._log_buckets = LogBucket(self._config.SHINGLER_LOGBUCKETS, self._config.SHINGLER_LOGBUCKET_RANGE)

    def _getStackSize(self, function_object):
        stack_size = 0
        trace = ""
        for ins in function_object.blocks[function_object.offset][:10]:
            if ins.mnemonic == "sub":
                operands = [op.strip() for op in ins.operands.split(",")]
                if len(operands) == 2 and operands[0] in ["esp", "rsp"]:
                    try:
                        stack_size = int(operands[1], 16)
                        if 0 <= stack_size < self._config.SHINGLER_LOGBUCKETS:
                            break
                        else:
                            stack_size = 0
                    except:
                        pass
                    try:
                        stack_size = int(operands[1])
                        if 0 <= stack_size < self._config.SHINGLER_LOGBUCKETS:
                            break
                        else:
                            stack_size = 0
                    except:
                        pass
        return stack_size

    def _create_bucketed_values(self, value, field_name):
        bucketed = []
        if self._config.SHINGLER_LOGBUCKET_CENTERED:
            field_count = Counter()
            bucket_range = self._log_buckets.getLogBucketRange(value)
            for index, bucket in enumerate(bucket_range):
                distance = abs(index - self._config.SHINGLER_LOGBUCKET_RANGE)
                max_range = self._config.SHINGLER_LOGBUCKET_RANGE + 1
                start_range = max_range - distance
                for _ in range(distance, self._config.SHINGLER_LOGBUCKET_RANGE + 1, 1):
                    field_count[bucket] += 1
                    bucketed.append("{}={}:{}".format(field_name, field_count[bucket], bucket))
        else:
            for bucket in self._log_buckets.getLogBucketRange(value):
                bucketed.append("{}:{}".format(field_name, bucket))
        return bucketed

    def _generateByteSequences(self, function_object):
        byte_sequences = []
        mnemonic_type_count = Counter()
        for instruction in function_object.getInstructions():
            mnemonic_type_count[instruction.getMnemonicGroup(IntelInstructionEscaper)] += 1
        num_instructions = function_object.num_instructions
        num_ins_C = mnemonic_type_count["C"] if "C" in mnemonic_type_count else 0
        num_ins_S = mnemonic_type_count["S"] if "S" in mnemonic_type_count else 0
        num_ins_M_rel = (
            int(100 * mnemonic_type_count["M"] / function_object.num_instructions) if "M" in mnemonic_type_count else 0
        )
        num_ins_S_rel = (
            int(100 * mnemonic_type_count["S"] / function_object.num_instructions) if "S" in mnemonic_type_count else 0
        )
        num_ins_A_rel = (
            int(100 * mnemonic_type_count["A"] / function_object.num_instructions) if "A" in mnemonic_type_count else 0
        )
        num_ins_C_rel = (
            int(100 * mnemonic_type_count["C"] / function_object.num_instructions) if "C" in mnemonic_type_count else 0
        )
        max_block_size = max([block.length for block in function_object.getBlocks()])
        num_sccs = len(function_object.strongly_connected_components)
        num_calls = function_object.num_calls
        num_returns = function_object.num_returns
        # num_loops = len([component for component in function_object.strongly_connected_components if len(component) > 1])
        stack_size = self._getStackSize(function_object)
        fields = {
            "num_ins_C": num_ins_C,
            "num_ins_S": num_ins_S,
            "num_ins_A_rel": num_ins_A_rel,
            "num_ins_M_rel": num_ins_M_rel,
            "num_calls": num_calls,
            "stack_size": stack_size,
            "max_block_size": max_block_size,
            # "num_returns": num_returns,
            # "stack_size": stack_size,
            # "max_block_size": max_block_size,
        }
        field_values = []
        for field_name, value in fields.items():
            bucket_values = self._create_bucketed_values(value, field_name)
            field_values.extend(bucket_values)
        return field_values
        # optionally group each two fields to create more fuzziness / a larger value corpus to minhash from
        for field_a, field_b in generate_unique_pairs(field_values):
            if field_a.split(":")[0] != field_b.split(":")[0]:
                byte_sequences.append("{}-{}-{}".format(self._name, field_a, field_b))
        return byte_sequences
