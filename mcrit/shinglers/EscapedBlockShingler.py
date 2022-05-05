#!/usr/bin/env python3

from collections import Counter

from AbstractShingler import AbstractShingler
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper


class EscapedBlockShingler(AbstractShingler):
    """Build a histogram of all mnemonic groups in the function and hash that."""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _escapeInstruction(self, instruction):
        return (
            instruction.getMnemonicGroup(IntelInstructionEscaper)
            + " "
            + instruction.getEscapedOperands(IntelInstructionEscaper)
        )
        # return instruction.mnemonic + " " + instruction.getEscapedOperands(IntelInstructionEscaper)

    def _maskInstructions(self, instructions, ngram_size=3):
        sequences = []
        escaped_sequence = [self._escapeInstruction(ins) for ins in instructions]
        if len(instructions) > ngram_size:
            for index in range(len(escaped_sequence) - ngram_size + 1):
                escaped_ngram = escaped_sequence[index : index + ngram_size]
                sequences.append(";".join(sorted(escaped_ngram)))
        else:
            sequences.append(";".join(sorted(escaped_sequence)))
        return sequences

    def _filterInstructions(self, instructions):
        sequence = []
        for i in instructions:
            if i.mnemonic in ["push", "pop"]:
                continue
            elif "esp" in i.operands or "rsp" in i.operands:
                continue
            sequence.append(i)
        return sequence

    def _relabelNgrams(self, ngrams):
        restructured = []
        counted_ngrams = Counter()
        for ngram in ngrams:
            counted_ngrams[ngram] += 1
            restructured.append(f"tok-{counted_ngrams[ngram]}|{ngram}")
        return restructured

    def _generateByteSequences(self, function_object):
        blocks_as_sequences = []
        all_instructions = []
        for _, block in sorted(function_object.blocks.items()):
            instructions = [ins for ins in block]
            # instructions = self._filterInstructions(instructions)
            masked_instructions = self._maskInstructions(instructions)
            blocks_as_sequences.extend(masked_instructions)
            all_instructions.extend(instructions)
        masked_instructions = self._maskInstructions(all_instructions)
        masked_instructions = self._relabelNgrams(masked_instructions)
        return blocks_as_sequences
