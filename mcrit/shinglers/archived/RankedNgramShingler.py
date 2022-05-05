#!/usr/bin/env python3

from collections import Counter

from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

from AbstractShingler import AbstractShingler

class RankedNgramShingler(AbstractShingler):
    """Build a histogram of all mnemonic groups in the function and hash that."""

    def __init__(self, config, weight=1):
        super().__init__(__class__.__name__)
        self._config = config
        self._weight = weight

    def _createScoredCandidates(self, ngram):
        mnemonic_group_scores = {
            "U": 1, "N": 2, "M": 2, "S": 2, "C": 2,
            "A": 4, "P": 6, "Y": 6, "F": 6, "X": 6
        }
        escaped_sequence = [ins.mnemonic + " " + ins.getEscapedOperands(IntelInstructionEscaper) for ins in ngram]
        masked_sequence = [ins.mnemonic + " " + ins.getMaskedOperands(IntelInstructionEscaper) for ins in ngram]
        ngram_score = 0
        for ins in ngram:
            ngram_score += 1 if ins.mnemonic in ["mov", "push", "call"] else mnemonic_group_scores[ins.getMnemonicGroup(IntelInstructionEscaper)]
        return (ngram_score, escaped_sequence, masked_sequence, sorted(escaped_sequence), sorted(masked_sequence))

    def _nFoldSequence(self, sequence, factor):
        nfolded_sequence = []
        for factor in range(factor):
            for element in sequence:
                prefix = ["X%d" % factor] if factor else [""]
                score, esc, unesc, sort_esc, sort_unesc = element
                nfolded_sequence.append((score / (factor + 1), prefix + esc, prefix + unesc, prefix + sort_esc, prefix + sort_unesc))
        return nfolded_sequence

    def _getScaledByteSequences(self, candidate_ngrams):
        byte_sequences = []
        nfolded = []
        if len(candidate_ngrams) <= 2:
            nfolded = self._nFoldSequence(candidate_ngrams, 16)
        elif len(candidate_ngrams) <= 8:
            nfolded = self._nFoldSequence(candidate_ngrams, 4)
        elif len(candidate_ngrams) <= 15:
            nfolded = self._nFoldSequence(candidate_ngrams, 2)
        else:
            nfolded = candidate_ngrams
        if len(nfolded) < 30:
            for ngram in nfolded:
                for index in range(1, 5, 1):
                    byte_sequences.append("{}-".format(self._name) + ";".join(ngram[index]))
        else:
            for ngram in sorted(nfolded)[:100]:
                for index in range(1, 3, 1):
                    byte_sequences.append("{}-".format(self._name) + ";".join(ngram[index]))
        return byte_sequences

    def _generateByteSequences(self, function_object):
        candidate_ngrams = []
        ngram_size = 3
        for _, block in sorted(function_object.blocks.items()):
            if len(block) >= ngram_size:
                instructions = [ins for ins in block]
                for index in range(len(block) - ngram_size + 1):
                    candidate_ngrams.append(self._createScoredCandidates(instructions[index:index + ngram_size]))
        return self._getScaledByteSequences(candidate_ngrams)
