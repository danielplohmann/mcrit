#!/usr/bin/env python3
# Credits for Abstraction of Shinglers: Martin Clauss
# Credits for pymmh3: Fredrik Kihlander (https://github.com/wc-duck/pymmh3)

import math
from abc import abstractmethod

from mcrit.minhash.MinHash import MinHash


class AbstractShingler:
    def __init__(self, plugin_name):
        self._name = plugin_name
        self._config = {}
        self._weight = 0
        self._use_weights = True

    @abstractmethod
    def _generateByteSequences(self, function_object):
        """actual logic of the shingle, output is a LIST of (potentially binary) strings that can be hashed"""
        raise NotImplementedError

    def _logbucket(self, value):
        if value == 0:
            return 0
        return math.ceil(math.log(value, 2))

    def _getLogBucketRange(self, value):
        log_value = math.log(value, 2) if value > 0 else 0
        floored_exponent = math.floor(log_value)
        if floored_exponent < 2:
            return (max(value - 1, 0), value, value + 1)
        window_size = 2 ** math.floor(floored_exponent / 2)
        middle_bucket = window_size * math.ceil(value / window_size)
        # for a power of two, the bucket size is halfed to the left
        if log_value % 2 == 0:
            return (middle_bucket - int(window_size / 2), middle_bucket, middle_bucket + window_size)
        else:
            return (middle_bucket - window_size, middle_bucket, middle_bucket + window_size)

    def process(self, function_object, hash_seed):
        """generic processor that uses output of private byte sequence generator and hashes it accordingly."""
        shingled_sequences = []
        byte_sequences = self._generateByteSequences(function_object)
        if not byte_sequences:
            return [[MinHash.getHashMax()]]
        shingled_reference = [self.hashShingle(byte_sequence, hash_seed) for byte_sequence in byte_sequences]
        shingled_sequences.append(shingled_reference)
        if self._use_weights:
            for index in range(1, self._weight, 1):
                xored_sequence = [shingle ^ self._config.SHINGLERS_XOR_VALUES[index] for shingle in shingled_reference]
                shingled_sequences.append(xored_sequence)
        return shingled_sequences

    def hashShingle(self, shingle, hash_seed=0):
        """produce a single 32bit UINT hash for a given shingle"""
        return MinHash.hashData(shingle, hash_seed)

    def getName(self):
        return self._name

    def getWeight(self):
        return self._weight

    def setUseWeights(self, use_weights):
        self._use_weights = use_weights

    def __lt__(self, other):
        return self.getName() < other.getName()
