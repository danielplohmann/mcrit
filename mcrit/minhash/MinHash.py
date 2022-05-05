import struct

import numpy as np

try:
    # try with a fast c-implementation ...
    import mmh3
except ImportError:
    # ... otherwise fallback to the pure python version
    import mcrit.libs.pymmh3 as mmh3


class MinHash(object):
    """DTO for an actual MinHash
    <minhash>: a binary sequence of packed int8/32 values
    <minhash_int>: the equivalent representation of <minhash> but as list of int8/32
    """

    _HASH_MAX = 0xFFFFFFFF
    _MINHASH_BITS = 32

    def __init__(self, function_id=None, minhash_bytes=None, minhash_signature=None, minhash_bits=32):
        self.minhash = b""
        self.minhash_int = []
        if minhash_bits:
            self._MINHASH_BITS = minhash_bits
        if minhash_bytes and minhash_signature:
            raise ValueError("Can use only one keyword argument")
        if minhash_bytes:
            if self._MINHASH_BITS <= 8:
                minhash_signature = np.frombuffer(minhash_bytes, dtype=np.uint8)
            else:
                minhash_signature = np.frombuffer(minhash_bytes, dtype=np.uint32)
            self.setMinHash(minhash_signature)
        elif minhash_signature:
            self.setMinHash(minhash_signature)

        self.shingler_composition = {}
        self.function_id = function_id

    def hasMinHash(self) -> bool:
        return len(self.minhash) > 0

    def getMinHash(self):
        return self.minhash

    def getMinHashInt(self):
        return self.minhash_int

    def getSignatureEntrySize(self):
        return 1 if MinHash._MINHASH_BITS <= 8 else 4

    def setMinHash(self, minhash_signature):
        self.minhash_int = [i % 2 ** self._MINHASH_BITS for i in minhash_signature]
        if self._MINHASH_BITS <= 8:
            self.minhash = np.array(self.minhash_int, dtype=np.uint8).tobytes()
        else:
            self.minhash = np.array(self.minhash_int, dtype=np.uint32).tobytes()

    def getComposition(self):
        return self.shingler_composition

    def scoreAgainst(self, other):
        return MinHash.calculateMinHashScore(self.minhash, other.minhash, minhash_bits=self._MINHASH_BITS)

    def __str__(self) -> str:
        return "Function ID: {}, Minhash: {}...".format(self.function_id, self.minhash[:16])

    @staticmethod
    def getHashMax():
        return MinHash._HASH_MAX

    @staticmethod
    def hashData(data, seed) -> int:
        if isinstance(data, (str, bytes, bytearray)):
            return mmh3.hash(data, seed) & MinHash._HASH_MAX
        elif isinstance(data, list):
            to_hash = "".join([str(elem) for elem in data])
            return mmh3.hash(to_hash, seed) & MinHash._HASH_MAX
        else:
            raise NotImplementedError

    @staticmethod
    def calculateMinHashScore(first, second, minhash_bits=32):
        if minhash_bits <= 8:
            first_np = np.frombuffer(first, dtype=np.uint8)
            second_np = np.frombuffer(second, dtype=np.uint8)
        else:
            first_np = np.frombuffer(first, dtype=np.uint32)
            second_np = np.frombuffer(second, dtype=np.uint32)
        return 100.0 * sum(first_np == second_np) / len(first_np)

    @staticmethod
    def calculateMinHashIntScore(first, second):
        score = 0
        num_hashes = len(first)
        if num_hashes:
            for index, part in enumerate(first):
                score += 1 if part == second[index] else 0
            return 100.0 * score / num_hashes
        return 0.0

    def __repr__(self):
        # return f"<Minhash(function_id={self.function_id}, length={len(self.minhash_int)})>"
        return "<Minhash(function_id={}, length={})>".format(self.function_id, len(self.minhash_int))
