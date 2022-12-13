import hashlib
import logging
from dataclasses import asdict, dataclass, field

from mcrit.config.ConfigInterface import ConfigInterface, default_field
from mcrit.minhash.MinHasher import MinHasher


@dataclass
class MinHashConfig(ConfigInterface):
    # Store the combination of shingles (unsorted) that were used to create the given MinHash
    MINHASH_TRACK_SHINGLES: bool = False
    # Which minhash calculation strategy should be used
    MINHASH_STRATEGY: ... = MinHasher.MINHASH_STRATEGY_SEGMENTED
    # A function must consist of minimum N instructions to be considered for MinHashing
    MINHASH_FN_MIN_INS: int = 10
    # A function must alternatively consist of minimum N basic blocks to be considered for MinHashing
    MINHASH_FN_MIN_BLOCKS: int = 0
    # Length in number of Shingles of which a minhash consists
    MINHASH_SIGNATURE_LENGTH: int = 64
    # Number of bits per signature element (1-32 bits)
    MINHASH_SIGNATURE_BITS: int = 8
    # The lower bound at which paired MinHashes are considered a match (range: 0-100)
    MINHASH_MATCHING_THRESHOLD: int = 50
    # random seed to be used when initiating XOR values for minhash seeds
    MINHASH_SEED: int = 0xDEADBEEF
    # When using as server, Gunicorn/Falcon may have issues with multiprocessing while indexing, which can be disabled this way.
    MINHASH_POOL_INDEXING: bool = True
    MINHASH_POOL_MATCHING: bool = True
    # The minimum number of band matches a minhash must have before being considered a candidate for matching
    BAND_MATCHES_REQUIRED = 1
    # minimum function size for considering PicHash matching
    PICHASH_SIZE: int = 10
    # do not perform minhash matching for pichash matches, instead assume they are implied
    PICHASH_IMPLIES_MINHASH_MATCH: bool = True

    def getConfigHash(self):
        config_str = ""
        config_str += f"_{self.MINHASH_STRATEGY}_{self.MINHASH_FN_MIN_INS}_{self.MINHASH_FN_MIN_BLOCKS}"
        config_str += f"_{self.MINHASH_SIGNATURE_LENGTH}_{self.MINHASH_SIGNATURE_BITS}_{self.MINHASH_SEED}"
        config_str += f"_{self.PICHASH_SIZE}"
        return hashlib.sha256(config_str.encode('utf-8')).hexdigest()
