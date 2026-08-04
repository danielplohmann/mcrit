import hashlib
from dataclasses import dataclass

from mcrit.config.ConfigInterface import ConfigInterface
from mcrit.minhash.MinHasher import MinHasher


@dataclass
class MinHashConfig(ConfigInterface):
    # Store the combination of shingles (unsorted) that were used to create the given MinHash
    MINHASH_TRACK_SHINGLES: bool = False
    # Which minhash calculation strategy should be used
    MINHASH_STRATEGY: int = MinHasher.MINHASH_STRATEGY_SEGMENTED
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
    BAND_MATCHES_REQUIRED = 2
    # minimum function size for considering PicHash matching
    PICHASH_SIZE: int = 10
    # do not perform minhash matching for pichash matches, instead assume they are implied
    PICHASH_IMPLIES_MINHASH_MATCH: bool = True
    # size of batches for which candidates are processed. With MINHASH_MATCHING_MAX_PAIRS
    # active this only bounds how many query functions are banded per storage round trip;
    # the memory-relevant unit is the pair budget below.
    MINHASH_MATCHING_FUNCTION_BATCH_SIZE: int = 10000
    # Upper bound on candidate pairs accumulated before a batch is scored. Candidate volume
    # per query function is extremely skewed (measured p50 ~7, p90 ~220k candidates), so any
    # fixed function count is simultaneously too big for the tail (peak RSS scales with
    # pairs: a single 10000-function batch has been measured holding 50M+ pairs / >7 GiB)
    # and needlessly small for the median. Packing batches to a pair budget caps matcher
    # memory by construction; a single query function whose candidate set alone exceeds the
    # budget is scored in a batch of its own, bounding the peak at the widest single group.
    # Batches are also capped at MINHASH_MATCHING_FUNCTION_BATCH_SIZE query functions, so lowering
    # that knob still lowers peak memory as documented in docs/TUNING.md; the budget bounds the tail
    # that a function count cannot.
    # The default is a guard against runaway jobs (#69-class: hundreds of millions of pairs)
    # and leaves typical jobs in one or two batches (measured +2% wall / -6% peak on a
    # 53M-pair sample). Lower values buy memory with wall time - measured on that sample:
    # 10M -> -40% peak / +68% wall, 2M -> -49% peak / +203% wall (roughly ~250 B resident
    # per in-flight pair; below the candidate-union size, batches also evict each other from
    # the MatchingCache, which is most of the added wall). 0 restores fixed-size batches.
    MINHASH_MATCHING_MAX_PAIRS: int = 50000000
    # score each query function against its candidates as one (C, L) numpy block instead of
    # per-pair tuples. Same matches, but pair tuples are never materialised, so peak memory
    # goes from O(pairs) to O(widest candidate group). When enabled, the matching phase runs
    # single-process and MINHASH_POOL_MATCHING is ignored for matching (indexing is unaffected);
    # the scalar per-pair path remains as automatic fallback where vectorisation cannot apply.
    MINHASH_MATCHING_VECTORIZED: bool = True
    # size of candidate packs to be processed per work unit
    MINHASH_MATCHING_CANDIDATE_WORKPACK_SIZE: int = 20000
    # size of functions to be processed into minhashes per work iteration
    MINHASH_GENERATION_WORKPACK_SIZE: int = 10000
    # when rebuilding minhash bands, work in packs of this size
    MINHASH_BAND_REBUILD_WORK_PACKAGE_SIZE: int = 100000

    def getConfigHash(self):
        config_str = ""
        config_str += f"_{self.MINHASH_STRATEGY}_{self.MINHASH_FN_MIN_INS}_{self.MINHASH_FN_MIN_BLOCKS}"
        config_str += f"_{self.MINHASH_SIGNATURE_LENGTH}_{self.MINHASH_SIGNATURE_BITS}_{self.MINHASH_SEED}"
        config_str += f"_{self.PICHASH_SIZE}"
        return hashlib.sha256(config_str.encode("utf-8")).hexdigest()
