import logging
import os
from dataclasses import dataclass
from typing import Dict

from mcrit.config.ConfigInterface import ConfigInterface, default_field
from mcrit.storage.StorageFactory import StorageFactory

LOGGER = logging.getLogger(__name__)

# measured resident cost per retained MatchingCache function (minhash bytes + dict/index
# overhead), used to convert STORAGE_MATCHING_CACHE_MAX_BYTES into an entry ceiling
MATCHING_CACHE_BYTES_PER_ENTRY = 314


@dataclass
class StorageConfig(ConfigInterface):
    # storage configuration, use "memory" for local testing or "mongodb" when working with larger data
    # STORAGE_METHOD = StorageFactory.STORAGE_METHOD_MEMORY
    STORAGE_METHOD: ... = StorageFactory.STORAGE_METHOD_MONGODB
    # Use this as endpoint for our server
    STORAGE_SERVER: str = "127.0.0.1"
    STORAGE_PORT: str = "27017"
    # By default, MongoDbStorage's DB's name and MongoQueue's DB's name are both "mcrit"
    # Changing one DB name here or at runtime DOES NOT change the other name!
    STORAGE_MONGODB_DBNAME: str = "mcrit"
    STORAGE_MONGODB_USERNAME: str = None
    STORAGE_MONGODB_PASSWORD: str = None
    STORAGE_MONGODB_FLAGS: str = ""
    # Enable periodic deletion of queried samples and their results after a given time
    STORAGE_MONGODB_ENABLE_CLEANUP: bool = False
    STORAGE_MONGODB_CLEANUP_DELTA: int = 60 * 60 * 24 * 7
    STORAGE_MONGODB_CLEANUP_TTL: int = 60 * 60 * 24 * 7
    # Once MinHashes have been calculated, discard disassembly from function entries
    STORAGE_DROP_DISASSEMBLY: bool = False
    # supported strategies:
    #  * random: randomly sample from minhash fields, possibly more fuzziness likely won't use all minhash fields
    #  * linear: use a sequential selection of minhash fields, requires size*number=MINHASH_SIGNATURE_LENGTH
    STORAGE_BAND_STRATEGY = "random"
    # random seed to be used when deriving sequences used as bands
    STORAGE_BAND_SEED: int = 0xDEADBEEF
    # Banding supports:
    #  * MemoryStorage: arbitrary banding configuration, multiple lengths
    #  * MongoDbStorage: arbitrary banding configuration, multiple lengths
    # configuration for bands, dict with size:number as structure - we allow mixed sizes to increase scatter effect and randomness
    _default_storage_bands = {4: 20}
    STORAGE_BANDS: Dict[int, int] = default_field(_default_storage_bands)
    # use a hashmap to cache all banding data - very memory intensive, but great speedups.
    STORAGE_CACHE: bool = False
    # Reuse the MatchingCache across the batches of a single matching job instead of
    # rebuilding it per batch. Measured redundancy of the per-batch rebuild on real data:
    # 1.54x (citadel) to 12.21x (merlin). Costs ~314 B resident per retained function.
    STORAGE_MATCHING_CACHE_PERSIST: bool = True
    # Memory budget for retained functions, in bytes (converted at ~314 B resident per
    # retained function, measured). Least-recently-needed entries are evicted first, never
    # those required by the batch currently being served, and every eviction is logged.
    # 0 disables the byte budget.
    STORAGE_MATCHING_CACHE_MAX_BYTES: int = 512 * 1024 * 1024
    # Ceiling on retained functions as an entry count. 0 (the default) derives it from
    # STORAGE_MATCHING_CACHE_MAX_BYTES at config load and logs the resolved value; an
    # explicit value here overrides the byte budget. Setting both this and
    # STORAGE_MATCHING_CACHE_MAX_BYTES to 0 disables the ceiling entirely.
    STORAGE_MATCHING_CACHE_MAX_ENTRIES: int = 0
    # How getCandidatesForMinHashes accumulates band hits:
    #  * "numpy": per-query-function int32 hit arrays + np.unique(return_counts) (default)
    #  * "dict":  dict[query_fid][candidate_fid] -> count  (legacy fallback, deprecated)
    # Same results either way; "numpy" avoids the ~100 B/pair Python dict and the O(pairs) loop.
    STORAGE_CANDIDATE_ACCUMULATION: str = "numpy"
    # Fetch candidate signatures for the MatchingCache with this many concurrent queries.
    # The call is latency-bound (186 B returned per ~4 kB document read), so concurrency
    # overlaps mongod's disk reads: measured 6.81x warm / 15.3x cold at 8 threads on 500k ids,
    # byte-identical results. 1 keeps the sequential behaviour. 0 (the default) derives
    # min(4, max(1, cpu_count // 2)) at config load and logs the resolved value - a
    # conservative half-step that captures most of the win (2.16x at 2 threads, 3.36x at 4
    # on the measured fetch) without turning a shared mongod into a contention point.
    # With N concurrent jobs sharing one mongod, keep N x threads <= pymongo's maxPoolSize
    # (default 100).
    STORAGE_CACHE_FETCH_THREADS: int = 0
    # function_ids per $in query. Must stay well under Mongo's 16 MB command limit; smaller
    # slices also give the thread pool something to overlap.
    STORAGE_CACHE_FETCH_SLICE_SIZE: int = 500000
    # limit maximum export size to protect the system against running OOM, default: 1 GB
    STORAGE_MAX_EXPORT_SIZE = 1024 * 1024 * 1024

    def __post_init__(self):
        super().__post_init__()
        # resolve derived defaults once, here, so every consumer sees a concrete value and
        # the resolved value is visible in the log - a silently-binding derived default is
        # indistinguishable from a fix that does not work
        if not self.STORAGE_CACHE_FETCH_THREADS:
            cpu_count = os.cpu_count() or 1
            self.STORAGE_CACHE_FETCH_THREADS = min(4, max(1, cpu_count // 2))
            LOGGER.info(
                "STORAGE_CACHE_FETCH_THREADS resolved to %d (derived from cpu_count=%d)",
                self.STORAGE_CACHE_FETCH_THREADS,
                cpu_count,
            )
        if not self.STORAGE_MATCHING_CACHE_MAX_ENTRIES and self.STORAGE_MATCHING_CACHE_MAX_BYTES:
            self.STORAGE_MATCHING_CACHE_MAX_ENTRIES = max(
                1, self.STORAGE_MATCHING_CACHE_MAX_BYTES // MATCHING_CACHE_BYTES_PER_ENTRY
            )
            LOGGER.info(
                "STORAGE_MATCHING_CACHE_MAX_ENTRIES resolved to %d (derived from "
                "STORAGE_MATCHING_CACHE_MAX_BYTES=%d at %d B/entry)",
                self.STORAGE_MATCHING_CACHE_MAX_ENTRIES,
                self.STORAGE_MATCHING_CACHE_MAX_BYTES,
                MATCHING_CACHE_BYTES_PER_ENTRY,
            )

    @property
    def STORAGE_NUM_BANDS(self):
        num_bands = 0
        if self.STORAGE_BANDS:
            num_bands = sum([value for value in self.STORAGE_BANDS.values()])
        return num_bands
