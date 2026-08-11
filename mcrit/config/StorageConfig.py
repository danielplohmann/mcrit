from dataclasses import dataclass
from typing import Dict

from mcrit.config.ConfigInterface import ConfigInterface, default_field
from mcrit.storage.StorageFactory import StorageFactory


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
    STORAGE_MATCHING_CACHE_PERSIST: bool = False
    # Ceiling on retained functions. Least-recently-needed are evicted first, and never those
    # required by the batch currently being served. 0 disables the ceiling.
    STORAGE_MATCHING_CACHE_MAX_ENTRIES: int = 2000000
    # How getCandidatesForMinHashes accumulates band hits:
    #  * "dict":  dict[query_fid][candidate_fid] -> count  (stock)
    #  * "numpy": per-query-function int32 hit arrays + np.unique(return_counts)
    # Same results either way; "numpy" avoids the ~100 B/pair Python dict and the O(pairs) loop.
    STORAGE_CANDIDATE_ACCUMULATION: str = "dict"
    # Fetch candidate signatures for the MatchingCache with this many concurrent queries.
    # The call is latency-bound (186 B returned per ~4 kB document read), so concurrency
    # overlaps mongod's disk reads: measured 6.81x warm / 15.3x cold at 8 threads on 500k ids,
    # byte-identical results. 1 keeps the sequential behaviour.
    STORAGE_CACHE_FETCH_THREADS: int = 1
    # function_ids per $in query. Must stay well under Mongo's 16 MB command limit; smaller
    # slices also give the thread pool something to overlap.
    STORAGE_CACHE_FETCH_SLICE_SIZE: int = 500000
    # limit maximum export size to protect the system against running OOM, default: 1 GB
    STORAGE_MAX_EXPORT_SIZE = 1024 * 1024 * 1024

    @property
    def STORAGE_NUM_BANDS(self):
        num_bands = 0
        if self.STORAGE_BANDS:
            num_bands = sum([value for value in self.STORAGE_BANDS.values()])
        return num_bands
