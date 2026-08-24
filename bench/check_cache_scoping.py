"""Gate-1 (#110 / R9) verification: the persistent MatchingCache must be scoped to the
matcher/job, never shared through the storage object.

No mongod needed: MongoDbStorage is instantiated but _getDb() is never called because
every createMatchingCache call here requests zero ids from storage.

Checks, in order:
  1. persist ON: two createMatchingCache([]) calls return DISTINCT objects
     (pre-fix they return the same storage-held object - the R9 collision).
  2. persist ON: simulating two concurrent /query/function requests, each injecting its
     own function_id = -1 entry, each cache serves back ITS OWN minhash.
  3. persist ON: passing previous= retains entries across a job's batches
     (fix 01's actual purpose still works).
  4. persist OFF: caches are fresh objects every call, previous= is ignored.
"""

import sys

sys.path.insert(0, "/opt/mcrit")

from mcrit.config.McritConfig import McritConfig
from mcrit.storage.MongoDbStorage import MongoDbStorage


def make_storage(persist):
    config = McritConfig()
    config.STORAGE_CONFIG.STORAGE_MATCHING_CACHE_PERSIST = persist
    config.STORAGE_CONFIG.STORAGE_MATCHING_CACHE_MAX_ENTRIES = 0
    storage = MongoDbStorage(config)
    return storage


def main():
    failures = []

    # 1. distinct objects per call with persist on
    storage = make_storage(persist=True)
    cache_a = storage.createMatchingCache([])
    cache_b = storage.createMatchingCache([])
    if cache_a is cache_b:
        failures.append("1: two createMatchingCache([]) calls share one object (R9 collision possible)")
    else:
        print("ok 1: persist=on, independent calls get distinct cache objects")

    # 2. the concrete R9 scenario: two 'requests' each inject function_id = -1
    cache_a._setFunctionEntry(-1, 7, b"A" * 64)
    cache_b._setFunctionEntry(-1, 9, b"B" * 64)
    got_a = cache_a.getMinHashByFunctionId(-1)
    got_b = cache_b.getMinHashByFunctionId(-1)
    if got_a != b"A" * 64 or got_b != b"B" * 64:
        failures.append("2: query-function minhash overwritten across caches (a=%r... b=%r...)" % (got_a[:2], got_b[:2]))
    else:
        print("ok 2: persist=on, per-request function_id=-1 entries do not collide")

    # 3. previous= retains entries across batches of one job
    retained = storage.createMatchingCache([], previous=cache_a)
    if retained is not cache_a or retained.getMinHashByFunctionId(-1) != b"A" * 64:
        failures.append("3: previous= does not retain the job's cache across batches")
    else:
        print("ok 3: persist=on, previous= retains the job-scoped cache across batches")

    # 4. persist off: fresh object every time, previous ignored
    storage_off = make_storage(persist=False)
    cache_c = storage_off.createMatchingCache([])
    cache_d = storage_off.createMatchingCache([], previous=cache_c)
    if cache_c is cache_d:
        failures.append("4: persist=off but caches are shared")
    else:
        print("ok 4: persist=off, every call returns a fresh cache")

    # 5. storage object holds no cache reference at all
    for attr in ("_matching_cache", "_matching_cache_evictable"):
        if getattr(storage, attr, None) is not None and getattr(storage, attr):
            failures.append("5: storage still holds state in %s" % attr)
    if not failures or not any(f.startswith("5") for f in failures):
        print("ok 5: storage object holds no matching-cache state")

    if failures:
        print("\nFAILED:")
        for failure in failures:
            print("  " + failure)
        sys.exit(1)
    print("\nall checks passed")


if __name__ == "__main__":
    main()
