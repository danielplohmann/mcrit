#!/usr/bin/env python3
"""How much of the per-batch MatchingCache rebuild is redundant?

Walks the same batches MatcherInterface would, computes candidate_groups per batch, and
tracks per-batch cache size vs the cumulative distinct union. The ratio is exactly the
redundancy factor an incremental (job-scoped) cache would eliminate.

Runs candidate retrieval only - no cache fetch, no scoring - so it is far cheaper than a
full match.
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, "/opt/mcrit")

from mcrit.config.McritConfig import McritConfig
from mcrit.minhash.MinHasher import MinHasher
from mcrit.storage.StorageFactory import StorageFactory


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sample_id", type=int)
    ap.add_argument("--k", type=int, default=None)
    ap.add_argument("--batch", type=int, default=None)
    ap.add_argument("--out", default="/opt/mcrit/bench/results")
    args = ap.parse_args()

    config = McritConfig()
    if args.batch is not None:
        config.MINHASH_CONFIG.MINHASH_MATCHING_FUNCTION_BATCH_SIZE = args.batch
    batch_size = config.MINHASH_CONFIG.MINHASH_MATCHING_FUNCTION_BATCH_SIZE
    k = args.k if args.k is not None else config.MINHASH_CONFIG.BAND_MATCHES_REQUIRED
    bits = config.MINHASH_CONFIG.MINHASH_SIGNATURE_BITS

    storage = StorageFactory.getStorage(config)
    function_entries = storage.getFunctionsBySampleId(args.sample_id)
    print("sample %d: %d functions, batch=%d, k=%d" % (args.sample_id, len(function_entries), batch_size, k))

    union = set()
    per_batch = []
    total_fetched = 0
    t0 = time.perf_counter()
    for start in range(0, len(function_entries), batch_size):
        fid_to_minhash = {fe.function_id: fe.getMinHash(minhash_bits=bits) for fe in function_entries[start : start + batch_size]}
        groups = storage.getCandidatesForMinHashes(fid_to_minhash, band_matches_required=k)
        ids = set()
        for key, values in groups.items():
            ids.add(key)
            ids.update(values)
        before = len(union)
        union |= ids
        total_fetched += len(ids)
        per_batch.append(
            {
                "batch": len(per_batch),
                "cache_ids": len(ids),
                "new_ids": len(union) - before,
                "union_so_far": len(union),
                "pairs": sum(len(v) for v in groups.values()),
            }
        )
        print("  batch %3d: cache_ids %9d  new %9d  union %9d" % (per_batch[-1]["batch"], len(ids), per_batch[-1]["new_ids"], len(union)))

    elapsed = time.perf_counter() - t0
    result = {
        "sample_id": args.sample_id,
        "num_functions": len(function_entries),
        "batch_size": batch_size,
        "band_matches_required": k,
        "n_batches": len(per_batch),
        "total_cache_fetches_current": total_fetched,
        "distinct_union": len(union),
        "redundancy_factor": round(total_fetched / len(union), 2) if union else None,
        "corpus_fraction_touched": round(len(union) / 11697468, 4),
        "candidate_retrieval_seconds": round(elapsed, 1),
        "per_batch": per_batch,
    }
    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, "overlap_s%d_k%d_b%d.json" % (args.sample_id, k, batch_size))
    with open(path, "w") as fh:
        json.dump(result, fh, indent=2)
    try:
        st = os.stat(args.out)
        os.chown(path, st.st_uid, st.st_gid)
    except OSError:
        pass

    print()
    print("current implementation fetches : %s records" % "{:,}".format(total_fetched))
    print("distinct union (incremental)   : %s records" % "{:,}".format(len(union)))
    print("REDUNDANCY FACTOR              : %.2fx" % result["redundancy_factor"])
    print("union is %.2f%% of the 11.7M-function corpus" % (100 * result["corpus_fraction_touched"]))
    print("wrote %s" % path)


if __name__ == "__main__":
    main()
