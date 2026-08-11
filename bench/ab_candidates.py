#!/usr/bin/env python3
"""A/B the candidate-accumulation variants of getCandidatesForMinHashes.

Runs candidate retrieval only - no MatchingCache fetch, no scoring - over the same batches
MatcherInterface would walk, using one accumulation variant per process invocation. One
variant per process so the peak-RSS number is not confounded by the other variant's
high-water mark (CPython/glibc do not hand arenas back).

    python /opt/mcrit/bench/ab_candidates.py <sample_id> --accum dict|numpy
           [--k N] [--batch N] [--batches N] [--tag NAME]

Emits a per-batch equivalence digest (order-independent over the candidate sets), so
"result-preserving" is proven rather than assumed.
"""

import argparse
import hashlib
import json
import os
import resource
import sys
import time

sys.path.insert(0, "/opt/mcrit")

import numpy as np

from mcrit.config.McritConfig import McritConfig
from mcrit.storage.StorageFactory import StorageFactory


def read_rss_kb():
    with open("/proc/self/status") as fh:
        for line in fh:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return 0


def groups_digest(groups):
    """Order-independent sha256 over {query_fid: {candidate_fids}}."""
    hasher = hashlib.sha256()
    for function_id in sorted(groups):
        candidates = groups[function_id]
        hasher.update(b"%d:%d:" % (function_id, len(candidates)))
        if candidates:
            arr = np.fromiter(candidates, dtype=np.int64, count=len(candidates))
            arr.sort()
            hasher.update(arr.tobytes())
    return hasher.hexdigest()[:32]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sample_id", type=int)
    ap.add_argument("--accum", choices=["dict", "numpy"], required=True)
    ap.add_argument("--k", type=int, default=None)
    ap.add_argument("--batch", type=int, default=None)
    ap.add_argument("--batches", type=int, default=0, help="only the first N batches (0 = all)")
    ap.add_argument("--tag", default="ab")
    ap.add_argument("--out", default="/opt/mcrit/bench/results")
    args = ap.parse_args()

    config = McritConfig()
    if args.batch is not None:
        config.MINHASH_CONFIG.MINHASH_MATCHING_FUNCTION_BATCH_SIZE = args.batch
    config.STORAGE_CONFIG.STORAGE_CANDIDATE_ACCUMULATION = args.accum
    batch_size = config.MINHASH_CONFIG.MINHASH_MATCHING_FUNCTION_BATCH_SIZE
    k = args.k if args.k is not None else config.MINHASH_CONFIG.BAND_MATCHES_REQUIRED
    bits = config.MINHASH_CONFIG.MINHASH_SIGNATURE_BITS

    storage = StorageFactory.getStorage(config)
    function_entries = storage.getFunctionsBySampleId(args.sample_id)
    starts = list(range(0, len(function_entries), batch_size))
    if args.batches:
        starts = starts[: args.batches]

    rss_baseline_kb = read_rss_kb()
    per_batch = []
    total_seconds = 0.0
    total_digest = hashlib.sha256()
    for batch_index, start in enumerate(starts):
        fid_to_minhash = {fe.function_id: fe.getMinHash(minhash_bits=bits) for fe in function_entries[start : start + batch_size]}
        rss_before_kb = read_rss_kb()
        t0 = time.perf_counter()
        groups = storage.getCandidatesForMinHashes(fid_to_minhash, band_matches_required=k)
        elapsed = time.perf_counter() - t0
        rss_after_kb = read_rss_kb()
        total_seconds += elapsed
        digest = groups_digest(groups)
        total_digest.update(digest.encode())
        pairs = sum(len(v) for v in groups.values())
        per_batch.append(
            {
                "batch": batch_index,
                "seconds": round(elapsed, 4),
                "n_query_fns": len(fid_to_minhash),
                "n_query_fns_with_candidates": len(groups),
                "pairs": pairs,
                "max_candidates_one_query_fn": max((len(v) for v in groups.values()), default=0),
                "rss_before_mib": round(rss_before_kb / 1024, 1),
                "rss_after_mib": round(rss_after_kb / 1024, 1),
                "digest": digest,
            }
        )
        print("  batch %3d  %8.3fs  pairs %12s  rss %6.0f -> %6.0f MiB  %s" % (batch_index, elapsed, "{:,}".format(pairs), rss_before_kb / 1024, rss_after_kb / 1024, digest))
        del groups, fid_to_minhash

    peak_rss_mib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    result = {
        "tag": args.tag,
        "accum": args.accum,
        "sample_id": args.sample_id,
        "band_matches_required": k,
        "batch_size": batch_size,
        "n_batches": len(starts),
        "num_functions": len(function_entries),
        "candidate_retrieval_seconds": round(total_seconds, 3),
        "total_pairs": sum(b["pairs"] for b in per_batch),
        "peak_rss_mib": round(peak_rss_mib, 1),
        "rss_baseline_mib": round(rss_baseline_kb / 1024, 1),
        "digest_all_batches": total_digest.hexdigest()[:32],
        "per_batch": per_batch,
    }
    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, "cand_%s_s%d_k%d_b%d_%s.json" % (args.tag, args.sample_id, k, batch_size, args.accum))
    with open(path, "w") as fh:
        json.dump(result, fh, indent=2)
    try:
        st = os.stat(args.out)
        os.chown(path, st.st_uid, st.st_gid)
    except OSError:
        pass

    print()
    print(
        "accum=%-5s  batches=%d  retrieval %.2fs  pairs %s  peak RSS %.0f MiB  digest %s"
        % (args.accum, len(starts), total_seconds, "{:,}".format(result["total_pairs"]), peak_rss_mib, result["digest_all_batches"])
    )
    print("wrote %s" % path)


if __name__ == "__main__":
    main()
