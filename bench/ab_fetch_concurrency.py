#!/usr/bin/env python3
"""Does concurrency help the call that now dominates matching?

After the session-03 fixes, `_getCacheDataForFunctionIds` is ~67 % of wall on k=1 samples and
almost all of that is blocked on the socket, not on CPU. That is latency, not bandwidth: the
query returns 186 B per document but WiredTiger reads the whole 4,188 B record to do it. If
it is latency-bound, issuing several queries concurrently should overlap mongod's disk reads
and the wall time should fall well short of linearly with thread count.

This fetches one fixed, deterministic set of function_ids at several thread counts and
compares. Threads, not processes: pymongo releases the GIL for socket I/O and BSON decode.

    python /opt/mcrit/bench/ab_fetch_concurrency.py [--ids N] [--threads 1,2,4,8] [--reps 2]
"""
import argparse
import hashlib
import json
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, "/opt/mcrit")

from mcrit.config.McritConfig import McritConfig
from mcrit.storage.StorageFactory import StorageFactory

PROJECTION = {"_id": 0, "sample_id": 1, "minhash": 1, "function_id": 1}


def fetch_slice(db, function_ids):
    """One $in query, decoded exactly like _getCacheDataForFunctionIds does."""
    found = 0
    checksum = 0
    for document in db["functions"].find({"function_id": {"$in": function_ids}}, PROJECTION):
        minhash = bytes.fromhex(document["minhash"])
        checksum ^= document["function_id"] * 31 + len(minhash)
        found += 1
    return found, checksum


def run(db, all_ids, threads, slice_size):
    slices = [all_ids[i:i + slice_size] for i in range(0, len(all_ids), slice_size)]
    t0 = time.perf_counter()
    if threads == 1:
        results = [fetch_slice(db, s) for s in slices]
    else:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            results = list(pool.map(lambda s: fetch_slice(db, s), slices))
    elapsed = time.perf_counter() - t0
    found = sum(r[0] for r in results)
    checksum = 0
    for _, c in results:
        checksum ^= c
    return elapsed, found, checksum


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", type=int, default=500000)
    ap.add_argument("--slice", type=int, default=25000, help="function_ids per $in query")
    ap.add_argument("--threads", default="1,2,4,8")
    ap.add_argument("--reps", type=int, default=2)
    ap.add_argument("--max-function-id", type=int, default=11697468)
    ap.add_argument("--seed", type=int, default=0xC0FFEE)
    ap.add_argument("--out", default="/opt/mcrit/bench/results")
    args = ap.parse_args()

    thread_counts = [int(t) for t in args.threads.split(",")]

    config = McritConfig()
    storage = StorageFactory.getStorage(config)
    db = storage._getDb()

    rng = random.Random(args.seed)
    all_ids = sorted(rng.sample(range(1, args.max_function_id + 1), args.ids))
    print("fetching %s function_ids in slices of %s, threads %s, %d reps" % (
        "{:,}".format(len(all_ids)), "{:,}".format(args.slice), thread_counts, args.reps))

    # interleave forwards then backwards so cache warming is not confused with concurrency
    order = []
    for rep in range(args.reps):
        order.extend(thread_counts if rep % 2 == 0 else list(reversed(thread_counts)))

    observations = []
    checksums = set()
    for threads in order:
        elapsed, found, checksum = run(db, all_ids, threads, args.slice)
        checksums.add((found, checksum))
        observations.append({"threads": threads, "seconds": round(elapsed, 3), "docs": found})
        print("  threads %2d  %8.3f s  %s docs  %s docs/s" % (
            threads, elapsed, "{:,}".format(found), "{:,}".format(int(found / elapsed))))

    print()
    print("result identical across all runs: %s" % (len(checksums) == 1))
    best = {}
    for observation in observations:
        best.setdefault(observation["threads"], []).append(observation["seconds"])
    baseline = min(best[thread_counts[0]])
    summary = []
    for threads in thread_counts:
        fastest = min(best[threads])
        summary.append({"threads": threads, "best_seconds": fastest,
                        "speedup_vs_%d" % thread_counts[0]: round(baseline / fastest, 2)})
        print("  threads %2d  best %8.3f s  %.2fx" % (threads, fastest, baseline / fastest))

    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, "fetch_concurrency_%d.json" % args.ids)
    with open(path, "w") as fh:
        json.dump({"ids": args.ids, "slice": args.slice, "reps": args.reps,
                   "identical": len(checksums) == 1, "observations": observations,
                   "summary": summary}, fh, indent=2)
    try:
        st = os.stat(args.out)
        os.chown(path, st.st_uid, st.st_gid)
    except OSError:
        pass
    print("wrote %s" % path)


if __name__ == "__main__":
    main()
