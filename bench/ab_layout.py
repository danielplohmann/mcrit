#!/usr/bin/env python3
"""A/B the `_getCacheDataForFunctionIds` query across three document layouts.

  functions  live, fat documents (_xcfg ~86% of bytes), minhash as 128-char hex
  fn_hex     slim {function_id, sample_id, minhash}, minhash as hex
  fn_bin     slim, minhash as bson.Binary (64 raw bytes)

  functions -> fn_hex   isolates C1 (cost of dragging _xcfg through a projected read)
  fn_hex    -> fn_bin   isolates B1 (cost of the hex encoding)

The same function_id set is used for all three, read from --ids (produced by --make-ids),
so the layouts are the only variable.

Cache state moves identical work by up to 3x on this box, so each layout is measured cold
(caller restarts mongod first, see ab_layout.sh) and then warm on an immediate repeat.
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, "/opt/mcrit")

from bson import Binary  # noqa: F401  (documents the encoding under test)
from pymongo import MongoClient

from bench.instrument import MongoProbe

PROJECTION = {"_id": 0, "sample_id": 1, "minhash": 1, "function_id": 1}


def make_ids(uri, db_name, sample_id, k, batch, limit, out_path):
    """Materialise a realistic candidate id set: the cache ids of one matcher batch."""
    from mcrit.config.McritConfig import McritConfig
    from mcrit.storage.StorageFactory import StorageFactory

    config = McritConfig()
    if batch:
        config.MINHASH_CONFIG.MINHASH_MATCHING_FUNCTION_BATCH_SIZE = batch
    storage = StorageFactory.getStorage(config)
    entries = storage.getFunctionsBySampleId(sample_id)
    bits = config.MINHASH_CONFIG.MINHASH_SIGNATURE_BITS
    bsize = config.MINHASH_CONFIG.MINHASH_MATCHING_FUNCTION_BATCH_SIZE
    fid_to_mh = {fe.function_id: fe.getMinHash(minhash_bits=bits) for fe in entries[:bsize]}
    groups = storage.getCandidatesForMinHashes(fid_to_mh, band_matches_required=k)
    ids = set()
    for key, vals in groups.items():
        ids.add(key)
        ids.update(vals)
    ids = sorted(i for i in ids if i >= 0)
    if limit and len(ids) > limit:
        step = len(ids) / float(limit)
        ids = [ids[int(i * step)] for i in range(limit)]
    with open(out_path, "w") as fh:
        json.dump({"sample_id": sample_id, "k": k, "batch": bsize, "n_ids": len(ids), "ids": ids}, fh)
    print("wrote %s ids to %s" % ("{:,}".format(len(ids)), out_path))


def _fetch_chunk(collection, chunk):
    decoded = []
    for doc in collection.find({"function_id": {"$in": chunk}}, PROJECTION):
        mh = doc["minhash"]
        # hex layouts need the decode; Binary is already bytes (this IS the B1 win)
        decoded.append((doc["function_id"], doc["sample_id"], bytes.fromhex(mh) if isinstance(mh, str) else bytes(mh)))
    return decoded


def fetch(collection, ids, slice_size=500000, threads=1):
    """Mirror of MongoDbStorage._getCacheDataForFunctionIds' read + decode."""
    minhashes = {}
    sample_ids = {}
    n_docs = 0
    chunks = [ids[start : start + slice_size] for start in range(0, len(ids), slice_size)]
    if threads > 1 and len(chunks) > 1:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=min(threads, len(chunks))) as pool:
            results = list(pool.map(lambda c: _fetch_chunk(collection, c), chunks))
    else:
        results = [_fetch_chunk(collection, c) for c in chunks]
    for decoded in results:
        for function_id, sample_id, minhash in decoded:
            minhashes[function_id] = minhash
            sample_ids[function_id] = sample_id
            n_docs += 1
    return n_docs, len(minhashes), len(sample_ids)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--uri", default="mongodb://mongodb:27017")
    ap.add_argument("--ids", default="/opt/mcrit/bench/results/ab_ids.json")
    ap.add_argument("--layout", choices=["functions", "fn_hex", "fn_bin"], required=False)
    ap.add_argument("--repeats", type=int, default=2, help="1st = cold (after restart), rest = warm")
    ap.add_argument("--out", default="/opt/mcrit/bench/results/ab_layout_results.jsonl")
    ap.add_argument("--make-ids", action="store_true")
    ap.add_argument("--sample-id", type=int, default=5188)
    ap.add_argument("--k", type=int, default=2)
    ap.add_argument("--batch", type=int, default=None)
    ap.add_argument("--limit", type=int, default=300000)
    ap.add_argument("--threads", type=int, default=1, help="concurrent $in queries")
    ap.add_argument("--slice", type=int, default=500000, help="function_ids per $in query")
    args = ap.parse_args()

    if args.make_ids:
        make_ids(args.uri, "mcrit", args.sample_id, args.k, args.batch, args.limit, args.ids)
        return 0

    with open(args.ids) as fh:
        ids = json.load(fh)["ids"]

    db_name, coll_name = ("mcrit", "functions") if args.layout == "functions" else ("mcrit_bench", args.layout)

    probe = MongoProbe().start()
    client = MongoClient(args.uri)
    collection = client[db_name][coll_name]

    rows = []
    for rep in range(args.repeats):
        before_bytes = sum(probe.read_bytes.values())
        t0 = time.perf_counter()
        n_docs, n_mh, n_sid = fetch(collection, ids, slice_size=args.slice, threads=args.threads)
        elapsed = time.perf_counter() - t0
        wire = sum(probe.read_bytes.values()) - before_bytes
        row = {
            "layout": args.layout,
            "threads": args.threads,
            "slice": args.slice,
            "db": db_name,
            "rep": rep,
            "state": "cold" if rep == 0 else "warm",
            "n_ids": len(ids),
            "n_docs": n_docs,
            "seconds": round(elapsed, 3),
            "wire_bytes": wire,
            "bytes_per_doc": round(wire / n_docs, 1) if n_docs else 0,
            "docs_per_second": round(n_docs / elapsed) if elapsed else 0,
        }
        rows.append(row)
        print(
            "%-10s t%-2d %-5s  %8.3fs  %7.1f MB  %6.1f B/doc  %s docs/s"
            % (args.layout, args.threads, row["state"], elapsed, wire / 1e6, row["bytes_per_doc"], "{:,}".format(row["docs_per_second"])),
            flush=True,
        )

    probe.stop()
    with open(args.out, "a") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    try:
        st = os.stat(os.path.dirname(args.out))
        os.chown(args.out, st.st_uid, st.st_gid)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
