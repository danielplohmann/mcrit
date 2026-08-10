#!/usr/bin/env python3
"""Build a side database for isolating B1 (binary minhash) and C1 (xcfg split).

Creates, in database `mcrit_bench`:
  fn_hex : {function_id, sample_id, minhash}  minhash as the current 128-char hex string
  fn_bin : {function_id, sample_id, minhash}  minhash as bson.Binary (64 raw bytes)

Both carry an index on function_id, matching `functions`. Comparing a
`_getCacheDataForFunctionIds`-shaped query across live `functions` / fn_hex / fn_bin gives:

  functions -> fn_hex   the cost of dragging _xcfg along on a projected read   (C1)
  fn_hex    -> fn_bin   the cost of the hex encoding                           (B1)

READ-ONLY with respect to the live `mcrit` database.
"""
import argparse
import sys
import time

from bson import Binary
from pymongo import MongoClient, ASCENDING


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--uri", default="mongodb://mongodb:27017")
    ap.add_argument("--src-db", default="mcrit")
    ap.add_argument("--dst-db", default="mcrit_bench")
    ap.add_argument("--batch", type=int, default=20000)
    ap.add_argument("--drop", action="store_true", help="drop destination collections first")
    args = ap.parse_args()

    client = MongoClient(args.uri)
    src = client[args.src_db]
    dst = client[args.dst_db]

    if args.drop:
        dst.fn_hex.drop()
        dst.fn_bin.drop()
        print("dropped existing fn_hex / fn_bin")

    total = src.functions.estimated_document_count()
    print("source functions: %s" % "{:,}".format(total))

    cursor = src.functions.find(
        {}, {"_id": 0, "function_id": 1, "sample_id": 1, "minhash": 1}, no_cursor_timeout=True
    ).batch_size(args.batch)

    hex_batch, bin_batch = [], []
    n = 0
    n_no_minhash = 0
    t0 = time.perf_counter()
    try:
        for doc in cursor:
            mh = doc.get("minhash", "")
            fid = doc["function_id"]
            sid = doc["sample_id"]
            hex_batch.append({"function_id": fid, "sample_id": sid, "minhash": mh})
            if mh:
                bin_batch.append({"function_id": fid, "sample_id": sid, "minhash": Binary(bytes.fromhex(mh))})
            else:
                n_no_minhash += 1
                bin_batch.append({"function_id": fid, "sample_id": sid, "minhash": Binary(b"")})
            n += 1
            if len(hex_batch) >= args.batch:
                dst.fn_hex.insert_many(hex_batch, ordered=False)
                dst.fn_bin.insert_many(bin_batch, ordered=False)
                hex_batch, bin_batch = [], []
                elapsed = time.perf_counter() - t0
                print("  %s / %s  (%.1f%%)  %.0f docs/s  %.0fs elapsed" % (
                    "{:,}".format(n), "{:,}".format(total), 100.0 * n / total,
                    n / elapsed, elapsed), flush=True)
    finally:
        cursor.close()

    if hex_batch:
        dst.fn_hex.insert_many(hex_batch, ordered=False)
        dst.fn_bin.insert_many(bin_batch, ordered=False)

    print("copied %s documents (%s without a minhash) in %.0fs" % (
        "{:,}".format(n), "{:,}".format(n_no_minhash), time.perf_counter() - t0))

    for coll in (dst.fn_hex, dst.fn_bin):
        t = time.perf_counter()
        coll.create_index([("function_id", ASCENDING)])
        print("indexed %s in %.0fs" % (coll.name, time.perf_counter() - t))

    print()
    for name in ("fn_hex", "fn_bin"):
        s = dst.command("collstats", name)
        print("%-8s count=%-12s size=%8.2f GB  storage=%8.2f GB  index=%6.2f GB  avgObj=%d B" % (
            name, "{:,}".format(s["count"]), s["size"] / 1e9, s["storageSize"] / 1e9,
            s["totalIndexSize"] / 1e9, s.get("avgObjSize", 0)))
    s = src.command("collstats", "functions")
    print("%-8s count=%-12s size=%8.2f GB  storage=%8.2f GB  index=%6.2f GB  avgObj=%d B" % (
        "functions", "{:,}".format(s["count"]), s["size"] / 1e9, s["storageSize"] / 1e9,
        s["totalIndexSize"] / 1e9, s.get("avgObjSize", 0)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
