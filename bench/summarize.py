#!/usr/bin/env python3
"""Aggregate bench/results/*.json into comparison tables."""
import glob
import json
import os
import sys

MIB = 2 ** 20

# pymongo runs a background topology monitor whose blocking heartbeat reads land in
# receive_data from a non-MCRIT frame. It transfers ~0 bytes but accumulates wall time,
# so it must be excluded from "time blocked on the database".
def app_sites(run):
    return [s for s in run["mongo"]["by_site"] if "MongoDbStorage" in s["site"] or "mcrit" in s["site"].lower()]


def mongo_blocked_seconds(run):
    return sum(s["read_seconds"] for s in app_sites(run))


def mongo_bytes(run):
    return sum(s["bytes"] for s in app_sites(run))


def load(pattern):
    rows = []
    for path in sorted(glob.glob(pattern)):
        if os.path.basename(path) == "sweep.log":
            continue
        try:
            with open(path) as fh:
                d = json.load(fh)
        except Exception as exc:
            print("skip %s (%s)" % (path, exc), file=sys.stderr)
            continue
        d["_path"] = path
        rows.append(d)
    return rows


def main():
    pattern = sys.argv[1] if len(sys.argv) > 1 else "/opt/mcrit/bench/results/*.json"
    rows = load(pattern)
    if not rows:
        print("no results")
        return

    print("=" * 118)
    print("RUNS  (k=band_matches_required, b=batch size)")
    print("=" * 118)
    hdr = "%-14s %-6s %6s %-6s %8s %9s %9s %11s %11s %8s %8s %7s"
    print(hdr % ("family", "sample", "k/b", "pool", "wall_s", "peak_MiB", "self_MiB",
                 "pairs", "cached_fns", "mongo_MB", "mongo_s", "calls"))
    key = lambda r: (r["meta"].get("num_functions_in_sample") or 0, r["meta"]["tag"])
    for r in sorted(rows, key=key):
        m, c, mem, mt, mg = r["meta"], r["config"], r["memory"], r["matcher"], r["mongo"]
        print(hdr % (
            (m.get("family") or "?")[:14],
            m["sample_id"],
            "%d/%d" % (c["band_matches_required"], c["batch_size"]),
            "pool" if c["pool_matching"] else "single",
            "%.1f" % m["wall_seconds"],
            "%.0f" % ((mem.get("cgroup_peak_bytes") or 0) / MIB),
            "%.0f" % ((mem.get("self_rss_peak_bytes") or 0) / MIB),
            "{:,}".format(mt["totals"]["n_pairs_entering_scoring"]),
            "{:,}".format(mt["totals"]["n_cached_functions"]),
            "%.1f" % (mongo_bytes(r) / 1e6),
            "%.1f" % mongo_blocked_seconds(r),
            mg["total_logical_calls"],
        ))

    print()
    print("=" * 118)
    print("PHASE BREAKDOWN (seconds)")
    print("=" * 118)
    phase_names = []
    for r in rows:
        for p in r["matcher"]["phases_seconds"]:
            if p not in phase_names:
                phase_names.append(p)
    print("%-14s %-6s %-6s %8s  " % ("family", "sample", "pool", "wall_s")
          + " ".join("%18s" % p[:18] for p in phase_names))
    for r in sorted(rows, key=key):
        m, c, mt = r["meta"], r["config"], r["matcher"]
        cells = []
        for p in phase_names:
            v = mt["phases_seconds"].get(p, 0.0)
            cells.append("%18s" % ("%.2f (%d%%)" % (v, round(100 * v / m["wall_seconds"]))))
        print("%-14s %-6s %-6s %8.1f  " % ((m.get("family") or "?")[:14], m["sample_id"],
                                           "pool" if c["pool_matching"] else "single",
                                           m["wall_seconds"]) + " ".join(cells))

    print()
    print("=" * 118)
    print("TOP MONGO CALL SITES (aggregated across runs: calls, bytes, seconds blocked)")
    print("=" * 118)
    agg = {}
    for r in rows:
        for s in app_sites(r):
            a = agg.setdefault(s["site"], {"calls": 0, "bytes": 0, "read_seconds": 0.0, "runs": 0})
            a["calls"] += s["logical_calls"]
            a["bytes"] += s["bytes"]
            a["read_seconds"] += s["read_seconds"]
            a["runs"] += 1
    print("%-52s %10s %12s %10s %6s" % ("site", "calls", "MB", "read_s", "runs"))
    for site, a in sorted(agg.items(), key=lambda x: -x[1]["bytes"])[:14]:
        print("%-52s %10s %12.1f %10.1f %6d" % (site[:52], "{:,}".format(a["calls"]),
                                                a["bytes"] / 1e6, a["read_seconds"], a["runs"]))

    print()
    print("=" * 118)
    print("SCORING THROUGHPUT (single-process runs only; pool children are not instrumented)")
    print("=" * 118)
    for r in sorted(rows, key=key):
        mt = r["matcher"]
        if not r["config"]["pool_matching"] and mt["score_seconds"]:
            print("  %-14s s%-6s %10s pairs in %7.2fs = %10s pairs/s" % (
                (r["meta"].get("family") or "?")[:14], r["meta"]["sample_id"],
                "{:,}".format(mt["score_pairs"]), mt["score_seconds"],
                "{:,.0f}".format(mt["score_pairs_per_second"] or 0)))

    print()
    print("=" * 118)
    print("DECODE")
    print("=" * 118)
    for r in sorted(rows, key=key):
        if r["config"]["pool_matching"]:
            continue
        d = r["decode"]
        tot = sum(v["seconds"] for v in d.values())
        print("  %-14s s%-6s decode total %6.2fs (%4.1f%% of wall)  %s" % (
            (r["meta"].get("family") or "?")[:14], r["meta"]["sample_id"], tot,
            100 * tot / r["meta"]["wall_seconds"],
            ", ".join("%s %.2fs/%d calls" % (k, v["seconds"], v["calls"]) for k, v in list(d.items())[:3])))


if __name__ == "__main__":
    main()
