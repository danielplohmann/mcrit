#!/usr/bin/env python3
"""Baseline: run one MatcherSample job against the live corpus, fully instrumented.

Runs the STOCK matching path (no MCRIT source changes) so the numbers are a true
"before" for the Tier 0/1/2 backlog.

Usage (inside the mcrit-worker container):
    python /opt/mcrit/bench/run_match.py <sample_id> [--k N] [--batch N]
                                          [--pool 0|1] [--tag NAME] [--out DIR]

Defaults for --k / --batch / --pool come from the live config, so a bare invocation
measures the deployment exactly as configured.
"""
import argparse
import json
import logging
import os
import platform
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, "/opt/mcrit")

from mcrit.config.McritConfig import McritConfig
from mcrit.matchers.MatcherSample import MatcherSample
from mcrit.minhash.MinHasher import MinHasher
from mcrit.queue.QueueRemoteCalls import NoProgressReporter
from mcrit.storage.StorageFactory import StorageFactory

from bench.instrument import DecodeProbe, MatcherProbe, MemSampler, MongoProbe, read_cgroup_mem

def _digest(match_report):
    """Stable fingerprint of the match result, so equivalence can be checked across variants."""
    import hashlib
    matches = match_report.get("matches", {})
    payload = json.dumps(matches, sort_keys=True, default=str)
    return {"sha256": hashlib.sha256(payload.encode()).hexdigest()[:32], "len": len(payload)}


logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)-7s %(name)-28s %(message)s")
LOGGER = logging.getLogger("bench")


class WorkerStub:
    """Minimal stand-in for Worker: what MatcherInterface actually touches."""

    def __init__(self, config, storage):
        self.config = config
        self._storage = storage
        self._minhash_config = config.MINHASH_CONFIG
        self._storage_config = config.STORAGE_CONFIG
        self._shingler_config = config.SHINGLER_CONFIG
        self._queue_config = config.QUEUE_CONFIG
        self.minhasher = MinHasher(config.MINHASH_CONFIG, config.SHINGLER_CONFIG)

    def getStorage(self):
        return self._storage


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sample_id", type=int)
    parser.add_argument("--k", type=int, default=None, help="band_matches_required (default: live config)")
    parser.add_argument("--batch", type=int, default=None, help="MINHASH_MATCHING_FUNCTION_BATCH_SIZE (default: live config)")
    parser.add_argument("--pool", type=int, default=None, help="1=multiprocessing pool, 0=single process (default: live config)")
    parser.add_argument("--persist-cache", type=int, default=None,
                        help="1=retain MatchingCache across batches, 0=rebuild per batch (default: live config)")
    parser.add_argument("--cache-max-entries", type=int, default=None)
    parser.add_argument("--cand-accum", choices=["dict", "numpy"], default=None,
                        help="candidate accumulation in getCandidatesForMinHashes (default: live config)")
    parser.add_argument("--fetch-threads", type=int, default=None, help="concurrent $in queries in _getCacheDataForFunctionIds")
    parser.add_argument("--fetch-slice", type=int, default=None, help="function_ids per $in query")
    parser.add_argument("--vectorized", type=int, default=None, help="1=vectorised scoring (B2), 0=stock per-pair scoring")
    parser.add_argument("--tag", default="baseline")
    parser.add_argument("--out", default="/opt/mcrit/bench/results")
    parser.add_argument("--mem-interval", type=float, default=0.05)
    args = parser.parse_args()

    config = McritConfig()
    if args.batch is not None:
        config.MINHASH_CONFIG.MINHASH_MATCHING_FUNCTION_BATCH_SIZE = args.batch
    if args.pool is not None:
        config.MINHASH_CONFIG.MINHASH_POOL_MATCHING = bool(args.pool)
    if args.persist_cache is not None:
        config.STORAGE_CONFIG.STORAGE_MATCHING_CACHE_PERSIST = bool(args.persist_cache)
    if args.cache_max_entries is not None:
        config.STORAGE_CONFIG.STORAGE_MATCHING_CACHE_MAX_ENTRIES = args.cache_max_entries
    if args.cand_accum is not None:
        config.STORAGE_CONFIG.STORAGE_CANDIDATE_ACCUMULATION = args.cand_accum
    if args.vectorized is not None:
        config.MINHASH_CONFIG.MINHASH_MATCHING_VECTORIZED = bool(args.vectorized)
    if args.fetch_threads is not None:
        config.STORAGE_CONFIG.STORAGE_CACHE_FETCH_THREADS = args.fetch_threads
    if args.fetch_slice is not None:
        config.STORAGE_CONFIG.STORAGE_CACHE_FETCH_SLICE_SIZE = args.fetch_slice
    band_matches_required = args.k if args.k is not None else config.MINHASH_CONFIG.BAND_MATCHES_REQUIRED

    os.makedirs(args.out, exist_ok=True)

    mongo = MongoProbe().start()
    decode = DecodeProbe().start()
    matcher_probe = MatcherProbe().start()

    storage = StorageFactory.getStorage(config)
    worker = WorkerStub(config, storage)

    # warm the sample metadata so the timed section is the matching job itself
    sample_entry = storage.getSampleById(args.sample_id)
    if sample_entry is None:
        print(json.dumps({"error": "sample_id %d not found" % args.sample_id}))
        return 2

    mem = MemSampler(interval=args.mem_interval)
    mem.start()

    matcher = MatcherSample(
        worker,
        minhash_threshold=config.MINHASH_CONFIG.MINHASH_MATCHING_THRESHOLD,
        pichash_size=config.MINHASH_CONFIG.PICHASH_SIZE,
        band_matches_required=band_matches_required,
        progress_reporter=NoProgressReporter(),
    )

    started = datetime.now(timezone.utc)
    t0 = time.perf_counter()
    match_report = matcher.getMatchesForSample(args.sample_id)
    wall_seconds = time.perf_counter() - t0

    mem.stop()
    matcher_probe.stop()
    decode.stop()
    mongo.stop()

    sample_dict = sample_entry.toDict()
    family = None
    try:
        family_entry = storage.getFamily(sample_dict.get("family_id"))
        family = family_entry.family_name if family_entry is not None else None
    except Exception:
        family = sample_dict.get("family")

    result = {
        "meta": {
            "tag": args.tag,
            "started_utc": started.isoformat(),
            "wall_seconds": round(wall_seconds, 3),
            "host_python": platform.python_version(),
            "mcrit_version": config.VERSION,
            "sample_id": args.sample_id,
            "family": family,
            "sample_version": sample_dict.get("version"),
            "num_functions_in_sample": sample_dict.get("statistics", {}).get("num_functions"),
        },
        "config": {
            "band_matches_required": band_matches_required,
            "batch_size": config.MINHASH_CONFIG.MINHASH_MATCHING_FUNCTION_BATCH_SIZE,
            "workpack_size": config.MINHASH_CONFIG.MINHASH_MATCHING_CANDIDATE_WORKPACK_SIZE,
            "pool_matching": config.MINHASH_CONFIG.MINHASH_POOL_MATCHING,
            "minhash_threshold": config.MINHASH_CONFIG.MINHASH_MATCHING_THRESHOLD,
            "storage_bands": {str(k): v for k, v in config.STORAGE_CONFIG.STORAGE_BANDS.items()},
            "band_strategy": getattr(config.STORAGE_CONFIG, "STORAGE_BAND_STRATEGY", "random"),
            "pichash_implies_minhash": config.MINHASH_CONFIG.PICHASH_IMPLIES_MINHASH_MATCH,
            "matching_cache_persist": getattr(config.STORAGE_CONFIG, "STORAGE_MATCHING_CACHE_PERSIST", False),
            "matching_cache_max_entries": getattr(config.STORAGE_CONFIG, "STORAGE_MATCHING_CACHE_MAX_ENTRIES", 0),
            "candidate_accumulation": getattr(config.STORAGE_CONFIG, "STORAGE_CANDIDATE_ACCUMULATION", "dict"),
            "vectorized_matching": getattr(config.MINHASH_CONFIG, "MINHASH_MATCHING_VECTORIZED", False),
            "cache_fetch_threads": getattr(config.STORAGE_CONFIG, "STORAGE_CACHE_FETCH_THREADS", 1),
            "cache_fetch_slice_size": getattr(config.STORAGE_CONFIG, "STORAGE_CACHE_FETCH_SLICE_SIZE", 500000),
        },
        "result_digest": _digest(match_report),
        "memory": mem.summary(),
        "matcher": matcher_probe.report(),
        "mongo": mongo.report(),
        "decode": decode.report(),
        "match_aggregation": match_report.get("matches", {}).get("aggregation"),
        "job_info": match_report.get("info", {}).get("job"),
    }

    name = "%s_s%d_k%d_b%d_%s%s.json" % (
        args.tag, args.sample_id, band_matches_required,
        config.MINHASH_CONFIG.MINHASH_MATCHING_FUNCTION_BATCH_SIZE,
        "pool" if config.MINHASH_CONFIG.MINHASH_POOL_MATCHING else "single",
        "_pcache" if getattr(config.STORAGE_CONFIG, "STORAGE_MATCHING_CACHE_PERSIST", False) else "",
    )
    name = name.replace(".json", "_%s%s.json" % (
        getattr(config.STORAGE_CONFIG, "STORAGE_CANDIDATE_ACCUMULATION", "dict"),
        "_vec" if getattr(config.MINHASH_CONFIG, "MINHASH_MATCHING_VECTORIZED", False) else ""))
    if getattr(config.STORAGE_CONFIG, "STORAGE_CACHE_FETCH_THREADS", 1) > 1:
        name = name.replace(".json", "_t%d.json" % config.STORAGE_CONFIG.STORAGE_CACHE_FETCH_THREADS)
    path = os.path.join(args.out, name)
    with open(path, "w") as fh:
        json.dump(result, fh, indent=2, default=str)
    # container runs as root; hand ownership back to whoever owns the output dir
    try:
        st = os.stat(args.out)
        os.chown(path, st.st_uid, st.st_gid)
    except OSError:
        pass

    m = result["memory"]
    mt = result["matcher"]
    print("wrote %s" % path)
    print("  wall %.1fs | container peak %.0f MiB | pairs %s | mongo %s calls / %.1f MiB / %.1fs" % (
        wall_seconds,
        (m.get("cgroup_peak_bytes") or 0) / 2 ** 20,
        mt["totals"]["n_pairs_entering_scoring"],
        result["mongo"]["total_logical_calls"],
        result["mongo"]["total_bytes"] / 2 ** 20,
        result["mongo"]["total_read_seconds"],
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
