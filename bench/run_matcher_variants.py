#!/usr/bin/env python3
"""Coverage check: do the session-02/03 flags preserve results on the OTHER matchers?

Every performance measurement in this project used MatcherSample. Fix 03 already carried one
bug that only MatcherQuery could have hit (query functions with no minhash), so "works on
MatcherSample" is not evidence for the rest. This runs each matcher twice - all flags off,
then all flags on - and compares a digest of the match report.

    python /opt/mcrit/bench/run_matcher_variants.py vs <sample_a> <sample_b> --flags 0|1
    python /opt/mcrit/bench/run_matcher_variants.py query <report.smda>    --flags 0|1
    python /opt/mcrit/bench/run_matcher_variants.py queryfunction <report.smda> --flags 0|1

NOTE: the query matchers call storage.addSmdaReport(isQuery=True), which WRITES a query
sample and its functions into the live database - exactly what mcritweb does on submit. This
script deletes what it created unless --keep is given.
"""

import argparse
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, "/opt/mcrit")

from smda.common.BinaryInfo import BinaryInfo
from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaReport import SmdaReport

from mcrit.config.McritConfig import McritConfig
from mcrit.matchers.MatcherQuery import MatcherQuery
from mcrit.matchers.MatcherQueryFunction import MatcherQueryFunction
from mcrit.matchers.MatcherVs import MatcherVs
from mcrit.minhash.MinHasher import MinHasher
from mcrit.queue.QueueRemoteCalls import NoProgressReporter
from mcrit.storage.StorageFactory import StorageFactory


def _canonicalize_query_ids(node, rank):
    """Replace query-side ids by their rank so two runs are comparable.

    The query matchers allocate sample_id and function_id from a counter
    (`_useCounter("query_samples")`), so a second run of the same report gets different
    negative ids and a raw digest would differ for reasons that have nothing to do with the
    flags under test. Only query-side ids are negative; corpus ids never are. Ranking them
    keeps the structure - including which query function matched what - fully comparable.
    """
    if isinstance(node, dict):
        return {_canonicalize_query_ids(k, rank): _canonicalize_query_ids(v, rank) for k, v in node.items()}
    if isinstance(node, list):
        return [_canonicalize_query_ids(v, rank) for v in node]
    if isinstance(node, bool):
        return node
    if isinstance(node, int) and node < 0:
        return "Q%d" % rank[node]
    if isinstance(node, str) and node.startswith("-") and node[1:].isdigit():
        value = int(node)
        if value in rank:
            return "Q%d" % rank[value]
    return node


def _collect_negative_ids(node, found):
    if isinstance(node, dict):
        for k, v in node.items():
            _collect_negative_ids(k, found)
            _collect_negative_ids(v, found)
    elif isinstance(node, list):
        for v in node:
            _collect_negative_ids(v, found)
    elif isinstance(node, bool):
        pass
    elif isinstance(node, int) and node < 0:
        found.add(node)
    elif isinstance(node, str) and node.startswith("-") and node[1:].isdigit():
        found.add(int(node))


def digest(match_report):
    matches = match_report.get("matches", {})
    negative_ids = set()
    _collect_negative_ids(matches, negative_ids)
    rank = {value: index for index, value in enumerate(sorted(negative_ids, reverse=True))}
    canonical = _canonicalize_query_ids(matches, rank) if rank else matches
    payload = json.dumps(canonical, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()[:32], len(payload), len(negative_ids)


class WorkerStub:
    """Same stand-in run_match.py uses, plus what the query matchers touch."""

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

    def calculateMinHashes(self, function_entries):
        # mirrors Worker.calculateMinHashes' non-pooled branch, including the
        # isMinHashableFunction filter - which is what leaves ~36 % of functions with no
        # minhash at all, the case that broke fix 03 on the query path
        smda_functions = []
        for function_entry in function_entries:
            binary_info = BinaryInfo(b"")
            binary_info.architecture = function_entry.architecture
            smda_functions.append((function_entry.function_id, SmdaFunction.fromDict(function_entry.xcfg, binary_info=binary_info)))
        smda_functions = [(function_id, smda_function) for function_id, smda_function in smda_functions if self.minhasher.isMinHashableFunction(smda_function)]
        return self.minhasher.calculateMinHashesFromStorage(smda_functions)


def apply_flags(config, enabled, cache_max_entries, fetch_threads, fetch_slice, hot_collection=None):
    config.MINHASH_CONFIG.MINHASH_POOL_MATCHING = False  # determinism, BUG-1
    config.STORAGE_CONFIG.STORAGE_MATCHING_CACHE_PERSIST = enabled
    config.STORAGE_CONFIG.STORAGE_CANDIDATE_ACCUMULATION = "numpy" if enabled else "dict"
    config.MINHASH_CONFIG.MINHASH_MATCHING_VECTORIZED = enabled
    config.STORAGE_CONFIG.STORAGE_CACHE_FETCH_THREADS = fetch_threads if enabled else 1
    config.STORAGE_CONFIG.STORAGE_CACHE_FETCH_SLICE_SIZE = fetch_slice if enabled else 500000
    if enabled:
        config.STORAGE_CONFIG.STORAGE_MATCHING_CACHE_MAX_ENTRIES = cache_max_entries
    if hot_collection is not None:
        config.STORAGE_CONFIG.STORAGE_HOT_MINHASH_COLLECTION = hot_collection


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("matcher", choices=["vs", "query", "queryfunction"])
    ap.add_argument("args", nargs="+")
    ap.add_argument("--flags", type=int, required=True, help="0 = all off (stock), 1 = all on")
    ap.add_argument("--k", type=int, default=None)
    ap.add_argument("--cache-max-entries", type=int, default=6000000)
    ap.add_argument("--fetch-threads", type=int, default=8)
    ap.add_argument("--fetch-slice", type=int, default=25000)
    ap.add_argument("--hot-collection", default=None, help='C1: "db.collection" slim minhash source; "" = off')
    ap.add_argument("--keep", action="store_true", help="do not delete the query sample created")
    ap.add_argument("--out", default="/opt/mcrit/bench/results")
    opts = ap.parse_args()

    config = McritConfig()
    apply_flags(config, bool(opts.flags), opts.cache_max_entries, opts.fetch_threads, opts.fetch_slice, opts.hot_collection)
    band_matches_required = opts.k if opts.k is not None else config.MINHASH_CONFIG.BAND_MATCHES_REQUIRED

    storage = StorageFactory.getStorage(config)
    worker = WorkerStub(config, storage)
    common = dict(
        minhash_threshold=config.MINHASH_CONFIG.MINHASH_MATCHING_THRESHOLD,
        pichash_size=config.MINHASH_CONFIG.PICHASH_SIZE,
        band_matches_required=band_matches_required,
        progress_reporter=NoProgressReporter(),
    )

    created_query_sample_id = None
    t0 = time.perf_counter()
    if opts.matcher == "vs":
        sample_a, sample_b = int(opts.args[0]), int(opts.args[1])
        matcher = MatcherVs(worker, **common)
        report = matcher.getMatchesForSample(sample_a, sample_b)
        label = "vs_%d_%d" % (sample_a, sample_b)
    else:
        report_path = opts.args[0]
        with open(report_path) as fh:
            smda_report = SmdaReport.fromDict(json.load(fh))
        if opts.matcher == "query":
            matcher = MatcherQuery(worker, **common)
            report = matcher.getMatchesForSmdaReport(smda_report)
        else:
            matcher = MatcherQueryFunction(worker, **common)
            report = matcher.getMatchesForSmdaFunction(smda_report)
        # only MatcherQuery actually writes a query sample; MatcherQueryFunction builds its
        # SampleEntry in memory, so deleting its _sample_id would delete something we did not
        # create
        if opts.matcher == "query":
            created_query_sample_id = getattr(matcher, "_sample_id", None)
        label = "%s_%s" % (opts.matcher, os.path.basename(report_path).replace(".smda", ""))
    wall = time.perf_counter() - t0

    sha, length, n_query_ids = digest(report)
    result = {
        "matcher": opts.matcher,
        "label": label,
        "flags_on": bool(opts.flags),
        "band_matches_required": band_matches_required,
        "wall_seconds": round(wall, 3),
        "digest": sha,
        "digest_len": length,
        "n_canonicalized_query_ids": n_query_ids,
        "n_matched_functions": len(report.get("matches", {}).get("functions", []) or []),
        "query_sample_id": created_query_sample_id,
    }
    os.makedirs(opts.out, exist_ok=True)
    hot_suffix = "_hot" if opts.hot_collection else ""
    path = os.path.join(opts.out, "matcher_%s_flags%d%s.json" % (label, opts.flags, hot_suffix))
    with open(path, "w") as fh:
        json.dump(result, fh, indent=2, default=str)
    try:
        st = os.stat(opts.out)
        os.chown(path, st.st_uid, st.st_gid)
    except OSError:
        pass

    if created_query_sample_id is not None and created_query_sample_id < 0 and not opts.keep:
        storage.deleteSample(created_query_sample_id)
        print("deleted query sample %d" % created_query_sample_id)

    print("%-28s flags=%d  %8.2fs  digest %s (len %d, %d query ids canonicalized)" % (label, opts.flags, wall, sha, length, n_query_ids))
    return 0


if __name__ == "__main__":
    sys.exit(main())
