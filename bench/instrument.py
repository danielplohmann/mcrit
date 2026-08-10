"""Non-invasive instrumentation for MCRIT matching baselines.

Monkeypatches only - no MCRIT source is modified. Captures the buckets asked for in
mcrit-mongo-first-backlog.md section 3:

  db_wait   - time blocked on pymongo, split by CALL SITE, with n_calls and bytes_returned
  decode    - bytes.fromhex / json.loads / *Entry.fromDict
  score     - time inside calculateScoresFromPackedTuples, plus n_pairs
  memory    - cgroup memory.current (whole container, incl. spawn pool children) + self RSS
  candidates- candidate/pair counts per batch, pre- and post-band-threshold

Bytes are counted at pymongo's socket read (network_layer.receive_data), which is exact
wire volume and costs O(1) per read, so it does not distort the timings.
"""
import functools
import json
import os
import sys
import threading
import time
from collections import defaultdict
from contextlib import contextmanager

# ---------------------------------------------------------------- memory


def read_cgroup_mem():
    for path in ("/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory/memory.usage_in_bytes"):
        try:
            with open(path) as fh:
                return int(fh.read().strip())
        except OSError:
            continue
    return None


def read_self_rss():
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    return 0


class MemSampler(threading.Thread):
    """Samples container memory and own RSS in the background."""

    def __init__(self, interval=0.05):
        super().__init__(daemon=True)
        self.interval = interval
        self.samples = []  # (t_rel, cgroup_bytes, self_rss_bytes)
        self._stop_event = threading.Event()
        self._t0 = time.monotonic()

    def run(self):
        while not self._stop_event.is_set():
            self.samples.append((time.monotonic() - self._t0, read_cgroup_mem(), read_self_rss()))
            self._stop_event.wait(self.interval)

    def stop(self):
        self._stop_event.set()
        self.join(timeout=2.0)

    def summary(self):
        if not self.samples:
            return {}
        cg = [s[1] for s in self.samples if s[1] is not None]
        rss = [s[2] for s in self.samples]
        return {
            "n_samples": len(self.samples),
            "cgroup_peak_bytes": max(cg) if cg else None,
            "cgroup_start_bytes": cg[0] if cg else None,
            "self_rss_peak_bytes": max(rss),
            "self_rss_start_bytes": rss[0],
        }


# ---------------------------------------------------------------- phases


class Phases:
    def __init__(self):
        self.seconds = defaultdict(float)
        self.calls = defaultdict(int)

    @contextmanager
    def __call__(self, name):
        t0 = time.perf_counter()
        try:
            yield
        finally:
            self.seconds[name] += time.perf_counter() - t0
            self.calls[name] += 1


# ---------------------------------------------------------------- call sites

_BENCH_DIR = os.path.dirname(os.path.abspath(__file__))


def _caller_site(skip_substrings=("pymongo", "bson", _BENCH_DIR)):
    """First stack frame outside pymongo/bson/this module, as 'basename:lineno in func'."""
    frame = sys._getframe(1)
    while frame is not None:
        fn = frame.f_code.co_filename
        if not any(s in fn for s in skip_substrings):
            return "%s:%d %s" % (os.path.basename(fn), frame.f_lineno, frame.f_code.co_name)
        frame = frame.f_back
    return "<unknown>"


# ---------------------------------------------------------------- mongo probe


class MongoProbe:
    """Counts pymongo logical calls and exact wire bytes, attributed to call site."""

    COLLECTION_METHODS = (
        "find", "find_one", "aggregate", "count_documents", "estimated_document_count",
        "distinct", "bulk_write", "update_one", "update_many", "insert_one",
        "insert_many", "delete_one", "delete_many", "find_one_and_update",
    )

    def __init__(self):
        self.calls = defaultdict(int)          # site -> n logical calls
        self.call_seconds = defaultdict(float)  # site -> seconds inside the call itself
        self.by_method = defaultdict(int)      # method name -> n calls
        self.read_bytes = defaultdict(int)     # site -> exact bytes read from socket
        self.read_calls = defaultdict(int)     # site -> n socket reads
        self.read_seconds = defaultdict(float)  # site -> seconds blocked in socket read
        self._patched = []

    def start(self):
        import pymongo.collection as pc

        for name in self.COLLECTION_METHODS:
            original = getattr(pc.Collection, name, None)
            if original is None:
                continue
            self._patched.append((pc.Collection, name, original))
            setattr(pc.Collection, name, self._wrap_collection(name, original))

        import pymongo.network_layer as nl

        original_receive = nl.receive_data
        self._patched.append((nl, "receive_data", original_receive))

        probe = self

        @functools.wraps(original_receive)
        def receive_data(*args, **kwargs):
            site = _caller_site()
            t0 = time.perf_counter()
            result = original_receive(*args, **kwargs)
            probe.read_seconds[site] += time.perf_counter() - t0
            probe.read_calls[site] += 1
            try:
                probe.read_bytes[site] += len(result)
            except TypeError:
                pass
            return result

        nl.receive_data = receive_data
        return self

    def _wrap_collection(self, name, original):
        probe = self

        @functools.wraps(original)
        def wrapper(*args, **kwargs):
            site = _caller_site()
            probe.calls[site] += 1
            probe.by_method[name] += 1
            t0 = time.perf_counter()
            try:
                return original(*args, **kwargs)
            finally:
                probe.call_seconds[site] += time.perf_counter() - t0

        return wrapper

    def stop(self):
        for owner, name, original in reversed(self._patched):
            setattr(owner, name, original)
        self._patched = []

    def report(self, top=25):
        sites = set(self.calls) | set(self.read_bytes)
        rows = []
        for site in sites:
            rows.append({
                "site": site,
                "logical_calls": self.calls.get(site, 0),
                "call_seconds": round(self.call_seconds.get(site, 0.0), 4),
                "socket_reads": self.read_calls.get(site, 0),
                "bytes": self.read_bytes.get(site, 0),
                "read_seconds": round(self.read_seconds.get(site, 0.0), 4),
            })
        rows.sort(key=lambda r: -(r["bytes"] + r["call_seconds"] * 1e6))
        return {
            "total_logical_calls": sum(self.calls.values()),
            "total_bytes": sum(self.read_bytes.values()),
            "total_call_seconds": round(sum(self.call_seconds.values()), 4),
            "total_read_seconds": round(sum(self.read_seconds.values()), 4),
            "by_method": dict(sorted(self.by_method.items(), key=lambda x: -x[1])),
            "by_site": rows[:top],
        }


# ---------------------------------------------------------------- decode probe


class DecodeProbe:
    """Times the decode paths: hex->bytes, json.loads (xcfg), *Entry.fromDict."""

    def __init__(self):
        self.seconds = defaultdict(float)
        self.calls = defaultdict(int)
        self.bytes_in = defaultdict(int)
        self._patched = []

    def start(self):
        import json as _json

        self._patch_callable(_json, "loads", "json.loads", size_of=lambda a, k: len(a[0]) if a and hasattr(a[0], "__len__") else 0)

        from mcrit.storage.FunctionEntry import FunctionEntry
        from mcrit.storage.SampleEntry import SampleEntry

        for cls, label in ((FunctionEntry, "FunctionEntry.fromDict"), (SampleEntry, "SampleEntry.fromDict")):
            if "fromDict" not in cls.__dict__:
                continue
            self._patch_staticlike(cls, "fromDict", label)
        return self

    def _patch_callable(self, owner, name, label, size_of=None):
        original = getattr(owner, name)
        self._patched.append((owner, name, original))
        probe = self

        @functools.wraps(original)
        def wrapper(*args, **kwargs):
            t0 = time.perf_counter()
            try:
                return original(*args, **kwargs)
            finally:
                probe.seconds[label] += time.perf_counter() - t0
                probe.calls[label] += 1
                if size_of is not None:
                    try:
                        probe.bytes_in[label] += size_of(args, kwargs)
                    except Exception:
                        pass

        setattr(owner, name, wrapper)

    def _patch_staticlike(self, cls, name, label):
        """Patch a plain / static / class method, preserving its descriptor kind."""
        raw = cls.__dict__[name]
        self._patched.append((cls, name, raw))
        probe = self
        kind = type(raw)
        underlying = raw.__func__ if isinstance(raw, (staticmethod, classmethod)) else raw

        @functools.wraps(underlying)
        def wrapper(*args, **kwargs):
            t0 = time.perf_counter()
            try:
                return underlying(*args, **kwargs)
            finally:
                probe.seconds[label] += time.perf_counter() - t0
                probe.calls[label] += 1

        setattr(cls, name, kind(wrapper) if kind in (staticmethod, classmethod) else wrapper)

    def stop(self):
        for owner, name, original in reversed(self._patched):
            setattr(owner, name, original)
        self._patched = []

    def report(self):
        return {
            label: {
                "seconds": round(self.seconds[label], 4),
                "calls": self.calls[label],
                "bytes_in": self.bytes_in.get(label, 0),
            }
            for label in sorted(self.seconds, key=lambda x: -self.seconds[x])
        }


# ---------------------------------------------------------------- matcher probe


class MatcherProbe:
    """Per-batch candidate/pair statistics, scoring time, and phase timings."""

    def __init__(self):
        self.phases = Phases()
        self.batches = []
        self.score_seconds = 0.0
        self.score_packs = 0
        self.score_pairs = 0
        self._patched = []
        self._current = None

    def start(self):
        from mcrit.matchers.MatcherInterface import MatcherInterface
        from mcrit.minhash.MinHasher import MinHasher
        from mcrit.storage.MongoDbStorage import MongoDbStorage

        probe = self

        # -- candidate retrieval -------------------------------------------------
        original_candidates = MongoDbStorage.getCandidatesForMinHashes
        self._patched.append((MongoDbStorage, "getCandidatesForMinHashes", original_candidates))

        @functools.wraps(original_candidates)
        def get_candidates(self_storage, function_id_to_minhash, band_matches_required=1):
            t0 = time.perf_counter()
            result = original_candidates(self_storage, function_id_to_minhash, band_matches_required)
            elapsed = time.perf_counter() - t0
            probe._current = {
                "n_query_functions": len(function_id_to_minhash),
                "band_matches_required": band_matches_required,
                "candidate_retrieval_seconds": round(elapsed, 4),
                "n_query_fns_with_candidates": len(result),
                "n_pairs_after_threshold": sum(len(v) for v in result.values()),
                "max_candidates_for_one_query_fn": max((len(v) for v in result.values()), default=0),
            }
            probe.phases.seconds["candidate_retrieval"] += elapsed
            probe.phases.calls["candidate_retrieval"] += 1
            return result

        MongoDbStorage.getCandidatesForMinHashes = get_candidates

        # -- matching cache ------------------------------------------------------
        original_cache = MatcherInterface._createMatchingCache
        self._patched.append((MatcherInterface, "_createMatchingCache", original_cache))

        @functools.wraps(original_cache)
        def create_cache(self_matcher, candidate_groups):
            t0 = time.perf_counter()
            result = original_cache(self_matcher, candidate_groups)
            elapsed = time.perf_counter() - t0
            probe.phases.seconds["matching_cache"] += elapsed
            probe.phases.calls["matching_cache"] += 1
            if probe._current is not None:
                probe._current["matching_cache_seconds"] = round(elapsed, 4)
                try:
                    probe._current["n_cached_functions"] = len(result._func_id_to_minhash)
                except Exception:
                    pass
            return result

        MatcherInterface._createMatchingCache = create_cache

        # -- minhash matching (per batch) ---------------------------------------
        original_perform = MatcherInterface._performMinHashMatching
        self._patched.append((MatcherInterface, "_performMinHashMatching", original_perform))

        @functools.wraps(original_perform)
        def perform(self_matcher, candidate_groups, cache):
            n_pairs = sum(len(v) for v in candidate_groups.values())
            t0 = time.perf_counter()
            result = original_perform(self_matcher, candidate_groups, cache)
            elapsed = time.perf_counter() - t0
            probe.phases.seconds["minhash_matching"] += elapsed
            probe.phases.calls["minhash_matching"] += 1
            entry = probe._current if probe._current is not None else {}
            entry.update({
                "n_pairs_entering_scoring": n_pairs,
                "minhash_matching_seconds": round(elapsed, 4),
                "n_matches_out": len(result),
                "cgroup_bytes_at_batch_end": read_cgroup_mem(),
                "self_rss_at_batch_end": read_self_rss(),
            })
            probe.batches.append(entry)
            probe._current = None
            return result

        MatcherInterface._performMinHashMatching = perform

        # -- scoring (only observable when POOL_MATCHING is off; pool children are
        #    separate processes and do not run this patch) ------------------------
        original_score = MinHasher.calculateScoresFromPackedTuples
        self._patched.append((MinHasher, "calculateScoresFromPackedTuples", original_score))

        @functools.wraps(original_score)
        def score(self_hasher, packed_tuples, *args, **kwargs):
            t0 = time.perf_counter()
            try:
                return original_score(self_hasher, packed_tuples, *args, **kwargs)
            finally:
                probe.score_seconds += time.perf_counter() - t0
                probe.score_packs += 1
                try:
                    probe.score_pairs += len(packed_tuples)
                except TypeError:
                    pass

        MinHasher.calculateScoresFromPackedTuples = score

        # -- pichash -------------------------------------------------------------
        original_pichash = MongoDbStorage.getPicHashMatchesBySampleId
        self._patched.append((MongoDbStorage, "getPicHashMatchesBySampleId", original_pichash))

        @functools.wraps(original_pichash)
        def pichash(self_storage, sample_id):
            with probe.phases("pichash_matching"):
                return original_pichash(self_storage, sample_id)

        MongoDbStorage.getPicHashMatchesBySampleId = pichash

        # -- function loading ----------------------------------------------------
        original_functions = MongoDbStorage.getFunctionsBySampleId
        self._patched.append((MongoDbStorage, "getFunctionsBySampleId", original_functions))

        @functools.wraps(original_functions)
        def functions_by_sample(self_storage, sample_id):
            with probe.phases("load_sample_functions"):
                return original_functions(self_storage, sample_id)

        MongoDbStorage.getFunctionsBySampleId = functions_by_sample

        # -- result assembly and its inner phases (attribution of the previously
        #    unaccounted wall). NOTE result_assembly CONTAINS summarize_matches and
        #    sample_summary; do not sum the three together. harmonize/vectorized
        #    scoring is covered by minhash_matching above.
        for method_name, phase_name in (
            ("_craftResultDict", "result_assembly"),
            ("_summarizeMatches", "summarize_matches"),
            ("_aggregateMatchSampleSummary", "sample_summary"),
            ("_harmonizeMinHashMatches", "harmonize_minhash"),
            ("_harmonizePicHashMatches", "harmonize_pichash"),
            ("filter_pichashes_from_candidate_groups", "pichash_filter"),
        ):
            original_method = getattr(MatcherInterface, method_name)
            self._patched.append((MatcherInterface, method_name, original_method))

            def make_timed(original_inner, inner_phase):
                @functools.wraps(original_inner)
                def timed(self_matcher, *args, **kwargs):
                    with probe.phases(inner_phase):
                        return original_inner(self_matcher, *args, **kwargs)
                return timed

            setattr(MatcherInterface, method_name, make_timed(original_method, phase_name))

        return self

    def stop(self):
        for owner, name, original in reversed(self._patched):
            setattr(owner, name, original)
        self._patched = []

    def report(self):
        return {
            "phases_seconds": {k: round(v, 4) for k, v in sorted(self.phases.seconds.items(), key=lambda x: -x[1])},
            "phases_calls": dict(self.phases.calls),
            "score_seconds": round(self.score_seconds, 4),
            "score_packs": self.score_packs,
            "score_pairs": self.score_pairs,
            "score_pairs_per_second": round(self.score_pairs / self.score_seconds, 1) if self.score_seconds else None,
            "n_batches": len(self.batches),
            "batches": self.batches,
            "totals": {
                "n_pairs_entering_scoring": sum(b.get("n_pairs_entering_scoring", 0) for b in self.batches),
                "n_cached_functions": sum(b.get("n_cached_functions", 0) for b in self.batches),
                "max_pairs_in_batch": max((b.get("n_pairs_entering_scoring", 0) for b in self.batches), default=0),
                "max_cache_in_batch": max((b.get("n_cached_functions", 0) for b in self.batches), default=0),
            },
        }
