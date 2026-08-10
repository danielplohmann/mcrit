#!/usr/bin/env python3
"""Unattended overnight sweep. Two phases, most valuable first.

PHASE A - broad equivalence sweep. Everything so far rests on 3 MatcherSample samples plus a
one-off run of each other matcher. This runs flags-off vs flags-on over a stratified random
selection of the corpus and compares result digests. The primary output is *equivalence over
many samples*, which is cache-independent and therefore trustworthy unattended; the speedup
distribution is a secondary output and is noisy (adjacent runs, alternating order, no mongod
restarts - see session-02-baseline.md section 6).

PHASE B - batch-size sweep. Fix 03 made scoring memory O(candidates) instead of O(pairs), so
BUG-3's shipped default of MINHASH_MATCHING_FUNCTION_BATCH_SIZE=10000 may now be safe - and
with fix 01 on, a bigger batch no longer multiplies I/O either. This measures wall and peak
memory at b = 200 / 1000 / 5000 / 10000 with the flags on, digest-checked against b=200.

Results are appended to JSONL and the markdown summary is rewritten after every single run,
so killing this at any point leaves a complete, readable result set.

    docker exec -d mcrit-worker python /opt/mcrit/bench/overnight.py [--budget-hours 11]
"""
import argparse
import json
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, "/opt/mcrit")

RUN_MATCH = "/opt/mcrit/bench/run_match.py"
RESULTS_DIR = "/opt/mcrit/bench/results"
JSONL = os.path.join(RESULTS_DIR, "overnight.jsonl")
SUMMARY = os.path.join(RESULTS_DIR, "overnight_summary.md")
SCRATCH = os.path.join(RESULTS_DIR, "overnight_runs")

# samples already covered by the session-03 ABBA runs; no need to spend the night on them
ALREADY_DONE = {5188, 8263, 601, 7455}


def log(message):
    print("[%s] %s" % (datetime.now(timezone.utc).strftime("%H:%M:%S"), message), flush=True)


def chown_like_dir(path):
    try:
        st = os.stat(RESULTS_DIR)
        os.chown(path, st.st_uid, st.st_gid)
    except OSError:
        pass


def pick_samples(n_small, n_medium, n_large, seed=0xBEEF):
    """Stratified by function count, so the sweep is not all tiny samples."""
    from mcrit.config.McritConfig import McritConfig
    from mcrit.storage.StorageFactory import StorageFactory

    storage = StorageFactory.getStorage(McritConfig())
    db = storage._getDb()
    buckets = {"small": [], "medium": [], "large": []}
    for document in db.samples.find({}, {"_id": 0, "sample_id": 1, "family_id": 1, "statistics": 1}):
        sample_id = document["sample_id"]
        if sample_id in ALREADY_DONE:
            continue
        num_functions = (document.get("statistics") or {}).get("num_functions", 0)
        if 50 <= num_functions < 400:
            buckets["small"].append((sample_id, num_functions))
        elif 400 <= num_functions < 1500:
            buckets["medium"].append((sample_id, num_functions))
        elif 1500 <= num_functions <= 6000:
            buckets["large"].append((sample_id, num_functions))
    rng = random.Random(seed)
    selection = []
    for name, count in (("small", n_small), ("medium", n_medium), ("large", n_large)):
        pool = sorted(buckets[name])
        rng.shuffle(pool)
        selection.extend((sample_id, num_functions, name) for sample_id, num_functions in pool[:count])
        log("bucket %-6s %6d available, taking %d" % (name, len(pool), min(count, len(pool))))
    return selection


def _limit_address_space(mib):
    def apply_limit():
        import resource
        limit = mib * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    return apply_limit


def run_one(sample_id, flags_on, batch=None, timeout_seconds=3600, tag="ov", k=None,
            mem_limit_mib=16384, cache_max_entries=6000000):
    """One run_match.py invocation. Returns a dict, never raises."""
    command = [
        sys.executable, RUN_MATCH, str(sample_id), "--pool", "0",
        "--out", SCRATCH, "--tag", "%s_%s" % (tag, "on" if flags_on else "off"),
    ]
    if k is not None:
        command += ["--k", str(k)]
    if flags_on:
        # deliberately NOT passing --fetch-slice: after the review fix the slice size is
        # derived from the thread count, and this sweep should exercise what an operator who
        # only sets STORAGE_CACHE_FETCH_THREADS actually gets
        command += ["--cand-accum", "numpy", "--vectorized", "1", "--persist-cache", "1",
                    "--cache-max-entries", str(cache_max_entries), "--fetch-threads", "8"]
    else:
        command += ["--cand-accum", "dict", "--vectorized", "0", "--persist-cache", "0",
                    "--fetch-threads", "1", "--fetch-slice", "500000"]
    if batch is not None:
        command += ["--batch", str(batch)]

    started = time.perf_counter()
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds,
                                   preexec_fn=_limit_address_space(mem_limit_mib))
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "seconds": round(time.perf_counter() - started, 1)}
    if completed.returncode != 0:
        return {"status": "error", "returncode": completed.returncode,
                "stderr_tail": completed.stderr[-800:], "seconds": round(time.perf_counter() - started, 1)}

    # find the JSON the run just wrote
    written = None
    for line in completed.stdout.splitlines():
        if line.startswith("wrote "):
            written = line[len("wrote "):].strip()
    if not written or not os.path.exists(written):
        return {"status": "no_output", "stdout_tail": completed.stdout[-500:]}
    with open(written) as fh:
        payload = json.load(fh)
    os.remove(written)  # the sweep keeps the summary rows, not 200 full profiles
    matcher = payload["matcher"]
    return {
        "status": "ok",
        "wall_seconds": payload["meta"]["wall_seconds"],
        "digest": payload["result_digest"]["sha256"],
        "digest_len": payload["result_digest"]["len"],
        "peak_mib": round((payload["memory"].get("cgroup_peak_bytes") or 0) / 2 ** 20),
        "mongo_mib": round(payload["mongo"]["total_bytes"] / 2 ** 20, 1),
        "pairs": matcher["totals"]["n_pairs_entering_scoring"],
        "phases": {k: round(v, 1) for k, v in matcher["phases_seconds"].items()},
        "batch_size": payload["config"]["batch_size"],
        "k": payload["config"]["band_matches_required"],
    }


def append_row(row):
    with open(JSONL, "a") as fh:
        fh.write(json.dumps(row) + "\n")
    chown_like_dir(JSONL)


def load_rows():
    if not os.path.exists(JSONL):
        return []
    rows = []
    with open(JSONL) as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_summary():
    try:
        _write_summary()
    except Exception as error:  # noqa: BLE001 - the sweep must outlive any rendering bug
        log("WARNING: write_summary failed (%s: %s) - results are safe in the JSONL"
            % (type(error).__name__, error))


def _write_summary():
    rows = load_rows()
    sweep = [r for r in rows if r.get("phase") == "A"]
    batch = [r for r in rows if r.get("phase") == "B"]
    lines = []
    lines.append("# Overnight sweep (auto-generated, rewritten after every run)\n")
    lines.append("Last updated %s UTC.\n" % datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))

    lines.append("\n## Phase A - equivalence over many samples\n")
    ok = [r for r in sweep if r["off"].get("status") == "ok" and r["on"].get("status") == "ok"]
    identical = [r for r in ok if r["off"]["digest"] == r["on"]["digest"]]
    mismatched = [r for r in ok if r["off"]["digest"] != r["on"]["digest"]]
    broken = [r for r in sweep if r not in ok]
    lines.append("| | count |\n|---|---|")
    lines.append("| samples completed both variants | %d |" % len(ok))
    lines.append("| **digests identical** | **%d** |" % len(identical))
    lines.append("| **digests DIFFERENT** | **%d** |" % len(mismatched))
    lines.append("| runs that timed out or errored | %d |" % len(broken))
    if mismatched:
        lines.append("\n### DIGEST MISMATCHES - investigate before anything is enabled\n")
        lines.append("| sample | fns | k | off digest | on digest |\n|---|---|---|---|---|")
        for r in mismatched:
            lines.append("| %d | %s | %s | `%s` | `%s` |" % (
                r["sample_id"], r["num_functions"], r["off"].get("k"),
                r["off"]["digest"], r["on"]["digest"]))
    if broken:
        lines.append("\n### Incomplete runs\n")
        lines.append("| sample | fns | off | on |\n|---|---|---|---|")
        for r in broken:
            lines.append("| %d | %s | %s | %s |" % (
                r["sample_id"], r["num_functions"],
                r["off"].get("status"), r["on"].get("status")))
    if ok:
        speedups = sorted(r["off"]["wall_seconds"] / max(r["on"]["wall_seconds"], 1e-6) for r in ok)
        def pct(p):
            return speedups[min(len(speedups) - 1, int(p * len(speedups)))]
        total_off = sum(r["off"]["wall_seconds"] for r in ok)
        total_on = sum(r["on"]["wall_seconds"] for r in ok)
        lines.append("\n### Speedup distribution (noisy - adjacent runs, no cache control)\n")
        lines.append("| statistic | value |\n|---|---|")
        lines.append("| min | %.2fx |" % speedups[0])
        lines.append("| p25 | %.2fx |" % pct(0.25))
        lines.append("| median | %.2fx |" % pct(0.50))
        lines.append("| p75 | %.2fx |" % pct(0.75))
        lines.append("| max | %.2fx |" % speedups[-1])
        lines.append("| aggregate (sum off / sum on) | **%.2fx** |" % (total_off / max(total_on, 1e-6)))
        lines.append("| total wall, flags off | %.1f h |" % (total_off / 3600))
        lines.append("| total wall, flags on | %.1f h |" % (total_on / 3600))
        slower = [r for r in ok if r["off"]["wall_seconds"] < r["on"]["wall_seconds"]]
        lines.append("| samples where flags-on was SLOWER | %d |" % len(slower))
        if slower:
            lines.append("\n#### Samples where the fixes lost\n")
            lines.append("| sample | fns | off s | on s | off peak | on peak |\n|---|---|---|---|---|---|")
            for r in sorted(slower, key=lambda x: x["on"]["wall_seconds"] / max(x["off"]["wall_seconds"], 1e-6))[-15:]:
                lines.append("| %d | %s | %.1f | %.1f | %s | %s |" % (
                    r["sample_id"], r["num_functions"], r["off"]["wall_seconds"],
                    r["on"]["wall_seconds"], r["off"]["peak_mib"], r["on"]["peak_mib"]))
        peaks = [(r["on"]["peak_mib"] - r["off"]["peak_mib"], r) for r in ok]
        # sort on the delta ONLY: (int, dict) tuples fall through to comparing dicts when two
        # samples share a delta, which is a TypeError. That killed the first launch at 22
        # samples, on a tie at +182 MiB.
        peaks.sort(key=lambda item: item[0], reverse=True)
        lines.append("\n### Memory delta (flags on minus off), worst 10\n")
        lines.append("| sample | fns | off peak MiB | on peak MiB | delta |\n|---|---|---|---|---|")
        for delta, r in peaks[:10]:
            lines.append("| %d | %s | %s | %s | +%s |" % (
                r["sample_id"], r["num_functions"], r["off"]["peak_mib"], r["on"]["peak_mib"], delta))

    if batch:
        lines.append("\n## Phase B - batch size with the flags on\n")
        lines.append("Does fix 03's O(candidates) scoring memory make BUG-3's shipped default "
                     "of 10000 safe again?\n")
        lines.append("| sample | batch | wall s | peak MiB | digest | matches b=200 |")
        lines.append("|---|---|---|---|---|---|")
        baseline = {}
        for r in batch:
            if r["result"].get("status") != "ok":
                lines.append("| %d | %s | - | - | %s | - |" % (
                    r["sample_id"], r["batch"], r["result"].get("status")))
                continue
            result = r["result"]
            if r["batch"] == 200:
                baseline[r["sample_id"]] = result["digest"]
            same = "n/a"
            if r["sample_id"] in baseline:
                same = "yes" if result["digest"] == baseline[r["sample_id"]] else "**NO**"
            lines.append("| %d | %s | %.1f | %s | `%s` | %s |" % (
                r["sample_id"], r["batch"], result["wall_seconds"], result["peak_mib"],
                result["digest"][:16], same))

    evict = [r for r in rows if r.get("phase") == "C"]
    if evict:
        lines.append("\n## Phase C - eviction + vectorised at the shipped 2 M ceiling\n")
        lines.append("| sample | status | wall s | peak MiB | digest | vs stock |")
        lines.append("|---|---|---|---|---|---|")
        for r in evict:
            res = r["result"]
            lines.append("| %d | %s | %s | %s | `%s` | %s |" % (
                r["sample_id"], res.get("status"), res.get("wall_seconds", "-"),
                res.get("peak_mib", "-"), res.get("digest", "-"), r.get("verdict")))

    with open(SUMMARY, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    chown_like_dir(SUMMARY)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget-hours", type=float, default=11.0)
    ap.add_argument("--small", type=int, default=45)
    ap.add_argument("--medium", type=int, default=25)
    ap.add_argument("--large", type=int, default=6)
    ap.add_argument("--timeout-seconds", type=int, default=1800)
    ap.add_argument("--skip-phase-a", action="store_true")
    args = ap.parse_args()

    os.makedirs(SCRATCH, exist_ok=True)
    deadline = time.time() + args.budget_hours * 3600
    log("budget %.1f h, deadline %s UTC" % (
        args.budget_hours, datetime.fromtimestamp(deadline, timezone.utc).strftime("%H:%M:%S")))

    already = {r["sample_id"] for r in load_rows() if r.get("phase") == "A"}

    if not args.skip_phase_a:
        selection = pick_samples(args.small, args.medium, args.large)
        log("PHASE A: %d samples selected, %d already done" % (len(selection), len(already)))
        for index, (sample_id, num_functions, bucket) in enumerate(selection):
            if sample_id in already:
                continue
            if time.time() > deadline:
                log("budget exhausted, stopping phase A after %d samples" % index)
                break
            # alternate which variant runs first, so cache warming does not systematically
            # favour one of them across the sweep
            off_first = index % 2 == 0
            order = [False, True] if off_first else [True, False]
            outcome = {}
            for flags_on in order:
                outcome["on" if flags_on else "off"] = run_one(
                    sample_id, flags_on, timeout_seconds=args.timeout_seconds)
            row = {"phase": "A", "sample_id": sample_id, "num_functions": num_functions,
                   "bucket": bucket, "off_first": off_first,
                   "off": outcome["off"], "on": outcome["on"],
                   "utc": datetime.now(timezone.utc).isoformat()}
            append_row(row)
            write_summary()
            verdict = "?"
            if outcome["off"].get("status") == "ok" and outcome["on"].get("status") == "ok":
                same = outcome["off"]["digest"] == outcome["on"]["digest"]
                verdict = "SAME" if same else "*** MISMATCH ***"
                log("A %3d/%d sample %5d (%5s fns) %6.1fs -> %6.1fs  %.2fx  %s" % (
                    index + 1, len(selection), sample_id, num_functions,
                    outcome["off"]["wall_seconds"], outcome["on"]["wall_seconds"],
                    outcome["off"]["wall_seconds"] / max(outcome["on"]["wall_seconds"], 1e-6), verdict))
            else:
                log("A %3d/%d sample %5d (%5s fns) off=%s on=%s" % (
                    index + 1, len(selection), sample_id, num_functions,
                    outcome["off"].get("status"), outcome["on"].get("status")))

    log("PHASE B: batch-size sweep")
    # same k each sample is documented at, so these are comparable with session-03-combined.md.
    # 12 GiB address-space cap: this phase deliberately provokes the BUG-3 blowup, and the
    # container has no memory limit of its own.
    out_of_budget = False
    for sample_id, sample_k in ((5188, 2), (8263, 1)):
        if out_of_budget:
            break
        for batch in (200, 1000, 5000, 10000):
            if time.time() > deadline:
                log("budget exhausted, stopping phase B")
                out_of_budget = True
                break
            result = run_one(sample_id, True, batch=batch, k=sample_k,
                             timeout_seconds=args.timeout_seconds, tag="ovb",
                             mem_limit_mib=12288)
            append_row({"phase": "B", "sample_id": sample_id, "batch": batch, "k": sample_k,
                        "result": result, "utc": datetime.now(timezone.utc).isoformat()})
            write_summary()
            log("B sample %d k=%d batch %5d -> %s %s" % (
                sample_id, sample_k, batch, result.get("status"),
                ("%.1fs / %s MiB" % (result.get("wall_seconds", 0), result.get("peak_mib")))
                if result.get("status") == "ok" else ""))

    log("PHASE C: eviction + vectorised at the SHIPPED ceiling (the untested cell)")
    # Every measured run that actually evicted had vectorised scoring OFF; every vectorised
    # run had its ceiling raised above the candidate union. Turning both flags on at the
    # shipped 2,000,000 default goes straight into that gap. bumblebee's union is 4,548,732,
    # so a 2 M ceiling forces eviction on most batches.
    KNOWN_STOCK_DIGESTS = {8263: "335875610c7491258cbcc2a5da492133",
                           601: "f3c4aebadf8b9be7af56306b71f2c7a8"}
    for sample_id, sample_k in ((601, 1), (8263, 1)):
        if time.time() > deadline:
            log("budget exhausted, stopping phase C")
            break
        result = run_one(sample_id, True, k=sample_k, timeout_seconds=args.timeout_seconds,
                         tag="ovc", cache_max_entries=2000000)
        expected = KNOWN_STOCK_DIGESTS.get(sample_id)
        verdict = "?"
        if result.get("status") == "ok":
            verdict = "MATCHES stock" if result["digest"] == expected else "*** MISMATCH ***"
        append_row({"phase": "C", "sample_id": sample_id, "k": sample_k,
                    "cache_max_entries": 2000000, "expected_digest": expected,
                    "result": result, "verdict": verdict,
                    "utc": datetime.now(timezone.utc).isoformat()})
        write_summary()
        log("C sample %d cap 2M -> %s %s" % (sample_id, result.get("status"), verdict))

    write_summary()
    log("DONE")


if __name__ == "__main__":
    main()
