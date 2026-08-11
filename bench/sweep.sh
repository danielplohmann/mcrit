#!/bin/bash
# Baseline sweep, smallest sample first so results bank early.
# rep1 = cold-ish (whatever the cache holds), rep2 = warm. Compare the pair.
set -u
OUT=/opt/mcrit/bench/results
LOG=/opt/mcrit/bench/results/sweep.log

run () {  # sample_id pool rep
  local sid=$1 pool=$2 rep=$3
  local tag="base-r${rep}-$([ "$pool" = 1 ] && echo pool || echo single)"
  echo "=== $(date -u +%H:%M:%S) sample=$sid pool=$pool rep=$rep" >> "$LOG"
  timeout 7200 python /opt/mcrit/bench/run_match.py "$sid" --pool "$pool" --tag "$tag" --out "$OUT" \
    2>>"$LOG" | grep -E '^(wrote|  wall)' >> "$LOG"
  echo "    exit=$?" >> "$LOG"
}

: > "$LOG"
for rep in 1 2; do
  for sid in 7455 601 8263; do
    for pool in 1 0; do
      run "$sid" "$pool" "$rep"
    done
  done
done
echo "=== $(date -u +%H:%M:%S) PHASE1 DONE" >> "$LOG"
