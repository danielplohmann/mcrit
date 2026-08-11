#!/bin/bash
# Bumblebee: 6.09x redundancy AND 76% cache-bound - the regime where the incremental cache
# should pay most in wall-clock. Single-process so digests are verifiable (pool matching is
# non-deterministic). ABBA order to cancel linear cache drift.
set -u
LOG=/opt/mcrit/bench/results/eq_bumblebee.log
: > "$LOG"
for spec in "1 0" "1 1" "2 1" "2 0"; do
  set -- $spec; pass=$1; p=$2
  echo "=== $(date -u +%H:%M:%S) pass=$pass persist=$p" >> "$LOG"
  python /opt/mcrit/bench/run_match.py 8263 --pool 0 --persist-cache $p \
    --tag "eqb-p${pass}" --out /opt/mcrit/bench/results 2>>/dev/null \
    | grep -E '^(wrote|  wall)' >> "$LOG"
done
echo "=== $(date -u +%H:%M:%S) BUMBLEBEE EQ DONE" >> "$LOG"
