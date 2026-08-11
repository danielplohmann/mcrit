#!/bin/bash
# Merlin (12.21x redundancy, the Go pathology) A/B, ABBA order to cancel linear cache drift.
set -u
LOG=/opt/mcrit/bench/results/eq_merlin.log
: > "$LOG"
for spec in "1 0" "1 1" "2 1" "2 0"; do
  set -- $spec; pass=$1; p=$2
  echo "=== $(date -u +%H:%M:%S) pass=$pass persist=$p" >> "$LOG"
  python /opt/mcrit/bench/run_match.py 5188 --k 2 --pool 1 --persist-cache $p \
    --tag "eqm-p${pass}" --out /opt/mcrit/bench/results 2>>/dev/null \
    | grep -E '^(wrote|  wall)' >> "$LOG"
done
echo "=== $(date -u +%H:%M:%S) MERLIN EQ DONE" >> "$LOG"
