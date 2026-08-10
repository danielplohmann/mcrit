#!/bin/bash
# Interleaved A/B of the job-scoped MatchingCache on a multi-batch sample.
# Two passes per variant, alternating, so WiredTiger cache drift affects both equally.
set -u
LOG=/opt/mcrit/bench/results/eq_test.log
: > "$LOG"
for pass in 1 2; do
  for p in 0 1; do
    echo "=== $(date -u +%H:%M:%S) pass=$pass persist=$p" >> "$LOG"
    python /opt/mcrit/bench/run_match.py 601 --pool 0 --persist-cache $p \
      --tag "eq-p${pass}" --out /opt/mcrit/bench/results 2>>/dev/null \
      | grep -E '^(wrote|  wall)' >> "$LOG"
  done
done
echo "=== $(date -u +%H:%M:%S) EQ DONE" >> "$LOG"
