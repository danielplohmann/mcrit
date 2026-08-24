#!/bin/bash
# Merlin equivalence with the pool OFF, so imap_unordered tie-break nondeterminism
# cannot mask a real difference. Single pass per variant; digests must match exactly.
set -u
LOG=/opt/mcrit/bench/results/eq_merlin_single.log
: > "$LOG"
for p in 0 1; do
  echo "=== $(date -u +%H:%M:%S) persist=$p (single process)" >> "$LOG"
  python /opt/mcrit/bench/run_match.py 5188 --k 2 --pool 0 --persist-cache $p \
    --tag "eqms" --out /opt/mcrit/bench/results 2>>/dev/null \
    | grep -E '^(wrote|  wall)' >> "$LOG"
done
echo "=== $(date -u +%H:%M:%S) MERLIN SINGLE EQ DONE" >> "$LOG"
