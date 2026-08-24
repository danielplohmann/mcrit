#!/bin/bash
# Merlin (win.merlin 5188, the Go pathology) at k=2 -- matching the March memray sweep's
# configuration so the numbers are directly comparable, rather than k=1 which would run
# for hours. Single rep, both pool modes.
set -u
OUT=/opt/mcrit/bench/results
LOG=$OUT/sweep.log

for pool in 1 0; do
  tag="base-r1-$([ "$pool" = 1 ] && echo pool || echo single)"
  echo "=== $(date -u +%H:%M:%S) sample=5188 k=2 pool=$pool" >> "$LOG"
  timeout 14400 python /opt/mcrit/bench/run_match.py 5188 --k 2 --pool "$pool" --tag "$tag" --out "$OUT" \
    2>>"$LOG" | grep -E '^(wrote|  wall)' >> "$LOG"
  echo "    exit=$?" >> "$LOG"
done
echo "=== $(date -u +%H:%M:%S) ALL DONE" >> "$LOG"
