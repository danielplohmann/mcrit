#!/bin/bash
# Lets the baseline sweep run rep1 in full plus the cheap rep2 runs (7455, 601), then stops
# it before the expensive bumblebee rep2 and hands over to merlin at k=2.
set -u
LOG=/opt/mcrit/bench/results/sweep.log

while true; do
  if grep -q 'sample=8263 pool=1 rep=2' "$LOG" 2>/dev/null; then
    pkill -f 'bench/sweep.sh'
    pkill -f 'run_match.py 8263'
    echo "=== $(date -u +%H:%M:%S) sweep truncated before 8263 rep2 (re-scope)" >> "$LOG"
    break
  fi
  if grep -q 'PHASE1 DONE' "$LOG" 2>/dev/null; then
    echo "=== $(date -u +%H:%M:%S) phase1 completed on its own" >> "$LOG"
    break
  fi
  sleep 10
done

sleep 5
bash /opt/mcrit/bench/phase2.sh
