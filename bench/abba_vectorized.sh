#!/bin/sh
# ABBA driver for the B2 (vectorised scoring) A/B. Single-process only: pooled matching is
# non-deterministic, so digests would not be comparable.
# Usage: abba_vectorized.sh <sample_id> <k> [tag]
SID=$1; K=$2; TAG=${3:-b2}
for V in 0 1 1 0; do
  echo "=== $(date +%H:%M:%S) sample $SID k=$K vectorized=$V ==="
  python /opt/mcrit/bench/run_match.py "$SID" --k "$K" --pool 0 --cand-accum dict \
      --vectorized "$V" --tag "$TAG$V" 2>/dev/null | tail -2
done
echo "=== $(date +%H:%M:%S) done ==="
