#!/bin/sh
# ABBA driver for the candidate-accumulation A/B. Interleaves variants so WiredTiger cache
# state cannot be mistaken for an effect. Usage: abba_candidates.sh <sample_id> <k> [batches]
SID=$1; K=$2; N=${3:-0}
NARG=""
[ "$N" != "0" ] && NARG="--batches $N"
for V in dict numpy numpy dict; do
  echo "=== $(date +%H:%M:%S) sample $SID k=$K accum=$V ==="
  python /opt/mcrit/bench/ab_candidates.py "$SID" --k "$K" --accum "$V" $NARG --tag abba$$ 2>&1 | tail -3
done
