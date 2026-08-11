#!/bin/sh
# ABBA of 1 vs N concurrent candidate-signature fetches, with the other three fixes on.
# Usage: abba_fetch_threads.sh <sample_id> <k> <cache_max_entries> <threads> [slice] [tag]
SID=$1; K=$2; CAP=$3; T=$4; SLICE=${5:-25000}; TAG=${6:-ft}
for N in 1 $T $T 1; do
  echo "=== $(date +%H:%M:%S) sample $SID k=$K fetch_threads=$N ==="
  python /opt/mcrit/bench/run_match.py "$SID" --k "$K" --pool 0 \
      --cand-accum numpy --vectorized 1 --persist-cache 1 --cache-max-entries "$CAP" \
      --fetch-threads "$N" --fetch-slice "$SLICE" --tag "${TAG}_t$N" 2>/dev/null | tail -2
done
echo "=== $(date +%H:%M:%S) done ==="
