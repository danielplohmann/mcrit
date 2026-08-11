#!/bin/sh
# ABBA of stock vs all three session-02/03 fixes enabled together.
# Usage: abba_combined.sh <sample_id> <k> <cache_max_entries> [tag]
SID=$1; K=$2; CAP=$3; TAG=${4:-combined}
for V in stock all all stock; do
  echo "=== $(date +%H:%M:%S) sample $SID k=$K variant=$V ==="
  if [ "$V" = "stock" ]; then
    python /opt/mcrit/bench/run_match.py "$SID" --k "$K" --pool 0 \
        --cand-accum dict --vectorized 0 --persist-cache 0 --tag "${TAG}_stock" 2>/dev/null | tail -2
  else
    python /opt/mcrit/bench/run_match.py "$SID" --k "$K" --pool 0 \
        --cand-accum numpy --vectorized 1 --persist-cache 1 --cache-max-entries "$CAP" \
        --tag "${TAG}_all" 2>/dev/null | tail -2
  fi
done
echo "=== $(date +%H:%M:%S) done ==="
