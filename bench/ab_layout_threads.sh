#!/bin/bash
# Does C1's cold-read win survive once the fetch is already concurrent (fix 04)?
# Same id set, same three layouts, at 1 and 8 threads, each measured cold after a mongod
# restart. Restarting mongod kills mcrit-worker (BUG-2), so it is restarted too.
set -u
OUT=/opt/mcrit/bench/results/ab_layout_threads.jsonl
RES=/data/docker-mcrit/repositories/mcrit/bench/results
SLICE=${SLICE:-25000}

MONGO_CONTAINER=$(docker ps --format '{{.Names}}' | grep -i mongo | head -1)
[ -z "$MONGO_CONTAINER" ] && { echo "no mongo container" >&2; exit 1; }

wait_for_mongo () {
  for _ in $(seq 1 60); do
    docker exec mcrit-worker python -c "
import pymongo,sys
try: pymongo.MongoClient('mongodb://mongodb:27017', serverSelectionTimeoutMS=2000).admin.command('ping')
except Exception: sys.exit(1)
" 2>/dev/null && return 0
    sleep 2
  done
  echo "mongod did not come back" >&2; return 1
}

rm -f "$RES/ab_layout_threads.jsonl"
echo "[$(date -u +%H:%M:%S)] regenerating candidate id set (merlin k=2, first batch)"
docker exec mcrit-worker python /opt/mcrit/bench/ab_layout.py --make-ids \
  --sample-id 5188 --k 2 --limit 300000 2>&1 | grep -vE 'ShingleLoader|INFO'

for threads in 1 8; do
  for layout in functions fn_hex fn_bin; do
    echo "[$(date -u +%H:%M:%S)] cold restart for $layout at $threads thread(s)"
    docker restart "$MONGO_CONTAINER" >/dev/null
    sleep 5
    docker start mcrit-worker >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do
      docker ps --format '{{.Names}}' | grep -qx mcrit-worker && break
      sleep 2
    done
    wait_for_mongo || exit 1
    sleep 3
    docker exec mcrit-worker python /opt/mcrit/bench/ab_layout.py --layout "$layout" \
      --threads "$threads" --slice "$SLICE" --repeats 2 --out "$OUT" 2>&1 \
      | grep -vE 'ShingleLoader|INFO'
  done
done
echo "[$(date -u +%H:%M:%S)] AB DONE"
