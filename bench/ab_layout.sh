#!/bin/bash
# Host-side driver for the layout A/B. Restarts mongod before each layout so the first
# measurement is genuinely cold, then repeats immediately for the warm number.
set -u
RES=/data/docker-mcrit/repositories/mcrit/bench/results
OUT=/opt/mcrit/bench/results/ab_layout_results.jsonl

# the mongo container has been recreated at some point and carries a hash-prefixed name
MONGO_CONTAINER=$(docker ps --format '{{.Names}}' | grep -i mongo | head -1)
if [ -z "$MONGO_CONTAINER" ]; then echo "no mongo container found" >&2; exit 1; fi
echo "using mongo container: $MONGO_CONTAINER"

# mongod reachable from the host (does not need mcrit-worker to be up)
wait_for_mongo_port () {
  for _ in $(seq 1 60); do
    if python3 -c "
import pymongo,sys
try:
    pymongo.MongoClient('mongodb://127.0.0.1:27017', serverSelectionTimeoutMS=2000).admin.command('ping')
except Exception:
    sys.exit(1)
" 2>/dev/null; then return 0; fi
    sleep 2
  done
  echo "mongod port did not come back" >&2; return 1
}

wait_for_mongo () {
  for _ in $(seq 1 60); do
    if docker exec mcrit-worker python -c "
import pymongo,sys
try:
    pymongo.MongoClient('mongodb://mongodb:27017', serverSelectionTimeoutMS=2000).admin.command('ping')
except Exception:
    sys.exit(1)
" 2>/dev/null; then return 0; fi
    sleep 2
  done
  echo "mongod did not come back" >&2; return 1
}

rm -f "$RES/ab_layout_results.jsonl"

echo "[$(date -u +%H:%M:%S)] generating candidate id set (merlin k=2, first batch)"
docker exec mcrit-worker python /opt/mcrit/bench/ab_layout.py --make-ids \
  --sample-id 5188 --k 2 --limit 300000 2>&1 | grep -vE 'ShingleLoader|INFO'

for layout in functions fn_hex fn_bin; do
  echo "[$(date -u +%H:%M:%S)] restarting mongod for cold measurement of $layout"
  docker restart "$MONGO_CONTAINER" >/dev/null
  wait_for_mongo_port || exit 1
  # mcrit-worker does not survive a mongod restart (unhandled NotPrimaryError at shutdown),
  # and the bench runs inside it, so bring it back before measuring
  docker start mcrit-worker >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do
    docker ps --format '{{.Names}}' | grep -qx mcrit-worker && break
    sleep 2
  done
  wait_for_mongo || exit 1
  sleep 3
  docker exec mcrit-worker python /opt/mcrit/bench/ab_layout.py --layout "$layout" \
    --repeats 3 --out "$OUT" 2>&1 | grep -vE 'ShingleLoader|INFO'
done

echo "[$(date -u +%H:%M:%S)] AB DONE"
