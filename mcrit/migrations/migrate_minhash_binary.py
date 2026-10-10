#!/usr/bin/env python3
"""Convert the minhashes stored as hex text into BSON binary, or back.

MCRIT stores a function's minhash as BSON binary and still reads the hex text it stored before,
so this migration is optional. It shrinks the documents of functions hashed before the upgrade:
on a 7,244-sample corpus with 64.8% of its functions hashed, `functions` by 5.7% uncompressed
and by an estimated 12.9% on disk. MongoDB reuses the freed space for new documents; only `compact`
returns it to the filesystem.

  count  - how many minhashes each collection holds as hex and as binary, and how many functions
           are not hashed yet. Read-only, one scan per collection.
  binary - rewrite hex minhashes as binary.
  revert - rewrite binary minhashes as hex, for going back to an MCRIT that only reads hex. Stop
           the server and workers first: a running MCRIT stores new minhashes as binary again.

Each update only applies while the function still holds the value just read, so a minhash that
was rehashed in the meantime is left as it is. Only minhashes still in the old form are selected,
which makes a run resumable without keeping state: a killed run is started again, and re-running
after completion changes nothing. Functions that are not hashed yet keep their "" marker.

Usage (--host, --port and --db default to MCRIT's storage config, --batch to 2000). It connects the
way MCRIT does, with the credentials and flags it is configured with (STORAGE_MONGODB_USERNAME,
_PASSWORD, _FLAGS). --uri takes a complete MongoDB URI instead; the database is then --db, else the
one the URI names, else the configured one:
    python -m mcrit.migrations.migrate_minhash_binary --mode count
    python -m mcrit.migrations.migrate_minhash_binary --mode binary
    python -m mcrit.migrations.migrate_minhash_binary --mode revert
"""

import argparse
import sys
import time
from datetime import UTC, datetime
from typing import List, Optional

from pymongo import ASCENDING, MongoClient, UpdateOne

from mcrit.config.McritConfig import McritConfig
from mcrit.storage.MongoDbStorage import MongoDbStorage

COLLECTIONS = ("functions", "query_functions")
HEX_MINHASH = {"minhash": {"$type": "string", "$ne": ""}}
BINARY_MINHASH = {"minhash": {"$type": "binData"}}


def log(message):
    print("%s %s" % (datetime.now(UTC).strftime("%H:%M:%S"), message), flush=True)


def count(db):
    counts = {}
    # one scan per collection, grouping the documents by the form their minhash is in
    form_of = {"$cond": [{"$eq": ["$minhash", ""]}, "not_hashed", {"$type": "$minhash"}]}
    form_names = {"string": "hex", "binData": "binary", "not_hashed": "not_hashed"}
    for collection_name in COLLECTIONS:
        counts[collection_name] = {"hex": 0, "binary": 0, "not_hashed": 0}
        for group in db[collection_name].aggregate([{"$group": {"_id": form_of, "num": {"$sum": 1}}}]):
            if group["_id"] in form_names:
                counts[collection_name][form_names[group["_id"]]] += group["num"]
    return counts


def convert(db, collection_name, mode, batch_size):
    """Rewrite one collection's minhashes into the form `mode` names; answers how many changed."""
    collection = db[collection_name]
    selection = HEX_MINHASH if mode == "binary" else BINARY_MINHASH
    last_function_id = None
    num_converted = 0
    started = time.time()
    while True:
        query = dict(selection)
        if last_function_id is not None:
            query["function_id"] = {"$gt": last_function_id}
        documents = list(collection.find(query, {"_id": 0, "function_id": 1, "minhash": 1}).sort("function_id", ASCENDING).limit(batch_size))
        if not documents:
            break
        last_function_id = documents[-1]["function_id"]
        updates = []
        for document in documents:
            stored = document["minhash"]
            converted = bytes.fromhex(stored) if mode == "binary" else bytes(stored).hex()
            updates.append(UpdateOne({"function_id": document["function_id"], "minhash": stored}, {"$set": {"minhash": converted}}))
        num_converted += collection.bulk_write(updates, ordered=False).modified_count
        log("%s: %d converted, up to function_id %d (%.0f/s)" % (collection_name, num_converted, last_function_id, num_converted / max(time.time() - started, 1e-9)))
    return num_converted


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--mode", choices=["count", "binary", "revert"], required=True)
    storage_config = McritConfig().STORAGE_CONFIG
    parser.add_argument("--host", default=storage_config.STORAGE_SERVER)
    # a string, as in the config: an empty port is how a host list is configured
    parser.add_argument("--port", default=storage_config.STORAGE_PORT)
    parser.add_argument("--db", default=None, help="database to migrate; defaults to the one --uri names, else the configured one")
    parser.add_argument("--uri", default=None, help="complete MongoDB URI; replaces host, port and the configured credentials and flags")
    parser.add_argument("--batch", type=int, default=2000)
    args = parser.parse_args(argv)
    if args.batch < 1:
        parser.error("--batch must be at least 1")

    # the URI MongoDbStorage itself connects with (STORAGE_MONGODB_* credentials and flags), so a
    # secured deployment needs nothing beyond its mcrit configuration
    configured_db = storage_config.STORAGE_MONGODB_DBNAME
    if args.uri:
        client = MongoClient(args.uri, connect=True)
        db = client[args.db] if args.db else client.get_default_database(default=configured_db)
    else:
        db_name = args.db or configured_db
        uri = MongoDbStorage.buildMongoUri(
            args.host, args.port, db_name, storage_config.STORAGE_MONGODB_USERNAME, storage_config.STORAGE_MONGODB_PASSWORD, storage_config.STORAGE_MONGODB_FLAGS
        )
        db = MongoClient(uri, connect=True)[db_name]
    # the database name only: the URI can carry a password
    log("database %s" % db.name)
    if args.mode != "count":
        for collection_name in COLLECTIONS:
            num_converted = convert(db, collection_name, args.mode, args.batch)
            log("%s: done, %d minhashes rewritten as %s" % (collection_name, num_converted, "binary" if args.mode == "binary" else "hex"))
    for collection_name, collection_counts in count(db).items():
        log("%s: %d hex, %d binary, %d not hashed" % (collection_name, collection_counts["hex"], collection_counts["binary"], collection_counts["not_hashed"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
