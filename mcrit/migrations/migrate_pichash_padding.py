#!/usr/bin/env python3
"""Store pichashes zero-padded so that their hex order is their numeric order (#145).

`functions._pichash` and `functions._picblockhashes[].hash` (and the same fields of
`query_functions`) hold 64 bit values as hex strings. Written with `hex()`, they have a
variable width ("0x4d2"), so a range condition or a sort on them orders "0x99" after
"0x1000". Padding every value to 16 digits ("0x00000000000004d2") makes string order numeric
order; the storage then allows range operators and sorting by pichash, which the search
cursor needs to page a pichash-sorted function search.

Modes:
  pad     - the migration: rewrite every unpadded value in place, batched by function_id
            (resumable: progress is a keyset cursor in a state document, a killed run costs
            one batch). A final sweep catches documents the walk did not see, then the
            settings flag `pichash_padded` is set, which switches every reader and writer
            of the instance to the padded shape.
  verify  - count the values that are still unpadded and check the flag against them;
            exits 1 when the flag says padded but unpadded values remain.
  unpad   - rollback: rewrite every value with `hex()` again and clear the flag.

Stop the mcrit server and its workers before `pad`: while the flag is unset they keep
writing unpadded values, which `pad` would have to be re-run for (it is idempotent, and
`verify` reports leftovers). Storage reads the flag once per process, so restart them
afterwards. Until the flag is set, all readers accept both widths, so the instance keeps
answering correctly during the walk; only range and sort by pichash stay rejected.

Usage:
    python -m mcrit.migrations.migrate_pichash_padding --mode pad
    python -m mcrit.migrations.migrate_pichash_padding --mode verify
    python -m mcrit.migrations.migrate_pichash_padding --mode unpad
"""

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

from pymongo import ASCENDING, MongoClient, UpdateOne

from mcrit.config.McritConfig import McritConfig
from mcrit.storage.MongoDbStorage import PICHASH_HEX_DIGITS, encode_pichash_value

STATE_COLLECTION = "pichash_padding_state"
COLLECTIONS = ("functions", "query_functions")
PROJECTION = {"function_id": 1, "_pichash": 1, "_picblockhashes.hash": 1, "_id": 0}


def build_mongo_uri(host: str, port: int, db_name: str, username: Optional[str], password: Optional[str], flags: Optional[str]) -> str:
    credentials = "%s:%s@" % (quote_plus(username), quote_plus(password)) if username and password else ""
    query = "?%s" % flags if flags else ""
    return "mongodb://%s%s:%d/%s%s" % (credentials, host, port, db_name, query)


def log(message):
    print("%s %s" % (datetime.now(UTC).strftime("%H:%M:%S"), message), flush=True)


def unpadded_query(prefix: str = "") -> Dict[str, Any]:
    """Values of fewer than 16 digits; anchored, so the index on the field serves it."""
    return {prefix + "_pichash": {"$regex": "^0x[0-9a-f]{1,%d}$" % (PICHASH_HEX_DIGITS - 1)}}


def unpadded_block_query() -> Dict[str, Any]:
    return {"_picblockhashes.hash": {"$regex": "^0x[0-9a-f]{1,%d}$" % (PICHASH_HEX_DIGITS - 1)}}


def padded_query() -> Dict[str, Any]:
    return {"_pichash": {"$regex": "^0x[0-9a-f]{%d}$" % PICHASH_HEX_DIGITS}}


def padded_block_query() -> Dict[str, Any]:
    return {"_picblockhashes.hash": {"$regex": "^0x[0-9a-f]{%d}$" % PICHASH_HEX_DIGITS}}


def rewrite(document: Dict[str, Any], padded: bool) -> Optional[UpdateOne]:
    """The update that brings one document to the requested width, or None if it is there."""
    update: Dict[str, Any] = {}
    pichash = document.get("_pichash")
    if isinstance(pichash, str):
        wanted = encode_pichash_value(int(pichash, 16), padded)
        if wanted != pichash:
            update["_pichash"] = wanted
    block_entries = document.get("_picblockhashes")
    if block_entries:
        wanted_hashes = [encode_pichash_value(int(entry["hash"], 16), padded) if isinstance(entry.get("hash"), str) else entry.get("hash") for entry in block_entries]
        if wanted_hashes != [entry.get("hash") for entry in block_entries]:
            # positional per-element $set keeps offset/length untouched and the array order stable
            for position, wanted in enumerate(wanted_hashes):
                if wanted != block_entries[position].get("hash"):
                    update["_picblockhashes.%d.hash" % position] = wanted
    if not update:
        return None
    return UpdateOne({"function_id": document["function_id"]}, {"$set": update})


def get_state(db, key):
    return db[STATE_COLLECTION].find_one({"_id": key}) or {"_id": key, "last_function_id": None, "seen": 0, "rewritten": 0, "started_at": None}


def put_state(db, state):
    db[STATE_COLLECTION].replace_one({"_id": state["_id"]}, state, upsert=True)


def walk(db, collection_name: str, padded: bool, batch_size: int) -> Dict[str, Any]:
    mode = "pad" if padded else "unpad"
    state = get_state(db, "%s:%s" % (mode, collection_name))
    if state["started_at"] is None:
        state["started_at"] = datetime.now(UTC).isoformat()
    last_function_id = state["last_function_id"]
    seen, rewritten = state["seen"], state["rewritten"]
    started = time.perf_counter()
    log("%s %s from function_id > %s" % (mode, collection_name, last_function_id))
    while True:
        query = {} if last_function_id is None else {"function_id": {"$gt": last_function_id}}
        documents = list(db[collection_name].find(query, PROJECTION).sort("function_id", ASCENDING).limit(batch_size))
        if not documents:
            break
        updates = [update for update in (rewrite(document, padded) for document in documents) if update is not None]
        if updates:
            db[collection_name].bulk_write(updates, ordered=False)
        last_function_id = documents[-1]["function_id"]
        seen += len(documents)
        rewritten += len(updates)
        state.update({"last_function_id": last_function_id, "seen": seen, "rewritten": rewritten})
        put_state(db, state)
        if seen % (batch_size * 10) == 0:
            elapsed = time.perf_counter() - started
            log("  %d seen, %d rewritten, %.0f docs/s" % (seen, rewritten, seen / max(elapsed, 1e-9)))
    # documents the keyset walk did not see: written below the cursor by a server that was
    # still running, or left by an interrupted earlier run
    leftover_query = {"$or": [unpadded_query(), unpadded_block_query()]} if padded else {"$or": [padded_query(), padded_block_query()]}
    swept = 0
    while True:
        documents = list(db[collection_name].find(leftover_query, PROJECTION).limit(batch_size))
        updates = [update for update in (rewrite(document, padded) for document in documents) if update is not None]
        if not updates:
            break
        db[collection_name].bulk_write(updates, ordered=False)
        swept += len(updates)
    state["finished_at"] = datetime.now(UTC).isoformat()
    put_state(db, state)
    elapsed = time.perf_counter() - started
    log("done %s: %d seen, %d rewritten, %d swept, %.1f s" % (collection_name, seen, rewritten, swept, elapsed))
    return {"seen": seen, "rewritten": rewritten, "swept": swept, "seconds": elapsed}


def set_flag(db, padded: bool) -> None:
    db.settings.update_one({}, {"$set": {"pichash_padded": padded}}, upsert=True)
    # clear the walk state so a later run of the other mode starts from the top
    db[STATE_COLLECTION].delete_many({})
    log("settings.pichash_padded = %s" % padded)


def verify(db) -> Dict[str, Any]:
    settings = db.settings.find_one({}, {"pichash_padded": 1, "_id": 0}) or {}
    flag = bool(settings.get("pichash_padded", False))
    report: Dict[str, Any] = {"pichash_padded": flag, "collections": {}, "problems": []}
    for collection_name in COLLECTIONS:
        counts = {
            "documents": db[collection_name].count_documents({}),
            "unpadded_pichashes": db[collection_name].count_documents(unpadded_query()),
            "padded_pichashes": db[collection_name].count_documents(padded_query()),
            "documents_with_unpadded_blockhashes": db[collection_name].count_documents(unpadded_block_query()),
            "documents_with_padded_blockhashes": db[collection_name].count_documents(padded_block_query()),
        }
        report["collections"][collection_name] = counts
        # only one direction is a problem: a 16-digit value is legitimate under either encoding
        # (most 64 bit pichashes have no leading zero), an unpadded one only while the flag is unset
        if flag and (counts["unpadded_pichashes"] or counts["documents_with_unpadded_blockhashes"]):
            report["problems"].append("%s: flag says padded but unpadded values remain; re-run --mode pad" % collection_name)
    return report


def run(db, mode: str, batch_size: int = 2000) -> Dict[str, Any]:
    result: Dict[str, Any] = {"mode": mode, "utc": datetime.now(UTC).isoformat()}
    if mode == "verify":
        result.update(verify(db))
        return result
    padded = mode == "pad"
    for collection_name in COLLECTIONS:
        result[collection_name] = walk(db, collection_name, padded, batch_size)
    set_flag(db, padded)
    result.update(verify(db))
    return result


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["pad", "verify", "unpad"], required=True)
    storage_config = McritConfig().STORAGE_CONFIG
    parser.add_argument("--host", default=storage_config.STORAGE_SERVER)
    parser.add_argument("--port", type=int, default=int(storage_config.STORAGE_PORT))
    parser.add_argument("--db", default=storage_config.STORAGE_MONGODB_DBNAME)
    parser.add_argument("--uri", default=None, help="complete MongoDB URI; overrides host/port and the configured credentials and flags")
    parser.add_argument("--batch", type=int, default=2000)
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)

    # the same credentials and connection flags MongoDbStorage connects with (STORAGE_MONGODB_*),
    # so a secured deployment needs nothing beyond its mcrit configuration
    uri = args.uri or build_mongo_uri(
        args.host, args.port, args.db, storage_config.STORAGE_MONGODB_USERNAME, storage_config.STORAGE_MONGODB_PASSWORD, storage_config.STORAGE_MONGODB_FLAGS
    )
    db = MongoClient(uri, connect=True)[args.db]
    result = run(db, args.mode, args.batch)
    print(json.dumps(result, indent=2, default=str))
    if args.out:
        with open(args.out, "w") as handle:
            json.dump(result, handle, indent=2, default=str)
    return 1 if result.get("problems") else 0


if __name__ == "__main__":
    sys.exit(main())
