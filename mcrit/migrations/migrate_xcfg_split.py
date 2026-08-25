#!/usr/bin/env python3
"""C1 migration: move `_xcfg` out of `functions` into its own collection.

Two modes, sharing one code path so the rehearsal exercises the real thing:

  copy    - read SOURCE read-only, write the migrated shape into TARGET. Used to
            rehearse against production data without touching it, and to measure
            what the real migration will cost.
  inplace - the production migration: write each batch's xcfg documents, then
            $unset `_xcfg` on those functions only after the write is durable.

Both are **resumable**: progress is a keyset cursor (last migrated function_id) kept
in a state document, so a killed run costs only the batch in flight. Re-running after
completion is a no-op. Neither mode deletes anything the other copy does not already
hold - `inplace` only unsets `_xcfg` for ids whose xcfg document is confirmed present.

Usage:
    python -m mcrit.migrations.migrate_xcfg_split --mode copy --target mcrit_rehearsal
    python -m mcrit.migrations.migrate_xcfg_split --mode verify --target mcrit_rehearsal
    python -m mcrit.migrations.migrate_xcfg_split --mode inplace
    python -m mcrit.migrations.migrate_xcfg_split --mode unsplit   # rollback
"""

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from typing import Any, Dict

from pymongo import ASCENDING, MongoClient, ReplaceOne, UpdateOne

from mcrit.config.McritConfig import McritConfig

STATE_COLLECTION = "c1_migration_state"
XCFG_COLLECTION = "xcfg"
# collections copied verbatim in copy mode, so the rehearsal target can serve a real
# matching job (bands + sample/family metadata + the counters ids are drawn from)
VERBATIM_PREFIXES = ("band_",)
VERBATIM_COLLECTIONS = ("samples", "families", "counters", "query_samples")


def log(message):
    print("%s %s" % (datetime.now(UTC).strftime("%H:%M:%S"), message), flush=True)


def get_state(target_db, key):
    document = target_db[STATE_COLLECTION].find_one({"_id": key})
    return document or {"_id": key, "last_function_id": None, "migrated": 0, "started_at": None}


def put_state(target_db, state):
    target_db[STATE_COLLECTION].replace_one({"_id": state["_id"]}, state, upsert=True)


def recreate_indexes(source_db, target_db, collection_name):
    """Rebuild every secondary index, carrying over its options.

    Only key order and `unique` would survive a hand-rolled copy; TTL, sparse,
    partialFilterExpression and friends live in the spec alongside them and are lost if
    not forwarded - so forward everything the server reports except the fields
    `create_index` derives itself.
    """
    for index in source_db[collection_name].list_indexes():
        keys = list(index["key"].items())
        if keys == [("_id", 1)]:
            continue
        options = {key: value for key, value in index.items() if key not in ("key", "v", "name", "ns")}
        target_db[collection_name].create_index(keys, **options)
        log("  recreated index %s %s" % (keys, options or ""))


def copy_verbatim(source_db, target_db, batch_size):
    names = [n for n in source_db.list_collection_names() if n in VERBATIM_COLLECTIONS or n.startswith(VERBATIM_PREFIXES)]
    for name in sorted(names):
        # exact counts, not estimated_document_count(): the estimate reads cached collection
        # metadata and can misread a partially copied target as "already present"
        if target_db[name].count_documents({}) >= source_db[name].count_documents({}):
            log("verbatim %s already present, skipping" % name)
            continue
        target_db[name].drop()
        copied = 0
        batch = []
        for document in source_db[name].find({}):
            batch.append(document)
            if len(batch) >= batch_size:
                target_db[name].insert_many(batch, ordered=False)
                copied += len(batch)
                batch = []
        if batch:
            target_db[name].insert_many(batch, ordered=False)
            copied += len(batch)
        recreate_indexes(source_db, target_db, name)
        log("verbatim %s: %d documents" % (name, copied))


def migrate_functions(source_db, target_db, mode, batch_size, limit, source_collection, xcfg_collection):
    state_key = "%s:%s:%s" % (mode, source_collection, xcfg_collection)
    state = get_state(target_db, state_key)
    if state["started_at"] is None:
        state["started_at"] = datetime.now(UTC).isoformat()
    last_function_id = state["last_function_id"]
    migrated = state["migrated"]
    xcfg_bytes = 0
    started = time.perf_counter()
    log("migrating %s (mode=%s) from function_id > %s" % (source_collection, mode, last_function_id))

    finished = True
    while True:
        query = {} if last_function_id is None else {"function_id": {"$gt": last_function_id}}
        # keyset paging on the indexed function_id: skip() would re-walk the collection
        documents = list(source_db[source_collection].find(query, {"function_id": 1, "_xcfg": 1, "_id": 0}).sort("function_id", ASCENDING).limit(batch_size))
        if not documents:
            break

        xcfg_documents = []
        function_ids_done = []
        for document in documents:
            function_id = document["function_id"]
            function_ids_done.append(function_id)
            xcfg = document.get("_xcfg")
            if xcfg:
                xcfg_bytes += len(xcfg)
                # _id IS the function_id: no secondary index needed, one lookup, minimal storage
                xcfg_documents.append(UpdateOne({"_id": function_id}, {"$set": {"_xcfg": xcfg}}, upsert=True))

        if xcfg_documents:
            target_db[xcfg_collection].bulk_write(xcfg_documents, ordered=False)

        if mode == "copy":
            # copy the function documents themselves, minus the blob
            function_documents = list(source_db[source_collection].find({"function_id": {"$in": function_ids_done}}, {"_xcfg": 0}))
            if function_documents:
                # upserts, not insert_many: a resume can re-enter the batch whose inserts
                # landed before the state save was killed - plain inserts would die on
                # duplicate _id there and make copy mode unresumable
                target_db[source_collection].bulk_write([ReplaceOne({"_id": document["_id"]}, document, upsert=True) for document in function_documents], ordered=False)
        elif mode == "inplace":
            # only now that the xcfg documents are durable, drop the blobs. Restricted to
            # ids we just wrote, so a crash can never unset an xcfg that was not saved.
            written_ids = [op._filter["_id"] for op in xcfg_documents]
            if written_ids:
                source_db[source_collection].update_many({"function_id": {"$in": written_ids}}, {"$unset": {"_xcfg": ""}})

        last_function_id = function_ids_done[-1]
        migrated += len(documents)
        state.update({"last_function_id": last_function_id, "migrated": migrated})
        put_state(target_db, state)

        if migrated % (batch_size * 10) == 0:
            elapsed = time.perf_counter() - started
            log("  %d migrated, %.0f docs/s, %.1f GB of xcfg moved" % (migrated, migrated / max(elapsed, 1e-9), xcfg_bytes / 1073741824))
        if limit and migrated >= limit:
            log("stopping at --limit %d" % limit)
            finished = False
            break

    if mode == "copy":
        # without these the target is not a like-for-like copy and any benchmark against it
        # measures missing indexes rather than the schema change
        index_started = time.perf_counter()
        recreate_indexes(source_db, target_db, source_collection)
        log("indexes rebuilt in %.1f s" % (time.perf_counter() - index_started))

    if finished:
        # terminal marker, read by MongoDbStorage.hasInlineXcfgRemaining: an inplace phase that
        # drained guarantees no inline `_xcfg` remains (the $unset only runs after the blob write),
        # so storage can report the migrated state O(1) instead of COLLSCAN-ing functions to prove
        # a negative. A --limit run deliberately writes none. unsplit deletes state documents, so
        # a rollback also removes the marker.
        state["finished_at"] = datetime.now(UTC).isoformat()
        put_state(target_db, state)
        log("phase finished, terminal marker written")

    elapsed = time.perf_counter() - started
    log("done: %d documents, %.1f GB xcfg, %.1f s (%.0f docs/s)" % (migrated, xcfg_bytes / 1073741824, elapsed, migrated / max(elapsed, 1e-9)))
    return {"migrated": migrated, "xcfg_bytes": xcfg_bytes, "seconds": elapsed}


def unsplit(db, batch_size, source_collection, xcfg_collection):
    """Rollback: write `_xcfg` back into the function documents and drop the blob collection.

    Needed because rollback is only free before the `$unset` phase of an inplace migration.
    After it, the blobs exist ONLY in the split collection, so undoing the migration means
    putting them back - this is that inverse. Same ordering discipline as forward: a function
    document is only updated from a blob that was read successfully, and the blob collection is
    dropped at the very end, so an interrupted run leaves duplicated data rather than none.
    """
    restored = 0
    missing = 0
    started = time.perf_counter()
    last_id = None
    while True:
        query = {} if last_id is None else {"_id": {"$gt": last_id}}
        blob_documents = list(db[xcfg_collection].find(query).sort("_id", ASCENDING).limit(batch_size))
        if not blob_documents:
            break
        operations = []
        for blob_document in blob_documents:
            operations.append(UpdateOne({"function_id": blob_document["_id"]}, {"$set": {"_xcfg": blob_document["_xcfg"]}}))
        result = db[source_collection].bulk_write(operations, ordered=False)
        restored += result.matched_count
        missing += len(operations) - result.matched_count
        last_id = blob_documents[-1]["_id"]
        if restored % (batch_size * 10) == 0:
            log("  %d restored, %d without a function document, %.0f docs/s" % (restored, missing, restored / max(time.perf_counter() - started, 1e-9)))
    log("restored %d blobs (%d had no matching function document) in %.1f s" % (restored, missing, time.perf_counter() - started))
    # Clear the forward migration's resume state. Without this a later re-migration finds the
    # cursor at the end, does nothing, and logs "done" - a silent no-op after a rollback.
    state_result = db[STATE_COLLECTION].delete_many({"_id": {"$regex": ":%s:%s$" % (source_collection, xcfg_collection)}})
    if state_result.deleted_count:
        log("cleared %d migration state document(s) so a re-migration starts from the beginning" % state_result.deleted_count)
    dropped = False
    if missing:
        # dropping now would destroy blobs whose function document is gone - keep them and say so
        log("KEEPING %s: %d blobs have no matching function document and would be lost" % (xcfg_collection, missing))
    else:
        db[xcfg_collection].drop()
        dropped = True
        log("dropped %s: every blob was restored into a function document" % xcfg_collection)
    return {
        "restored": restored,
        "orphaned_blobs": missing,
        "dropped_blob_collection": dropped,
        "cleared_state_documents": state_result.deleted_count,
        "seconds": time.perf_counter() - started,
    }


def verify(source_db, target_db, sample_size, source_collection, xcfg_collection, max_function_id=None):
    """Spot-check that no xcfg was lost or altered, and that counts line up.

    Sampling is restricted to the range the migration has actually reached, taken from the
    resume state unless overridden, so a partial rehearsal can be verified without every
    not-yet-migrated function being reported as a loss.
    """
    problems = []
    # exact counts, not estimated_document_count(): the latter reads cached collection
    # metadata and was measured 36,662 documents (0.3%) stale on the live instance, which
    # would report a perfectly faithful migration as a count mismatch
    source_count = source_db[source_collection].count_documents({})
    target_count = target_db[source_collection].count_documents({})

    if max_function_id is None:
        for state_document in target_db[STATE_COLLECTION].find({"_id": {"$regex": ":%s:%s$" % (source_collection, xcfg_collection)}}):
            if state_document.get("last_function_id") is not None:
                max_function_id = max(max_function_id or 0, state_document["last_function_id"])
    complete = max_function_id is None
    if complete and target_count and source_count != target_count:
        problems.append("function count mismatch: source %d target %d" % (source_count, target_count))

    range_filter = {} if complete else {"function_id": {"$lte": max_function_id}}
    pipeline = [{"$match": range_filter}, {"$sample": {"size": sample_size}}, {"$project": {"function_id": 1, "_xcfg": 1, "_id": 0}}]
    checked = 0
    empty_source = 0
    for document in source_db[source_collection].aggregate(pipeline):
        function_id = document["function_id"]
        source_xcfg = document.get("_xcfg")
        migrated = target_db[xcfg_collection].find_one({"_id": function_id})
        if not source_xcfg:
            empty_source += 1
            continue
        if migrated is None:
            problems.append("function %d: no xcfg document in target" % function_id)
        elif migrated["_xcfg"] != source_xcfg:
            problems.append("function %d: xcfg differs (%d vs %d bytes)" % (function_id, len(source_xcfg), len(migrated["_xcfg"])))
        checked += 1
    # After an inplace migration the source no longer holds blobs, so content comparison is
    # impossible - saying "problems: []" then would be a silent pass. Check coverage instead and
    # label what was actually established.
    gap_function_ids = []
    if checked == 0 and empty_source:
        # probe the sampled function ids against the blob collection in batches instead of
        # materializing every blob _id: at production scale that set alone would not fit memory
        function_ids = [document["function_id"] for document in source_db[source_collection].find(range_filter, {"function_id": 1, "_id": 0}).limit(200000)]
        covered_ids = set()
        for start in range(0, len(function_ids), 10000):
            chunk = function_ids[start : start + 10000]
            covered_ids.update(document["_id"] for document in target_db[xcfg_collection].find({"_id": {"$in": chunk}}, {"_id": 1}))
        gap_function_ids = [function_id for function_id in function_ids if function_id not in covered_ids]
        if gap_function_ids:
            problems.append(
                "no blob document for %d of %d sampled function ids, e.g. %s"
                % (
                    len(gap_function_ids),
                    len(function_ids),
                    gap_function_ids[:5],
                )
            )
    return {
        "checked": checked,
        "established": (
            "blob contents compared byte-for-byte"
            if checked
            else "coverage only - the source no longer holds blobs, so contents could not be compared (take a dump before an inplace run)"
        ),
        "coverage_gaps_sampled": len(gap_function_ids),
        "verified_range_max_function_id": max_function_id,
        "empty_source": empty_source,
        "source_functions": source_count,
        "target_functions": target_count,
        "target_xcfg_documents": target_db[xcfg_collection].estimated_document_count(),
        "problems": problems,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["copy", "inplace", "verify", "unsplit"], required=True)
    storage_config = McritConfig().STORAGE_CONFIG
    parser.add_argument("--host", default=storage_config.STORAGE_SERVER)
    parser.add_argument("--port", type=int, default=int(storage_config.STORAGE_PORT))
    parser.add_argument("--source", default=storage_config.STORAGE_MONGODB_DBNAME)
    parser.add_argument("--target", default=None, help="target DB for copy/verify; defaults to source for inplace")
    parser.add_argument("--batch", type=int, default=2000)
    parser.add_argument("--limit", type=int, default=0, help="stop after N functions (rehearsal/sampling)")
    parser.add_argument("--sample", type=int, default=2000, help="verify: how many functions to spot-check")
    parser.add_argument("--max-function-id", type=int, default=None, help="verify: cap the sampled range (defaults to how far the migration got)")
    parser.add_argument("--include-query-functions", action="store_true")
    parser.add_argument("--skip-verbatim", action="store_true")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    client = MongoClient("mongodb://%s:%d" % (args.host, args.port), connect=True)
    source_db = client[args.source]
    target_db = client[args.target] if args.target else source_db
    if args.mode == "inplace" and args.target and args.target != args.source:
        parser.error("inplace mode migrates within one database; drop --target")

    result: Dict[str, Any] = {"mode": args.mode, "source": args.source, "target": args.target or args.source, "utc": datetime.now(UTC).isoformat()}

    if args.mode == "unsplit":
        result["functions"] = unsplit(source_db, args.batch, "functions", XCFG_COLLECTION)
        if args.include_query_functions:
            result["query_functions"] = unsplit(source_db, args.batch, "query_functions", "query_" + XCFG_COLLECTION)
    elif args.mode == "verify":
        result["functions"] = verify(source_db, target_db, args.sample, "functions", XCFG_COLLECTION, args.max_function_id)
        if args.include_query_functions:
            result["query_functions"] = verify(source_db, target_db, args.sample, "query_functions", "query_" + XCFG_COLLECTION, args.max_function_id)
    else:
        if args.mode == "copy" and not args.skip_verbatim:
            copy_verbatim(source_db, target_db, args.batch)
        result["functions"] = migrate_functions(source_db, target_db, args.mode, args.batch, args.limit, "functions", XCFG_COLLECTION)
        if args.include_query_functions:
            result["query_functions"] = migrate_functions(source_db, target_db, args.mode, args.batch, args.limit, "query_functions", "query_" + XCFG_COLLECTION)

    print(json.dumps(result, indent=2, default=str))
    if args.out:
        with open(args.out, "w") as handle:
            json.dump(result, handle, indent=2, default=str)
    problems = result.get("functions", {}).get("problems") if args.mode == "verify" else None
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
