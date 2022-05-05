import datetime
import json
import logging
import traceback
from operator import itemgetter
from typing import Any, TYPE_CHECKING, Dict, List, Optional, Set, Tuple


LOGGER = logging.getLogger(__name__)
try:
    from pymongo import InsertOne, MongoClient, UpdateOne
    from pymongo.collection import ReturnDocument
except:
    LOGGER.warn("pymongo package import failed - MongoDB backend will not be available.")

from picblocks.blockhasher import BlockHasher

from mcrit.libs.utility import generate_unique_groups
from mcrit.storage.FunctionEntry import FunctionEntry
from mcrit.storage.MatchingCache import MatchingCache
from mcrit.storage.SampleEntry import SampleEntry
from mcrit.storage.StorageInterface import StorageInterface

if TYPE_CHECKING: # pragma: no cover
    from mcrit.config.StorageConfig import StorageConfig
    from mcrit.minhash.MinHash import MinHash
    from mcrit.storage.MemoryStorage import MemoryStorage
    from pymongo.database import Database
    from smda.common.SmdaFunction import SmdaFunction
    from smda.common.SmdaReport import SmdaReport

# TODO when is checking self._database.samples.count_documents() necessary?


class MongoDbStorage(StorageInterface):

    _DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

    _database: "Database"
    _matching_cache: Optional[MatchingCache]

    def __init__(self, config: "StorageConfig") -> None:
        super().__init__(config)  # sets config
        self._matching_cache = None
        self.blockhasher = BlockHasher()
        self._initDb(self._config.STORAGE_SERVER, self._config.STORAGE_PORT, self._config.STORAGE_MONGODB_DBNAME)

    def _initDb(self, server, port, db_name):
        self._database = MongoClient(server, port=port)[db_name]
        self._ensureIndexAndUnknownFamily()

    def _ensureIndexAndUnknownFamily(self) -> None:
        self._database["samples"].create_index("sample_id")
        self._database["families"].create_index("family_id")
        self._database["functions"].create_index("function_id")
        self._database["functions"].create_index("sample_id")
        self._database["functions"].create_index("_pichash")
        self._database["functions"].create_index("_picblockhashes.hash")
        self._database["matches"].create_index("match_id")
        self._database["candidates"].create_index("function_id")
        self._database["counters"].create_index("name")
        for band_id in range(self._config.STORAGE_NUM_BANDS):
            self._database["band_%d" % band_id].create_index("band_hash")
        # Add Family "" if it is not already in storage
        if self.getFamily(0) is None:
            self.addFamily("")
        assert self.getFamily(0) == ""

    ###############################################################################
    # Generic database functionality and logging
    ###############################################################################

    def _getCurrentTimestamp(self) -> datetime.datetime:
        return datetime.datetime.utcnow()

    def _convertTimestampToString(self, timestamp) -> str:
        return datetime.datetime.fromtimestamp(timestamp).strftime(self._DATETIME_FORMAT)

    def _convertDatetimeToString(self, dt: datetime.datetime) -> str:
        return dt.strftime(self._DATETIME_FORMAT)

    def _convertStringToDatetime(self, date_string: str) -> datetime.datetime:
        return datetime.datetime.strptime(date_string, self._DATETIME_FORMAT)

    def _toBinary(self, obj):
        """Checks data to be inserted to the database for non-UTF8 strings and escapes these as BSON.Binary"""
        if isinstance(obj, str):
            return obj
            # return bson.binary.Binary(obj)
        elif isinstance(obj, dict):
            return {k: self._toBinary(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._toBinary(element) for element in obj]
        elif isinstance(obj, tuple):
            return tuple(self._toBinary(element) for element in obj)
        elif isinstance(obj, set):
            return [self._toBinary(element) for element in sorted(obj)]
        else:
            return obj

    def _dbInsert(self, collection: str, data: Dict):
        try:
            insert_result = self._database[collection].insert_one(self._toBinary(data))
            if insert_result.acknowledged:
                return insert_result.inserted_id
            return None
        except Exception as exc:
            self._dbLogError(
                'Database insert for collection "%s" failed.' % collection,
                {"user": "internal/mcrit", "traceback": traceback.format_exc(exc).split("\n")},
            )
            raise ValueError("Database insert failed.")

    def _dbQuery(self, collection: str, query: Dict, find_one: bool = False):
        try:
            if find_one:
                return self._database[collection].find_one(query)
            else:
                return self._database[collection].find(query)
        except Exception as exc:
            self._dbLogError(
                'Database query for collection "%s" failed.' % collection,
                {"user": "internal/mcrit", "traceback": traceback.format_exc(exc).split("\n")},
            )
            raise ValueError("Database query failed.")

    def _dbLogEvent(self, event_msg, details=None):
        if details is None:
            details = {"user": "internal"}
        self._dbLog("event", event_msg, details)

    def _dbLogError(self, error_msg, details=None):
        if details is None:
            details = {"user": "internal"}
        self._dbLog("error", error_msg, details)

    def _dbLog(self, log_type, log_msg, log_details):
        record = {"ts": self._getCurrentTimestamp(), "%s_msg" % log_type: log_msg, "%s_details" % log_type: log_details}
        self._database[log_type].insert_one(self._toBinary(record))

    def _useCounter(self, name: str) -> int:
        result = self._database.counters.find_one_and_update(
            filter={"name": name}, 
            update={"$inc": {"value": 1}}, 
            # return_document=ReturnDocument.AFTER,
            upsert=True
        )
        if result is None:
            return 0
        return result["value"]

    ###############################################################################
    # Conversion
    ###############################################################################
    def _encodeXcfg(self, function_dict: Dict, delete_old: bool = True) -> None:
        if "xcfg" in function_dict:
            function_dict["_xcfg"] = json.dumps(function_dict["xcfg"])
            if delete_old:
                del function_dict["xcfg"]

    def _decodeXcfg(self, function_dict: Dict, delete_old: bool = True) -> None:
        if "_xcfg" in function_dict:
            function_dict["xcfg"] = json.loads(function_dict["_xcfg"])
            if delete_old:
                del function_dict["_xcfg"]

    def _encodePichash(self, function_dict: Dict, delete_old: bool = True) -> None:
        if "pichash" in function_dict:
            function_dict["_pichash"] = hex(function_dict["pichash"])
            if delete_old:
                del function_dict["pichash"]
        if "picblockhashes" in function_dict:
            converted_entries = []
            for blockhash_dict in function_dict["picblockhashes"]:
                converted_entries.append({
                    "hash": hex(blockhash_dict["hash"]),
                    "size": blockhash_dict["size"],
                    "count": blockhash_dict["count"],
                })
            function_dict["_picblockhashes"] = converted_entries
            if delete_old:
                del function_dict["picblockhashes"]

    def _decodePichash(self, function_dict: Dict, delete_old: bool = True) -> None:
        if "_pichash" in function_dict:
            function_dict["pichash"] = int(function_dict["_pichash"], 16)
            if delete_old:
                del function_dict["_pichash"]
        if "_picblockhashes" in function_dict:
            converted_entries = []
            for blockhash_dict in function_dict["_picblockhashes"]:
                converted_entries.append({
                    "hash": int(blockhash_dict["hash"], 16),
                    "size": blockhash_dict["size"],
                    "count": blockhash_dict["count"],
                })
            function_dict["picblockhashes"] = converted_entries
            if delete_old:
                del function_dict["_picblockhashes"]

    def _encodeFunction(self, function_dict: Dict, delete_old: bool = True) -> None:
        self._encodePichash(function_dict, delete_old=delete_old)
        self._encodeXcfg(function_dict, delete_old=delete_old)

    def _decodeFunction(self, function_dict: Dict, delete_old: bool = True) -> None:
        self._decodePichash(function_dict, delete_old=delete_old)
        self._decodeXcfg(function_dict, delete_old=delete_old)

    ###############################################################################
    # Interface
    ###############################################################################

    def getContent(self) -> Dict[str, Any]:
        raise NotImplementedError

    def setContent(self, content: Dict[str, Any]) -> None:
        raise NotImplementedError

    # NOTE this actually only gets used in MemoryStorage / MatchingCache
    def getMinHashByFunctionId(self, function_id: int) -> Optional[bytes]:
        function = self.getFunctionById(function_id)
        if function is None:
            return None
        return function.minhash

    # NOTE this actually only gets used in MemoryStorage / MatchingCache
    def getSampleIdByFunctionId(self, function_id: int) -> Optional[int]:
        function_document = self._database.functions.find_one({"function_id": function_id})
        if function_document is None:
            return None
        return function_document["sample_id"]

    def deleteSample(self, sample_id: int) -> bool:
        function_entries = self.getFunctionsBySampleId(sample_id)
        if function_entries is None:
            # in this case sample_id is does not exist
            return False

        for function_entry in function_entries:
            minhash = function_entry.getMinHash()
            # remove minhash entries, if necessary
            if not minhash:
                continue
            band_hashes = self.getBandHashesForMinHash(minhash)
            for band_number, band_hash in sorted(band_hashes.items()):
                # delete function id from bandhash
                band_document = self._database["band_%d" % band_number].find_one_and_update(
                    {"band_hash": band_hash},
                    {"$pull": {"function_ids": minhash.function_id}},
                    return_document=ReturnDocument.AFTER,
                )
                # delete bandhash if empty
                if band_document is not None and len(band_document["function_ids"]) == 0:
                    self._database["band_%d" % band_number].delete_one({"band_hash": band_hash})

        # remove functions
        self._database.functions.delete_many({"sample_id": sample_id})
        # remove sample
        self._database.samples.delete_one({"sample_id": sample_id})
        return True

    def getSamplesByFamilyId(self, family_id: int) -> Optional[List["SampleEntry"]]:
        if self.getFamily(family_id) is None:
            return None
        samples = self._database.samples.find({"family_id": family_id}, {"_id":0})
        return [SampleEntry.fromDict(sample_document) for sample_document in samples]

    def getSamples(self, start_index: int, limit: int) -> Optional["SampleEntry"]:
        sample_entries = []
        for sample_document in self._database.samples.find().skip(start_index).limit(limit):
            sample_entries.append(SampleEntry.fromDict(sample_document))
        return sample_entries

    def clearStorage(self) -> None:
        collections = ["samples", "families", "functions", "matches", "candidates", "counters"]
        for band_id in range(self._config.STORAGE_NUM_BANDS):
            collections.append("band_%d" % band_id)
        for c in collections:
            self._database[c].drop()
        self._ensureIndexAndUnknownFamily()

    def getSampleBySha256(self, sha256: str) -> Optional["SampleEntry"]:
        if self._database.samples.count_documents(filter={}):
            report_dict = self._database.samples.find_one({"sha256": sha256})
            if not report_dict:
                return None
            return SampleEntry.fromDict(report_dict)
        return None

    def addSmdaReport(self, smda_report: "SmdaReport") -> Optional["SampleEntry"]:
        sample_entry = None
        if not self.getSampleBySha256(smda_report.sha256):
            sample_entry = SampleEntry(
                smda_report, sample_id=self._useCounter("samples"), family_id=self.addFamily(smda_report.family)
            )
            self._dbInsert("samples", sample_entry.toDict())
            for smda_function in smda_report.getFunctions():
                self._addFunction(sample_entry, smda_function)
        else:
            LOGGER.warn("Sample %s already existed, skipping.", smda_report.sha256)
        return sample_entry

    def importSampleEntry(self, sample_entry: "SampleEntry") -> Optional["SampleEntry"]:
        if not self.getSampleBySha256(sample_entry.sha256):
            sample_id = self._useCounter("samples")
            sample_entry.sample_id = sample_id
            self._dbInsert("samples", sample_entry.toDict())
        else:
            LOGGER.warn("Sample %s already existed, skipping.", sample_entry.sha256)
        return sample_entry

    def importFunctionEntry(self, function_entry: "FunctionEntry") -> Optional["FunctionEntry"]:
        function_entry.function_id = self._useCounter("functions")
        # add function to regular storage
        function_dict = function_entry.toDict()
        self._encodeFunction(function_dict)
        self._dbInsert("functions", function_dict)
        return function_entry

    def getFunctionsBySampleId(self, sample_id: int) -> Optional[List["FunctionEntry"]]:
        if not self.isSampleId(sample_id):
            return None
        function_dicts = list(self._database.functions.find({"sample_id": sample_id}, {"_id": 0}))
        functions = []
        for f in function_dicts:
            self._decodeFunction(f)
            functions.append(FunctionEntry.fromDict(f))
        return functions

    def getFunctions(self, start_index: int, limit: int) -> Optional["FunctionEntry"]:
        functions = []
        for function_document in self._database.functions.find().skip(start_index).limit(limit):
            self._decodeFunction(function_document)
            functions.append(FunctionEntry.fromDict(function_document))
        return functions

    def getSampleIds(self) -> List[int]:
        return self._database.samples.find().distinct("sample_id")

    def isSampleId(self, sample_id: int) -> bool:
        return bool(self._database.samples.find_one({"sample_id": sample_id}))

    def getPicHashMatchesBySampleId(self, sample_id: int) -> Optional[Dict[int, Set[Tuple[int, int]]]]:
        if not self.isSampleId(sample_id):
            return None
        function_ids = list(
            map(
                itemgetter("function_id"),
                list(self._database.functions.find({"sample_id": sample_id}, {"function_id": 1, "_id": 0})),
            )
        )  # ["function_id"]
        return self.getPicHashMatchesByFunctionIds(function_ids)

    def getPicHashMatchesByFunctionId(self, function_id: int) -> Optional[Dict[int, Set[Tuple[int, int]]]]:
        query_result = self._database.functions.find_one({"function_id": function_id})
        if query_result is None or not "_pichash" in query_result:
            return None
        self._decodePichash(query_result, delete_old=False)
        encoded_pichash = query_result["_pichash"]
        decoded_pichash = query_result["pichash"]
        if decoded_pichash is None:
            return None

        sample_and_function_ids = set(
            map(
                lambda x: (x["sample_id"], x["function_id"]),
                list(self._database.functions.find({"_pichash": encoded_pichash})),
            )
        )

        return {decoded_pichash: sample_and_function_ids}

    def getPicHashMatchesByFunctionIds(self, function_ids: List[int]) -> Dict[int, Set[Tuple[int, int]]]:
        # internal format!
        pichash_raw = self._database.functions.find({"function_id": {"$in": function_ids}}, {"_pichash": 1, "_id": 0})
        pichashes_list = list(pichash_raw)  # broken? TODO
        pichashes = {}
        for pichash in pichashes_list:
            # TODO what happens if pichash does not exist??
            self._decodePichash(pichash, delete_old=False)
            encoded_pichash = pichash["_pichash"]
            decoded_pichash = pichash["pichash"]
            if decoded_pichash in pichashes:
                continue
            pichashes[decoded_pichash] = set(
                map(
                    lambda x: (x["sample_id"], x["function_id"]),
                    list(self._database.functions.find({"_pichash": encoded_pichash})),
                )
            )
        return pichashes

    def isFunctionId(self, function_id: int) -> bool:
        return bool(self._database.functions.find_one({"function_id": function_id}))

    def isFamilyId(self, family_id: int) -> bool:
        return bool(self._database.families.find_one({"family_id": family_id}))

    def addMinHash(self, minhash: "MinHash") -> bool:
        if minhash.function_id is None:
            return False
        function_entry = self.getFunctionById(minhash.function_id)
        if function_entry is None:
            return False
        function_entry.minhash = minhash.getMinHash()
        function_entry.minhash_shingle_composition = minhash.getComposition()
        function_dict = function_entry.toDict()
        self._encodeFunction(function_dict)
        set_command = {
            "$set": {"minhash": minhash.getMinHash().hex(), "minhash_shingle_composition": minhash.getComposition()}
        }
        self._database["functions"].find_one_and_update({"function_id": minhash.function_id}, set_command)
        self._addMinHashToBands(minhash)
        return True

    def addMinHashes(self, minhashes: List["MinHash"]) -> None:
        # TODO can this be removed
        if not minhashes:
            return
        function_updates = []
        for minhash in minhashes:
            set_command = {
                "$set": {"minhash": minhash.getMinHash().hex(), "minhash_shingle_composition": minhash.getComposition()}
            }
            # TODO what happens if one of the function_ids is not found or minhash.function_id is not set?
            function_updates.append(UpdateOne({"function_id": minhash.function_id}, set_command))
        self._database.functions.bulk_write(function_updates, ordered=False)
        self._addMinHashesToBands(minhashes)

    # original implementation, already working
    def _addMinHashToBands(self, minhash: "MinHash") -> None:
        # reuse multi-insert function
        self._addMinHashesToBands([minhash])

    def _addMinHashesToBands(self, minhashes: List["MinHash"]) -> None:
        band_hashes = {number: {} for number in range(self._config.STORAGE_NUM_BANDS)}
        for minhash in minhashes:
            for band_number, band_hash in self.getBandHashesForMinHash(minhash).items():
                if band_hash not in band_hashes[band_number]:
                    band_hashes[band_number][band_hash] = []
                band_hashes[band_number][band_hash].append(minhash.function_id)
        self._updateBands(band_hashes)

    # original implementation, already working
    def _updateBands(self, band_hashes: Dict[int, Dict[int, List[int]]]) -> None:
        num_band_updates = 0
        for band_number, band_data in band_hashes.items():
            band_updates = []
            for band_hash, function_ids in band_data.items():
                if len(function_ids) >= 1:
                    push_command = {"$push": {"function_ids": {"$each": function_ids}}}
                band_updates.append(UpdateOne({"band_hash": band_hash}, push_command, upsert=True))
            self._database["band_%d" % band_number].bulk_write(band_updates, ordered=False)
            num_band_updates += len(band_updates)

    # COPIED FROM MEMORYSTORAGE
    # TODO optimize or move to interface
    def getCandidatesForMinHashes(self, function_id_to_minhash: Dict[int, "MinHash"]) -> Dict[int, Set[int]]:
        candidates = {}
        for function_id, minhash in function_id_to_minhash.items():
            candidates[function_id] = self.getCandidatesForMinHash(minhash)
        return candidates

    def getCandidatesForMinHash(self, minhash: "MinHash") -> Set[int]:
        candidates = set([])
        band_hashes = self.getBandHashesForMinHash(minhash)
        for band_number, band_hash in sorted(band_hashes.items()):
            band_hash_query = {"band_hash": band_hash}
            band_document = self._database["band_%d" % band_number].find_one(band_hash_query)
            if band_document:
                candidates.update(band_document["function_ids"])
        return candidates

    # TODO return type
    def _getCacheDataForFunctionIds(self, function_ids: List[int]):
        cache_data = {}
        sample_ids = {}
        minhashs = {}
        # TODO why is list necessary here?
        for function_document in self._database.functions.find(
            {"function_id": {"$in": list(function_ids)}}, {"_id": 0}
        ):
            self._decodeFunction(function_document)
            entry = FunctionEntry.fromDict(function_document)
            minhashs[entry.function_id] = entry.minhash
            sample_ids[entry.function_id] = entry.sample_id
        cache_data["func_id_to_minhash"] = minhashs
        cache_data["func_id_to_sample_id"] = sample_ids
        return cache_data

    def deleteXcfgForSampleId(self, sample_id: int) -> None:
        self._database.functions.update_many({"sample_id": sample_id}, {"$set": {"_xcfg": "{}"}})

    def deleteXcfgData(self) -> None:
        self._database.functions.update_many({}, {"$set": {"_xcfg": "{}"}})

    # TODO move to storage interface, remove this from memory storage?
    def getLibraryInfoForSampleId(self, sample_id: int) -> Optional[Dict[str, str]]:
        sample_entry = self.getSampleById(sample_id)
        if sample_entry is None:
            return None
        if sample_entry.is_library:
            return {"family": sample_entry.family, "version": sample_entry.version}
        return None

    def isPicHash(self, pichash: int) -> bool:
        query = {"pichash": pichash}
        self._encodePichash(query)
        return self._database.functions.find_one(query) is not None

    def getMatchesForPicHash(self, pichash: int) -> Set[Tuple[int, int]]:
        query = {"pichash": pichash}
        self._encodePichash(query)
        return set(
            map(
                lambda x: (x["sample_id"], x["function_id"]),
                list(self._database.functions.find(query, {"function_id": 1, "sample_id": 1, "_id": 0})),
            )
        )

    ########################## 'old' implementations below

    def _addFunction(
        self, sample_entry: "SampleEntry", smda_function: "SmdaFunction", minhash: Optional["MinHash"] = None
    ) -> "FunctionEntry":
        function_id = self._useCounter("functions")
        function_entry = FunctionEntry(sample_entry, smda_function, function_id, minhash=minhash)
        # calculate block hashes and add separately
        image_lower = sample_entry.base_addr
        image_upper = image_lower + sample_entry.binary_size
        function_entry.picblockhashes = self.blockhasher.getBlockhashesForFunction(smda_function, image_lower, image_upper, hash_size=8)
        # convert for persistance
        function_dict = function_entry.toDict()
        self._encodeFunction(function_dict)
        self._dbInsert("functions", function_dict)
        if minhash and minhash.hasMinHash():
            minhash.function_id = function_entry.function_id
            self._addMinHashToBands(minhash)
        return function_entry

    def createMatchingCache(self, function_ids: List[int]) -> MatchingCache:
        cache_data = self._getCacheDataForFunctionIds(function_ids)
        # TODO dont store this as attribute
        self._matching_cache = MatchingCache(cache_data)
        return self._matching_cache

    def clearMatchingCache(self) -> None:
        self._matching_cache = None

    def getFamilyId(self, family_name: str) -> Optional[int]:
        family_document = self._database.families.find_one({"family_name": family_name})
        if family_document is None:
            return None
        return family_document["family_id"]

    def getFamilyIds(self) -> List[int]:
        return self._database.families.find().distinct("family_id")

    def addFamily(self, family_name: str) -> int:
        family_document = self._database.families.find_one({"family_name": family_name})
        if family_document is not None:
            return family_document["family_id"]
        family_id = self._useCounter("families")
        self._dbInsert("families", {"family_name": family_name, "family_id": family_id})
        return family_id

    def getFamily(self, family_id: int) -> Optional[str]:
        family_document = self._database.families.find_one({"family_id": family_id})
        if family_document is None:
            return None
        return family_document["family_name"]

    def getFunctionById(self, function_id: int) -> Optional["FunctionEntry"]:
        function_document = self._database.functions.find_one({"function_id": function_id}, {"_id": 0})
        if not function_document:
            return None
        self._decodeFunction(function_document)
        return FunctionEntry.fromDict(function_document)

    def getSampleById(self, sample_id: int) -> Optional["SampleEntry"]:
        sample_document = self._database.samples.find_one({"sample_id": sample_id}, {"_id": 0})
        if not sample_document:
            return None
        return SampleEntry.fromDict(sample_document)

    # TODO add types
    def getStats(self) -> Dict:
        band_info = {}
        for band_id in range(self._config.STORAGE_NUM_BANDS):
            band_info[band_id] = self._database["band_%d" % band_id].count_documents(filter={})
        # we will have to work around using .aggregate(), as a collection with unique pic hashes will easily exceed 16M
        # https://stackoverflow.com/questions/20348093/mongodb-aggregation-how-to-get-total-records-count
        num_unique_pichashes = 0
        for result in self._database["functions"].aggregate([{"$group": {"_id": "$_pichash"}}, {"$count": "Total" }]):
            num_unique_pichashes = result["Total"]
        stats = {
            "num_families": self._database.families.count_documents(filter={}),
            "num_samples": self._database.samples.count_documents(filter={}),
            "num_functions": self._database.functions.count_documents(filter={}),
            "bands": band_info,
            "num_pichashes": num_unique_pichashes,
            "num_matches": self._database.matches.count_documents(filter={}),
        }
        return stats

    def getUnhashedFunctions(self, function_ids: Optional[List[int]] = None) -> List["FunctionEntry"]:
        unhashed_functions = []
        search_query = {}
        if function_ids is not None:
            search_query = {"function_id": {"$in": list(function_ids)}}
        for function_document in self._database.functions.find(search_query, {"_id": 0}):
            self._decodeFunction(function_document)
            if not function_document["minhash"]:
                unhashed_functions.append(FunctionEntry.fromDict(function_document))
        return unhashed_functions

    def findFamilyByString(self, needle: str, max_num_results: int = 100) -> Dict[int, str]:
        result_dict = {}
        for family_document in self._database.families.find():
            if needle in family_document["family_name"]:
                result_dict[family_document["family_id"]] = family_document["family_name"]
            if len(result_dict) > max_num_results:
                break
        return result_dict

    def findSampleByString(self, needle: str, max_num_results: int = 100) -> Dict[int, "SampleEntry"]:
        result_dict = {}
        for sample_document in self._database.samples.find():
            entry = SampleEntry.fromDict(sample_document)
            if needle in entry.filename:
                result_dict[entry.sample_id] = entry
            elif len(needle) >= 3 and needle in entry.sha256:
                result_dict[entry.sample_id] = entry
            elif needle in entry.family:
                result_dict[entry.sample_id] = entry
            elif needle in entry.component:
                result_dict[entry.sample_id] = entry
            elif needle in entry.version:
                result_dict[entry.sample_id] = entry
            if len(result_dict) > max_num_results:
                break
        return result_dict

    def findFunctionByString(self, needle: str, max_num_results: int = 100) -> Dict[int, "FunctionEntry"]:
        result_dict = {}
        for function_document in self._database.functions.find():
            self._decodeFunction(function_document)
            entry = FunctionEntry.fromDict(function_document)
            if needle in entry.function_name:
                result_dict[entry.function_id] = entry
        # TODO also search through function labels once we have implemented them
            if len(result_dict) > max_num_results:
                break
        return result_dict
