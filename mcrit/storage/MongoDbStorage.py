import re
import uuid
import json
import logging
import datetime
import traceback
from packaging import version
from operator import itemgetter
from itertools import zip_longest
from collections import defaultdict
from typing import Any, TYPE_CHECKING, Dict, Iterable, List, Optional, Set, Tuple, Union

LOGGER = logging.getLogger(__name__)
try:
    from pymongo import InsertOne, MongoClient, UpdateOne
    from pymongo.collection import ReturnDocument
    from gridfs import GridFS
except:
    LOGGER.warning("pymongo package import failed - MongoDB backend will not be available.")

from picblocks.blockhasher import BlockHasher
from smda.SmdaConfig import SmdaConfig
from smda.common.BinaryInfo import BinaryInfo
from smda.common.SmdaFunction import SmdaFunction

from mcrit.index.SearchCursor import FullSearchCursor
from mcrit.index.SearchQueryTree import AndNode, BaseVisitor, FilterSingleElementLists, NodeType, NotNode, OrNode, PropagateNot, SearchConditionNode, SearchFieldResolver, SearchTermNode
from mcrit.libs.utility import generate_unique_groups, encode_two_complement, decode_two_complement
from mcrit.minhash.MinHash import MinHash
from mcrit.storage.FamilyEntry import FamilyEntry
from mcrit.storage.FunctionEntry import FunctionEntry
from mcrit.storage.FunctionLabelEntry import FunctionLabelEntry
from mcrit.storage.MatchingCache import MatchingCache
from mcrit.storage.SampleEntry import SampleEntry
from mcrit.storage.StorageInterface import StorageInterface

if TYPE_CHECKING: # pragma: no cover
    from mcrit.config.StorageConfig import StorageConfig
    from mcrit.storage.MemoryStorage import MemoryStorage
    from pymongo.database import Database
    from smda.common.SmdaFunction import SmdaFunction
    from smda.common.SmdaReport import SmdaReport


class MongoSearchTranspiler(BaseVisitor):
    """
    Converts a tree to a MongoDB query.
    The input tree MUST NOT contain Not or SearchTerm nodes.
    """
    @staticmethod
    def _or_query(*conditions):
        if len(conditions) == 0:
            return {}
        if len(conditions) == 1:
            return conditions[0]
        return {"$or": conditions}

    @staticmethod
    def _and_query(*conditions):
        if len(conditions) == 0:
            return {}
        if len(conditions) == 1:
            return conditions[0]
        return {"$and": conditions}

    def visitAndNode(self, node: AndNode):
        visited_children = [self.visit(child) for child in node.children]
        return self._and_query(*visited_children)

    def visitOrNode(self, node: OrNode):
        visited_children = [self.visit(child) for child in node.children]
        return self._or_query(*visited_children)

    def visitSearchConditionNode(self, node:SearchConditionNode):
        operator_to_mongo = {
            "<": "$lt",
            "<=": "$lte",
            ">": "$gt",
            ">=": "$gte",
            "=": None,
            "": None,
            "!=": "$ne",
            "?": None,
            "!?": "$not",
        }
        value = node.value
        if node.operator.endswith("?"):
            value = re.compile(re.escape(node.value), re.IGNORECASE)
        elif node.field in ("pichash", "offset") or node.field.endswith("_id") or "num_" in node.field:
            try:
                value = int(value, 0)
            except Exception:
                pass
        mongo_operator = operator_to_mongo[node.operator]
        if mongo_operator is None:
            condition = {node.field: value}
        else:
            condition = {node.field: {mongo_operator: value}}
        # TODO: fix
        MongoDbStorage._encodePichash(None, condition)
        return condition



class MongoDbStorage(StorageInterface):

    _DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

    _database: "Database"
    _matching_cache: Optional[MatchingCache]

    def __init__(self, config: "StorageConfig") -> None:
        super().__init__(config)  # sets config
        self._matching_cache = None
        self.blockhasher = BlockHasher()
        self._database = None
        self.fs = None
        
    def _getDb(self):
        # because of gunicorn and forking workers, we want to delay creation of MongoClient until actual usage and avoid it within __init__()
        if self._database is None:
            self._initDb(self._storage_config.STORAGE_SERVER, 
                         self._storage_config.STORAGE_PORT, 
                         self._storage_config.STORAGE_MONGODB_DBNAME, 
                         self._storage_config.STORAGE_MONGODB_USERNAME, 
                         self._storage_config.STORAGE_MONGODB_PASSWORD, 
                         self._storage_config.STORAGE_MONGODB_FLAGS)
        return self._database

    def _initDb(self, server, port, db_name, username="", password="", flags=""):
        userpw_url = f"{username}:{password}@" if username and len(username) > 0 and password and len(password) > 0 else ""
        port_url = f":{port}" if port and len(port) > 0 else ""
        flags_url = f"?{flags}" if flags and len(flags) > 0 else ""

        mongo_uri = f"mongodb://{userpw_url}{server}{port_url}/{db_name}{flags_url}"

        self._database = MongoClient(mongo_uri, connect=False)[db_name]
        self.fs = GridFS(self._database)
        self._ensureIndexAndUnknownFamily()

    def _ensureIndexAndUnknownFamily(self) -> None:
        if "settings" not in self._getDb().list_collection_names():
            self._getDb()["settings"].insert_one({"mcrit_db_id": str(uuid.uuid4()), "db_state": 0})
        self._getDb()["samples"].create_index("sample_id")
        self._getDb()["families"].create_index("family_id")
        self._getDb()["functions"].create_index("function_id")
        self._getDb()["functions"].create_index("sample_id")
        self._getDb()["functions"].create_index("_pichash")
        self._getDb()["functions"].create_index("_picblockhashes.hash")
        self._getDb()["functions"].create_index("_picblockhashes.offset")
        # stored without guarantee of existence
        self._getDb()["query_samples"].create_index("sample_id")
        self._getDb()["query_functions"].create_index("function_id")
        self._getDb()["query_functions"].create_index("sample_id")
        # ensure that their counters are at least 1, so that they never contain items with sample_id/function_id 0
        self._getDb().counters.find_one_and_update(
            filter={"name": "query_samples", "value": 0}, 
            update={"$inc": {"value": 1}}, 
            upsert=True
        )
        self._getDb().counters.find_one_and_update(
            filter={"name": "query_functions", "value": 0}, 
            update={"$inc": {"value": 1}}, 
            upsert=True
        )
        self._getDb()["matches"].create_index("match_id")
        self._getDb()["candidates"].create_index("function_id")
        self._getDb()["counters"].create_index("name")
        self._getDb()["logs"].create_index("username")
        for band_id in range(self._storage_config.STORAGE_NUM_BANDS):
            self._getDb()["band_%d" % band_id].create_index("band_hash")
        # Add Family "" if it is not already in storage
        if self.getFamily(0) is None:
            self.addFamily("")
        assert self.getFamily(0).family_name == ""

    ###############################################################################
    # Generic database functionality and logging
    ###############################################################################

    def _getCurrentTimestamp(self) -> datetime.datetime:
        return datetime.datetime.utcnow()

    def _convertTimestampToString(self, timestamp) -> str:
        return datetime.datetime.fromtimestamp(timestamp).strftime(self._DATETIME_FORMAT)

    def _convertDatetimeToString(self, dt: datetime.datetime) -> str:
        if isinstance(dt, datetime.datetime):
            return dt.strftime(self._DATETIME_FORMAT)

    def _convertStringToDatetime(self, date_string: str) -> datetime.datetime:
        if isinstance(date_string, str):
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
            insert_result = self._getDb()[collection].insert_one(self._toBinary(data))
            if insert_result.acknowledged:
                return insert_result.inserted_id
            return None
        except Exception as exc:
            self._dbLogError(
                'Database insert for collection "%s" failed.' % collection,
                details={"traceback": traceback.format_exc().split("\n")},
            )
            raise ValueError("Database insert failed.")

    def _dbInsertMany(self, collection: str, data: List["Dict"]):
        if len(data) == 0:
            return []
        try:
            insert_result = self._getDb()[collection].insert_many([self._toBinary(document) for document in data])
            if insert_result.acknowledged:
                return insert_result.inserted_ids
            return None
        except Exception as exc:
            self._dbLogError(
                'Database insert_many for collection "%s" failed.' % collection,
                details={"traceback": traceback.format_exc().split("\n")},
            )
            raise ValueError("Database insert failed.")

    def _dbQuery(self, collection: str, query: Dict, find_one: bool = False):
        try:
            if find_one:
                return self._getDb()[collection].find_one(query)
            else:
                return self._getDb()[collection].find(query)
        except Exception as exc:
            self._dbLogError(
                'Database query for collection "%s" failed.' % collection,
                details={"traceback": traceback.format_exc().split("\n")},
            )
            raise ValueError("Database query failed.")

    def dbLogEvent(self, event_msg, username=None, details=None):
        if details is None:
            details = {}
        self._dbLog("event", event_msg, username, details)

    def _dbLogError(self, error_msg, username=None, details=None):
        if details is None:
            details = {}
        self._dbLog("error", error_msg, username, details)

    def _dbLog(self, log_type, log_msg, log_username, log_details):
        if log_username is None:
            log_username = "mcrit/internal"
        record = {"ts": self._getCurrentTimestamp(), "%s_msg" % log_type: log_msg, "username": log_username, "%s_details" % log_type: log_details}
        self._getDb()[log_type].insert_one(self._toBinary(record))

    def _useCounterBulk(self, name: str, num_counts: int) -> Iterable[int]:
        assert num_counts >= 0
        if num_counts == 0:
            return []
        query_result = self._getDb().counters.find_one_and_update(
            filter={"name": name}, 
            update={"$inc": {"value": num_counts}}, 
            upsert=True
        )
        first_count = 0
        if query_result is not None:
            first_count = query_result["value"]
        return range(first_count, first_count+num_counts)
    
    def _useCounter(self, name:str) -> int:
        return next(iter(self._useCounterBulk(name, 1)))

    def _updateDbState(self):
        result = self._getDb().settings.find_one_and_update({}, { "$inc": { "db_state": 1}})
        result = self._getDb().settings.find_one_and_update({}, { "$set": {"db_timestamp": self._getCurrentTimestamp()}}, upsert=True)
        if result is None:
            raise Exception("Database does not have a db_state field")
        else:
            return result["db_state"]

    def _getDbState(self):
        result = self._getDb().settings.find_one({})
        if result is None:
            raise Exception("Database does not have a state field yet")
        elif "db_state" in result:
            return result["db_state"]
        
    def _getDbTimestamp(self):
        result = self._getDb().settings.find_one({})
        if result is None:
            raise Exception("Database does not have a state field yet")
        elif "db_timestamp" in result:
            return result["db_timestamp"]
        
    def updateDbCleanupTimestamp(self):
        result = self._getDb().settings.find_one_and_update({}, { "$inc": { "db_state": 1}})
        result = self._getDb().settings.find_one_and_update({}, { "$set": {"db_cleanup_timestamp": self._getCurrentTimestamp()}}, upsert=True)
        if result is None:
            raise Exception("Database does not have a db_state field")
        else:
            return result["db_cleanup_timestamp"]
    
    def getDbCleanupTimestamp(self):
        result = self._getDb().settings.find_one({})
        if result is None:
            raise Exception("Database does not have a state field yet")
        elif "db_cleanup_timestamp" in result:
            return result["db_cleanup_timestamp"]

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
            for entry in function_dict["picblockhashes"]:
                converted_entry = dict(**entry)
                converted_entry["hash"] = hex(converted_entry["hash"])
                # use two-complement to convert unit64 to int64 and vice versa
                converted_entry["offset"] = encode_two_complement(converted_entry["offset"])
                converted_entries.append(converted_entry)
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
            for entry in function_dict["_picblockhashes"]:
                converted_entry = dict(**entry)
                converted_entry["hash"] = int(converted_entry["hash"], 16)
                # use two-complement to convert unit64 to int64 and vice versa
                converted_entry["offset"] = decode_two_complement(converted_entry["offset"])
                converted_entries.append(converted_entry)
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
        if function_id < 0:
            function_document = self._getDb().query_functions.find_one({"function_id": function_id})
        else:
            function_document = self._getDb().functions.find_one({"function_id": function_id})
        if function_document is None:
            return None
        return function_document["sample_id"]

    def deleteSample(self, sample_id: int) -> bool:
        sample_entry = self.getSampleById(sample_id)
        if sample_entry is None:
            return False
        # Delete from GridFS if applicable
        if sample_entry.gridfs_id and self.fs:
            try:
                self.fs.delete(sample_entry.gridfs_id)
            except Exception as e:
                LOGGER.error(f"Failed to delete from GridFS (id: {sample_entry.gridfs_id}): {e}")
        if sample_id < 0:
            # remove functions
            self._getDb().query_functions.delete_many({"sample_id": sample_id})
            # remove sample
            self._getDb().query_samples.delete_one({"sample_id": sample_id})
            return 
        function_entries = self.getFunctionsBySampleId(sample_id)
        if function_entries is None:
            # in this case sample_id is does not exist
            return False

        # collect all band entries that need updating and pull all function_ids at once.
        # might need to batch this into slices of function_ids again
        minhashes_to_remove = {band_number: {} for band_number in range(self._storage_config.STORAGE_NUM_BANDS)}
        for function_entry in function_entries:
            minhash = function_entry.getMinHash(minhash_bits=self._minhash_config.MINHASH_SIGNATURE_BITS)
            # remove minhash entries, if necessary
            if not minhash or not minhash.hasMinHash():
                continue
            band_hashes = self.getBandHashesForMinHash(minhash)
            for band_number, band_hash in sorted(band_hashes.items()):
                if band_hash not in minhashes_to_remove[band_number]:
                    minhashes_to_remove[band_number][band_hash] = []
                if function_entry.function_id not in minhashes_to_remove[band_number][band_hash]:
                    minhashes_to_remove[band_number][band_hash].append(function_entry.function_id)
        self._updateBands(minhashes_to_remove, method="pull")

        # update family stats
        self._updateFamilyStats(sample_entry.family_id, -1, -sample_entry.statistics["num_functions"], -int(sample_entry.is_library))
        # remove functions
        self._getDb().functions.delete_many({"sample_id": sample_id})
        # remove sample
        self._getDb().samples.delete_one({"sample_id": sample_id})
        # delete family if empty
        family_info = self.getFamily(sample_entry.family_id)
        if family_info.num_samples == 0 and family_info.family_id != 0:
            self._getDb().families.delete_one({"family_id": family_info.family_id})
        self._updateDbState()
        return True

    def _updateFamilyStats(self, family_id, num_samples_inc, num_functions_inc, num_library_samples_inc):
        self._getDb().families.update_one(
            {"family_id": family_id},
            {
                "$inc": {
                    "num_samples": num_samples_inc,
                    "num_functions": num_functions_inc,
                    "num_library_samples": num_library_samples_inc,
                },
            }
        )

    def modifySample(self, sample_id: int, update_information: dict) -> bool:
        if not self.isSampleId(sample_id):
            return False
        sample_entry = self.getSampleById(sample_id)
        if "is_library" in update_information:
            is_library_info_changed = sample_entry.is_library != update_information["is_library"]
            self._getDb().samples.update_one({"sample_id": sample_id}, {"$set": {"is_library": update_information["is_library"]}})
            family_entry = self.getFamily(sample_entry.family_id)
            if is_library_info_changed:
                new_value = family_entry.num_library_samples + (1 if update_information["is_library"] else -1)
                self._getDb().families.update_one({"family_id": sample_entry.family_id}, {"$set": {"num_library_samples": new_value}})
        if "family_name" in update_information:
            old_family_entry = self.getFamily(sample_entry.family_id)
            family_name = update_information["family_name"]
            family_id = self.addFamily(family_name)
            new_family_entry = self.getFamily(family_id)
            # update sample_entry and function_entries with new family information
            self._getDb().samples.update_one({"sample_id": sample_id}, {"$set": {"family_id": family_id, "family": family_name}})
            self._getDb().functions.update_many({"sample_id": sample_id}, {"$set": {"family_id": family_id}})
            # update family entry with statistics
            self._getDb().families.update_one(
                {"family_id": old_family_entry.family_id}, 
                {"$set": {
                    "num_samples": old_family_entry.num_samples - 1,
                    "num_functions": old_family_entry.num_functions - sample_entry.statistics["num_functions"],
                    "num_library_samples": old_family_entry.num_library_samples - (1 if sample_entry.is_library else 0),
                    }
                }
            )
            self._getDb().families.update_one(
                {"family_id": family_id}, 
                {"$set": {
                    "num_samples": new_family_entry.num_samples + 1,
                    "num_functions": new_family_entry.num_functions + sample_entry.statistics["num_functions"],
                    "num_library_samples": new_family_entry.num_library_samples + (1 if sample_entry.is_library else 0),
                    }
                }
            )
            old_family_entry = self.getFamily(sample_entry.family_id)
            # delete family if empty
            if old_family_entry.num_samples == 0 and old_family_entry.family_id != 0:
                self._getDb().families.delete_one({"family_id": old_family_entry.family_id})
            self._updateDbState()
        if "version" in update_information:
            self._getDb().samples.update_one({"sample_id": sample_id}, {"$set": {"version": update_information["version"]}})
        if "component" in update_information:
            self._getDb().samples.update_one({"sample_id": sample_id}, {"$set": {"component": update_information["component"]}})
        return True

    def modifyFamily(self, family_id: int, update_information: dict) -> bool:
        if not self.isFamilyId(family_id):
            return False
        old_family_info = self.getFamily(family_id)
        if "is_library" in update_information:
            self._getDb().samples.update_many({"family_id": family_id}, {"$set": {"is_library": update_information["is_library"]}})
            updated_count = old_family_info.num_samples if update_information["is_library"] else 0
            self._getDb().families.update_one({"family_id": family_id}, {"$set": {"num_library_samples": updated_count}})
            self._updateDbState()
        if "family_name" in update_information:
            old_family_info = self.getFamily(family_id)
            family_name = update_information["family_name"]
            new_family_id = self.addFamily(family_name)
            new_family_info = self.getFamily(new_family_id)
            new_num_samples = new_family_info.num_samples + old_family_info.num_samples
            new_num_functions = new_family_info.num_functions + old_family_info.num_functions
            new_num_lib_samples = new_family_info.num_library_samples + old_family_info.num_library_samples
            # update family_entry
            if family_id == 0:
                self._getDb().families.update_one({"family_id": 0}, {"$set": {"num_samples": 0, "num_functions": 0, "num_library_samples": 0}})
            else:
                self._getDb().families.delete_one({"family_id": family_id})
            self._getDb().families.update_one({"family_id": new_family_id}, {"$set": {"num_samples": new_num_samples, "num_functions": new_num_functions, "num_library_samples": new_num_lib_samples}})
            # update sample_entry and function_entries with new family information
            self._getDb().samples.update_many({"family_id": family_id}, {"$set": {"family_id": new_family_id, "family": family_name}})
            self._getDb().functions.update_many({"family_id": family_id}, {"$set": {"family_id": new_family_id}})
            self._updateDbState()
        return True

    def deleteFamily(self, family_id: int, keep_samples: Optional[str] = False) -> bool:
        family_entry = self.getFamily(family_id)
        if family_entry is None:
            return False
        sample_entries = self.getSamplesByFamilyId(family_id)
        if keep_samples:
            self._getDb().samples.update_many({"family_id": family_id}, {"$set": {"family_id": 0, "family": ""}})
            self._getDb().functions.update_many({"family_id": family_id}, {"$set": {"family_id": 0}})
            self._updateFamilyStats(0, family_entry.num_samples, family_entry.num_functions, family_entry.num_library_samples)
        else:
            for sample_entry in sample_entries:
                self.deleteSample(sample_entry.sample_id)
        # ensure we always have family_id 0 as empty family.
        if family_id == 0:
            self._getDb().families.update_one({"family_id": 0}, {"$set": {"num_samples": 0, "num_functions": 0, "num_library_samples": 0}})
        else:
            self._getDb().families.delete_one({"family_id": family_id})
        self._updateDbState()
        return True

    def getSamplesByFamilyId(self, family_id: int) -> Optional[List["SampleEntry"]]:
        if self.getFamily(family_id) is None:
            return None
        samples = self._getDb().samples.find({"family_id": family_id}, {"_id":0})
        return [SampleEntry.fromDict(sample_document) for sample_document in samples]

    def getSamples(self, start_index: int, limit: int, is_query=False) -> Optional["SampleEntry"]:
        sample_entries = []
        if is_query:
            for sample_document in self._getDb().query_samples.find().skip(start_index).limit(limit):
                sample_entries.append(SampleEntry.fromDict(sample_document))
        else:
            for sample_document in self._getDb().samples.find().skip(start_index).limit(limit):
                sample_entries.append(SampleEntry.fromDict(sample_document))
        return sample_entries

    def clearStorage(self) -> None:
        collections = ["samples", "families", "functions", "matches", "candidates", "counters", "query_samples", "query_functions"]
        for band_id in range(self._storage_config.STORAGE_NUM_BANDS):
            collections.append("band_%d" % band_id)
        for c in collections:
            self._getDb()[c].drop()
        self._ensureIndexAndUnknownFamily()

    def getSampleBySha256(self, sha256: str, is_query=False) -> Optional["SampleEntry"]:
        target_sample = None
        if is_query:
            if self._getDb().query_samples.count_documents(filter={}):
                report_dict = self._getDb().query_samples.find_one({"sha256": sha256})
                if report_dict:
                    target_sample = SampleEntry.fromDict(report_dict)
                    # Note: Query samples are not expected to have GridFS data currently
        else:
            if self._getDb().samples.count_documents(filter={}):
                report_dict = self._getDb().samples.find_one({"sha256": sha256})
                if report_dict:
                    target_sample = SampleEntry.fromDict(report_dict)
                    if target_sample and target_sample.gridfs_id and self.fs:
                        try:
                            gridfs_file = self.fs.get(target_sample.gridfs_id)
                            target_sample.binary_data = gridfs_file.read()
                        except Exception as e:
                            LOGGER.error(f"Failed to retrieve from GridFS (id: {target_sample.gridfs_id}): {e}")
                            target_sample.binary_data = None # Ensure it's None if retrieval fails
        return target_sample

    def updateFunctionLabels(self, smda_report: "SmdaReport", username) -> Optional["SampleEntry"]:
        sample_entry = self.getSampleBySha256(smda_report.sha256)
        if not sample_entry:
            return False
        # check which functions in the SmdaReport have suitable function_names
        submitted_labels = {}
        for smda_function in smda_report.getFunctions():
            function_name = smda_function.function_name
            if function_name and not re.match("sub_[a-fA-F0-9]{1,16}", function_name):
                # use two-complement to convert unit64 to int64 and vice versa
                offset = encode_two_complement(smda_function.offset)
                submitted_labels[offset] = function_name
        # get the respective FunctionEntries and check if the label is novel
        sample_function_entries = {entry.offset: entry for entry in self.getFunctionsBySampleId(sample_entry.sample_id)}
        label_updates = []
        for label_offset, extracted_label in submitted_labels.items():
            is_new_label = False
            # we can only ever update labels if their offset exists in our DB
            if label_offset in sample_function_entries:
                is_new_label = True
                existing_labels = sample_function_entries[label_offset].function_labels
                for existing_label in existing_labels:
                    if existing_label.username == username and existing_label.function_label == extracted_label:
                        is_new_label = False
            # match by function_id or offset and add the label if it had not existed before.
            if is_new_label:
                new_function_entry_label = FunctionLabelEntry(extracted_label, username)
                update_command = {"$push": {"function_labels": new_function_entry_label.toDict()}}
                label_updates.append(UpdateOne({"function_id": sample_function_entries[label_offset].function_id}, update_command, upsert=True))
        if label_updates:
            self._getDb().functions.bulk_write(label_updates, ordered=False)

    def addSmdaReport(self, smda_report: "SmdaReport", isQuery=False) -> Optional["SampleEntry"]:
        sample_entry = None
        if isQuery:
            sample_entry = SampleEntry(
                smda_report, sample_id=-1 * self._useCounter("query_samples"), family_id=0
            )
            self._dbInsert("query_samples", sample_entry.toDict())
            function_ids = self._useCounterBulk("query_functions",  smda_report.num_functions)
            function_dicts = []
            for function_id, smda_function in zip(function_ids, smda_report.getFunctions()):
                function_dicts.append(self._getFunctionDocument(sample_entry, smda_function, -1 * function_id))
            self._dbInsertMany("query_functions", function_dicts)
        else:
            if not self.getSampleBySha256(smda_report.sha256):
                family_id = self.addFamily(smda_report.family)
                sample_entry = SampleEntry(
                    smda_report, sample_id=self._useCounter("samples"), family_id=family_id
                )
                # Store binary in GridFS
                binary_data = smda_report.buffer # Assuming smda_report.buffer contains the binary
                gridfs_id = self.fs.put(binary_data, filename=smda_report.sha256, sha256=smda_report.sha256)
                sample_entry.gridfs_id = str(gridfs_id)
                self._dbInsert("samples", sample_entry.toDict())
                function_ids = self._useCounterBulk("functions",  smda_report.num_functions)
                function_dicts = []
                for function_id, smda_function in zip(function_ids, smda_report.getFunctions()):
                    function_dicts.append(self._getFunctionDocument(sample_entry, smda_function, function_id))
                self._dbInsertMany("functions", function_dicts)
                self._updateFamilyStats(family_id, +1, sample_entry.statistics["num_functions"], int(sample_entry.is_library))
                self._updateDbState()
            else:
                LOGGER.warning("Sample %s already existed, skipping.", smda_report.sha256)
        return sample_entry

    def importSampleEntry(self, sample_entry: "SampleEntry") -> Optional["SampleEntry"]:
        if not self.getSampleBySha256(sample_entry.sha256):
            sample_id = self._useCounter("samples")
            sample_entry.sample_id = sample_id
            self._dbInsert("samples", sample_entry.toDict())
            self._updateFamilyStats(sample_entry.family_id, +1, sample_entry.statistics["num_functions"], int(sample_entry.is_library))
            self._updateDbState()
        else:
            LOGGER.warning("Sample %s already existed, skipping.", sample_entry.sha256)
        return sample_entry

    def importFunctionEntry(self, function_entry: "FunctionEntry") -> Optional["FunctionEntry"]:
        function_entry.function_id = self._useCounter("functions")
        if function_entry.function_name and len(function_entry.function_labels) == 0:
            new_function_entry_label = FunctionLabelEntry(function_entry.function_name, "mcrit-import")
            function_entry.function_labels.append(new_function_entry_label)
        # add function to regular storage
        function_dict = function_entry.toDict()
        self._encodeFunction(function_dict)
        self._dbInsert("functions", function_dict)
        return function_entry

    def importFunctionEntries(self, function_entries: List["FunctionEntry"]) -> Optional[List["FunctionEntry"]]:
        functions_as_dicts = []
        function_ids = self._useCounterBulk("functions", len(function_entries))
        for function_id, function_entry in zip(function_ids, function_entries):
            function_entry.function_id = function_id
            if function_entry.function_name and len(function_entry.function_labels) == 0:
                new_function_entry_label = FunctionLabelEntry(function_entry.function_name, "mcrit-import")
                function_entry.function_labels.append(new_function_entry_label)
            # add function to regular storage
            function_dict = function_entry.toDict()
            self._encodeFunction(function_dict)
            functions_as_dicts.append(function_dict)
        self._dbInsertMany("functions", functions_as_dicts)
        return function_entries

    def getFunctionsBySampleId(self, sample_id: int) -> Optional[List["FunctionEntry"]]:
        if not self.isSampleId(sample_id):
            return None
        if sample_id < 0:
            function_dicts = list(self._getDb().query_functions.find({"sample_id": sample_id}, {"_id": 0}))
        else:
            function_dicts = list(self._getDb().functions.find({"sample_id": sample_id}, {"_id": 0}))
        functions = []
        for f in function_dicts:
            self._decodeFunction(f)
            functions.append(FunctionEntry.fromDict(f))
        return functions

    def getFunctionIdsBySampleId(self, sample_id: int) -> Optional[List["FunctionEntry"]]:
        function_ids = None
        if not self.isSampleId(sample_id):
            return function_ids
        function_ids = []
        if sample_id < 0:
            function_dicts = list(self._getDb().query_functions.find({"sample_id": sample_id}, {"_id": 0, "function_id": 1}))
        else:
            function_dicts = list(self._getDb().functions.find({"sample_id": sample_id}, {"_id": 0, "function_id": 1}))
        for f in function_dicts:
            function_ids(f["function_ids"])
        return function_ids

    def getFunctions(self, start_index: int, limit: int) -> Optional["FunctionEntry"]:
        functions = []
        for function_document in self._getDb().functions.find().skip(start_index).limit(limit):
            self._decodeFunction(function_document)
            functions.append(FunctionEntry.fromDict(function_document))
        return functions

    def getSampleIds(self) -> List[int]:
        return self._getDb().samples.find().distinct("sample_id")

    def isSampleId(self, sample_id: int) -> bool:
        is_sample_id = None
        if sample_id < 0:
            is_sample_id = bool(self._getDb().query_samples.find_one({"sample_id": sample_id}))
        else:
            is_sample_id = bool(self._getDb().samples.find_one({"sample_id": sample_id}))
        return is_sample_id

    def getPicHashMatchesBySampleId(self, sample_id: int) -> Optional[Dict[int, Set[Tuple[int, int]]]]:
        if not self.isSampleId(sample_id):
            return None
        function_ids = list(
            map(
                itemgetter("function_id"),
                list(self._getDb().functions.find({"sample_id": sample_id}, {"function_id": 1, "_id": 0})),
            )
        )  # ["function_id"]
        return self.getPicHashMatchesByFunctionIds(function_ids)

    def getPicHashMatchesByFunctionId(self, function_id: int) -> Optional[Dict[int, Set[Tuple[int, int, int]]]]:
        query_result = self._getDb().functions.find_one({"function_id": function_id}, {"_id": 0, "_pichash": 1})
        if query_result is None or not "_pichash" in query_result:
            return None
        self._decodePichash(query_result, delete_old=False)
        encoded_pichash = query_result["_pichash"]
        decoded_pichash = query_result["pichash"]
        if decoded_pichash is None:
            return None

        sample_and_function_ids = set(
            map(
                lambda x: (x["family_id"], x["sample_id"], x["function_id"]),
                list(self._getDb().functions.find({"_pichash": encoded_pichash}, {"family_id": 1, "sample_id": 1, "function_id":1, "_id": 0})),
            )
        )

        return {decoded_pichash: sample_and_function_ids}

    def getPicHashMatchesByFunctionIds(self, function_ids: List[int]) -> Dict[int, Set[Tuple[int, int, int]]]:
        # internal format!
        pichash_raw = self._getDb().functions.find({"function_id": {"$in": function_ids}}, {"_pichash": 1, "_id": 0})
        pichashes_list = list(pichash_raw)  # broken? TODO
        pichashes = {}
        fields_to_fetch =  {"family_id": 1, "sample_id": 1, "function_id":1, "_id": 0}
        for pichash in pichashes_list:
            # TODO what happens if pichash does not exist??
            self._decodePichash(pichash, delete_old=False)
            encoded_pichash = pichash["_pichash"]
            decoded_pichash = pichash["pichash"]
            if decoded_pichash in pichashes:
                continue
            pichashes[decoded_pichash] = set(
                map(
                    lambda x: (x["family_id"], x["sample_id"], x["function_id"]),
                    list(self._getDb().functions.find({"_pichash": encoded_pichash}, fields_to_fetch)),
                )
            )
        return pichashes

    def isFunctionId(self, function_id: int) -> bool:
        is_function_id = None
        if function_id < 0:
            is_function_id = bool(self._getDb().query_functions.find_one({"function_id": function_id}))
        else:
            is_function_id = bool(self._getDb().functions.find_one({"function_id": function_id}))
        return is_function_id

    def isFamilyId(self, family_id: int) -> bool:
        return bool(self._getDb().families.find_one({"family_id": family_id}))

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
        self._getDb().functions.find_one_and_update({"function_id": minhash.function_id}, set_command)
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
        self._getDb().functions.bulk_write(function_updates, ordered=False)
        self._addMinHashesToBands(minhashes)

    # original implementation, already working
    def _addMinHashToBands(self, minhash: "MinHash") -> None:
        # reuse multi-insert function
        self._addMinHashesToBands([minhash])

    def _addMinHashesToBands(self, minhashes: List["MinHash"]) -> None:
        band_hashes = {number: {} for number in range(self._storage_config.STORAGE_NUM_BANDS)}
        for minhash in minhashes:
            if minhash.hasMinHash():
                for band_number, band_hash in self.getBandHashesForMinHash(minhash).items():
                    if band_hash not in band_hashes[band_number]:
                        band_hashes[band_number][band_hash] = []
                    band_hashes[band_number][band_hash].append(minhash.function_id)
        self._updateBands(band_hashes)

    def _updateBands(self, band_hashes: Dict[int, Dict[int, List[int]]], method="push") -> None:
        if method not in ["push", "pull"]:
            raise ValueError(f"MongoDbStorage._updateBands() can only do 'push' and 'pull', not '{method}'.")
        num_band_updates = 0
        for band_number, band_data in band_hashes.items():
            band_updates = []
            for band_hash, function_ids in band_data.items():
                update_command = None
                if len(function_ids) >= 1:
                    if method == "push":
                        update_command = {"$push": {"function_ids": {"$each": function_ids}}}
                    else:
                        update_command = {"$pull": {"function_ids": {"$in": function_ids}}}
                band_updates.append(UpdateOne({"band_hash": band_hash}, update_command, upsert=True))
            if band_updates:
                self._getDb()["band_%d" % band_number].bulk_write(band_updates, ordered=False)
            num_band_updates += len(band_updates)
        return num_band_updates

    def getCandidatesForMinHashes(self, function_id_to_minhash: Dict[int, "MinHash"], band_matches_required=1) -> Dict[int, Set[int]]:
        candidates = {}
        target_band_hashes_per_band = {band_number: set() for band_number in range(self._storage_config.STORAGE_NUM_BANDS)}
        band_hash_to_function_ids = {band_number: {} for band_number in range(self._storage_config.STORAGE_NUM_BANDS)}
        for function_id, minhash in function_id_to_minhash.items():
            if not minhash.hasMinHash():
                continue
            band_hashes = self.getBandHashesForMinHash(minhash)
            for band_number, band_hash in sorted(band_hashes.items()):
                target_band_hashes_per_band[band_number].add(band_hash)
                if band_hash not in band_hash_to_function_ids[band_number]:
                    band_hash_to_function_ids[band_number][band_hash] = set()
                band_hash_to_function_ids[band_number][band_hash].add(function_id)
        for band_number, band_hashes in target_band_hashes_per_band.items():
            match_query = {"$match": {"band_hash": {"$in": list(band_hashes)}}}
            cursor = self._getDb()["band_%d" % band_number].aggregate([match_query])
            for hit in cursor:
                reference_function_ids = band_hash_to_function_ids[band_number][hit["band_hash"]]
                for function_id in reference_function_ids:
                    if function_id not in candidates:
                        candidates[function_id] = {}
                    for hit_function_id in hit["function_ids"]:
                        if hit_function_id not in candidates[function_id]:
                            candidates[function_id][hit_function_id] = 0
                        candidates[function_id][hit_function_id] += 1
        # reduce candidates based on banding requirements
        valid_candidates = {}
        for function_id, hit_counters in candidates.items():
            for other_id, count in hit_counters.items():
                if count >= band_matches_required:
                    if function_id not in valid_candidates:
                        valid_candidates[function_id] = set()
                    valid_candidates[function_id].add(other_id)
        return valid_candidates

    def getCandidatesForMinHash(self, minhash: "MinHash", band_matches_required=1) -> Set[int]:
        if not minhash.hasMinHash():
            return
        candidates = {}
        band_hashes = self.getBandHashesForMinHash(minhash)
        for band_number, band_hash in sorted(band_hashes.items()):
            band_hash_query = {"band_hash": band_hash}
            band_document = self._getDb()["band_%d" % band_number].find_one(band_hash_query)
            if band_document:
                for function_id in band_document["function_ids"]:
                    if function_id not in candidates:
                        candidates[function_id] = 0
                    candidates[function_id] += 1
        # reduce candidates based on banding requirements
        valid_candidates = set([])
        for function_id, hit_count in candidates.items():
            if hit_count >= band_matches_required:
                valid_candidates.add(function_id)
        return valid_candidates

    def _getCacheDataForFunctionIds(self, function_ids: List[int]) -> Dict:
        cache_data = {}
        sample_ids = {}
        sample_to_func_ids = {}
        minhashes = {}
        # process this in batches as the number of function_ids can be exceedingly large, pushing beyond Mongo's 16M limit
        for sliced_ids in zip_longest(*[iter(function_ids)]*500000):
            query_function_ids = [fid for fid in sliced_ids if fid is not None]
            for function_document in self._getDb().functions.find(
                {"function_id": {"$in": list(query_function_ids)}}, {"_id": 0, "sample_id": 1, "minhash": 1, "function_id": 1}
            ):
                function_id = function_document["function_id"]
                sample_id = function_document["sample_id"]
                minhash = bytes.fromhex(function_document["minhash"])
                minhashes[function_id] = minhash
                sample_ids[function_id] = sample_id
                if sample_id not in sample_to_func_ids:
                    sample_to_func_ids[sample_id] = set()
                sample_to_func_ids[sample_id].add(function_id)
        cache_data["func_id_to_minhash"] = minhashes
        cache_data["func_id_to_sample_id"] = sample_ids
        cache_data["sample_id_to_func_ids"] = sample_to_func_ids
        return cache_data

    def deleteXcfgForSampleId(self, sample_id: int) -> None:
        self._getDb().functions.update_many({"sample_id": sample_id}, {"$set": {"_xcfg": "{}"}})

    def deleteXcfgData(self) -> None:
        self._getDb().functions.update_many({}, {"$set": {"_xcfg": "{}"}})

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
        return self._getDb().functions.find_one(query) is not None

    def getMatchesForPicHash(self, pichash: int) -> Set[Tuple[int, int, int]]:
        query = {"pichash": pichash}
        self._encodePichash(query)
        return set(
            map(
                lambda x: (x["family_id"], x["sample_id"], x["function_id"]),
                list(self._getDb().functions.find(query, {"family_id": 1, "function_id": 1, "sample_id": 1, "_id": 0})),
            )
        )

    def getMatchesForPicBlockHash(self, picblockhash: int) -> Set[Tuple[int, int, int, int]]:
        query = {"_picblockhashes.hash": hex(picblockhash)}
        result = self._getDb().functions.aggregate([
            {"$match": query}, 
            {"$unwind": "$_picblockhashes"}, 
            {"$match": query}, 
            {"$project": {"_id": 0, "function_id": 1, "family_id": 1, "sample_id": 1, "offset": "$_picblockhashes.offset"}}])
        return set(
            map(
                # use two-complement to convert unit64 to int64 and vice versa
                lambda x: (x["family_id"], x["sample_id"], x["function_id"], decode_two_complement(x["offset"])),
                result,
            )
        )

    ########################## 'old' implementations below

    def _getFunctionDocument(
        self, sample_entry: "SampleEntry", smda_function: "SmdaFunction", function_id: int) -> Dict:
        """
        Converts a SmdaFunction to a dict ready for insertion into MongoDb.
        Picblockhashes will be added to the function.
        The function_id has to be explicitly provided.
        """
        function_entry = FunctionEntry(sample_entry, smda_function, function_id)
        # calculate block hashes and add separately
        image_lower = sample_entry.base_addr
        image_upper = image_lower + sample_entry.binary_size
        picblockhashes = []
        for hash_entry in self.blockhasher.getBlockhashesForFunction(smda_function, image_lower, image_upper, hash_size=8):
            for block_entry in hash_entry["offset_tuples"]:
                block_entry["hash"] = hash_entry["hash"]
                picblockhashes.append(block_entry)
        function_entry.picblockhashes = picblockhashes
        # convert for persistance
        function_dict = function_entry.toDict()
        self._encodeFunction(function_dict)
        return function_dict

    def createMatchingCache(self, function_ids: List[int]) -> MatchingCache:
        cache_data = self._getCacheDataForFunctionIds(function_ids)
        # TODO dont store this as attribute
        self._matching_cache = MatchingCache(cache_data)
        return self._matching_cache

    def clearMatchingCache(self) -> None:
        self._matching_cache = None

    def getFamilyId(self, family_name: str) -> Optional[int]:
        family_document = self._getDb().families.find_one({"family_name": family_name})
        if family_document is None:
            return None
        return family_document["family_id"]

    def getFamilyIds(self) -> List[int]:
        return self._getDb().families.find().distinct("family_id")

    def addFamily(self, family_name: str) -> int:
        family_document = self._getDb().families.find_one({"family_name": family_name})
        if family_document is not None:
            return family_document["family_id"]
        family_id = self._useCounter("families")
        family_entry = FamilyEntry(family_name=family_name, family_id=family_id)
        self._dbInsert("families", family_entry.toDict())
        self._updateDbState()
        return family_id

    def getFamily(self, family_id: int) -> Optional[FamilyEntry]:
        family_document = self._getDb().families.find_one({"family_id": family_id})
        if family_document is None:
            return None
        return FamilyEntry.fromDict(family_document)

    def getFunctionById(self, function_id: int, with_xcfg=False) -> Optional["FunctionEntry"]:
        field_selection = {"_id": 0}
        if not with_xcfg:
            field_selection["_xcfg"] = 0
        if function_id < 0:
            function_document = self._getDb().query_functions.find_one({"function_id": function_id}, field_selection)
        else:
            function_document = self._getDb().functions.find_one({"function_id": function_id}, field_selection)
        if not function_document:
            return None
        self._decodeFunction(function_document)
        return FunctionEntry.fromDict(function_document)

    def getSampleById(self, sample_id: int) -> Optional["SampleEntry"]:
        if sample_id < 0:
            sample_document = self._getDb().query_samples.find_one({"sample_id": sample_id}, {"_id": 0})
        else:
            sample_document = self._getDb().samples.find_one({"sample_id": sample_id}, {"_id": 0})
        if not sample_document:
            return None
        sample_entry = SampleEntry.fromDict(sample_document)
        if sample_entry and sample_entry.gridfs_id and self.fs and sample_id >= 0: # only for non-query samples
            try:
                gridfs_file = self.fs.get(sample_entry.gridfs_id)
                sample_entry.binary_data = gridfs_file.read()
            except Exception as e:
                LOGGER.error(f"Failed to retrieve from GridFS (id: {sample_entry.gridfs_id}): {e}")
                sample_entry.binary_data = None # Ensure it's None if retrieval fails
        return sample_entry

    # TODO add types
    def getStats(self, with_pichash=True) -> Dict:
        # we will have to work around using .aggregate(), as a collection with unique pic hashes will easily exceed 16M
        # https://stackoverflow.com/questions/20348093/mongodb-aggregation-how-to-get-total-records-count
        num_unique_pichashes = 0
        if with_pichash:
            for result in self._getDb().functions.aggregate([{"$group": {"_id": "$_pichash"}}, {"$count": "Total" }]):
                num_unique_pichashes = result["Total"]
        # use family statistics to derive relevant values
        stats = {
            "db_state": self._getDbState(),
            "db_timestamp": self._convertDatetimeToString(self._getDbTimestamp()),
            "num_families": 0,
            "num_samples": 0,
            "num_query_samples": self._getDb().query_samples.estimated_document_count(),
            "num_query_functions": self._getDb().query_functions.estimated_document_count(),
            "num_functions": 0,
            "num_bands": self._storage_config.STORAGE_NUM_BANDS,
            "num_pichashes": num_unique_pichashes,
        }
        for family_document in self._getDb().families.find():
            stats["num_families"] += 1
            stats["num_samples"] += family_document["num_samples"]
            stats["num_functions"] += family_document["num_functions"]
        return stats

    def getUnhashedFunctions(self, function_ids: Optional[List[int]] = None, only_function_ids=False) -> List["FunctionEntry"]:
        unhashed_functions = []
        search_query = {}
        if function_ids is not None:
            search_query = {"function_id": {"$in": list(function_ids)}}
        for function_document in self._getDb().functions.find(search_query, {"_id": 0}):
            if function_document["minhash"] == "":
                if only_function_ids:
                    unhashed_functions.append(function_document["function_id"])
                else:
                    self._decodeFunction(function_document)
                    unhashed_functions.append(FunctionEntry.fromDict(function_document))
        return unhashed_functions
    
    def rebuildMinhashBandIndex(self, progress_reporter=None):
        # drop band collections
        # recreate collections and their indices
        collections = []
        for band_id in range(self._storage_config.STORAGE_NUM_BANDS):
            collections.append("band_%d" % band_id)
        for c in collections:
            self._getDb()[c].drop()
            col = self._getDb()[c]
            self._getDb()[c].create_index("band_hash")
        # re-add minhashes in batches
        total_functions = self._getDb().functions.count_documents(filter={})
        minhash_functions = 0
        batch_size = self._minhash_config.MINHASH_BAND_REBUILD_WORK_PACKAGE_SIZE
        if progress_reporter:
            progress_reporter.set_total((total_functions // batch_size) + 1)
        for start_index in range(0, total_functions, batch_size):
            minhashes = []
            for function_document in self._getDb().functions.find({}, {"function_id": 1, "minhash": 1, "_id": 0}).skip(start_index).limit(batch_size):
                if function_document["minhash"]:
                    function_id = function_document["function_id"]
                    minhash_bytes = bytes.fromhex(function_document["minhash"])
                    minhash_obj = MinHash(function_id, minhash_bytes, minhash_bits=self._minhash_config.MINHASH_SIGNATURE_BITS)
                    minhashes.append(minhash_obj)
            self._addMinHashesToBands(minhashes)
            minhash_functions += len(minhashes)
            if progress_reporter:
                progress_reporter.step()
        return {"minhash_functions_indexed": minhash_functions}
    
    def deleteAllMinHashes(self, progress_reporter=None):
        # delete all minhashes
        self._getDb().functions.update_many({}, {"$set": {"minhash": ""}})
        # reset bands
        collections = []
        for band_id in range(self._storage_config.STORAGE_NUM_BANDS):
            collections.append("band_%d" % band_id)
        for c in collections:
            self._getDb()[c].drop()
            col = self._getDb()[c]
            self._getDb()[c].create_index("band_hash")
        LOGGER.info("Dropped all Minhashes and created a fresh banding index.")
        return
    
    def recalculateAllPicHashes(self, progress_reporter=None):
        # get current SMDA version
        smda_config = SmdaConfig()
        smda_version = smda_config.VERSION
        smda_downward_compatibility = getattr(smda_config, "ESCAPER_DOWNWARD_COMPATIBILITY", None)
        if smda_downward_compatibility is None:
            LOGGER.warn("SMDA downward compatibility version unknown, using current SMDA version as threshold...")
            smda_downward_compatibility = smda_version
        compatibility_threshold = version.parse(smda_downward_compatibility)
        # get samples where recalculation is necessary
        samples_to_be_updated = {}
        for sample_document in self._getDb().samples.find({}, {"sample_id": 1, "smda_version": 1, "architecture": 1, "base_addr": 1, "binary_size": 1, "bitness": 1, "_id": 0}):
            report_version = sample_document["smda_version"]
            if report_version.startswith("MCRIT4IDA"):
                report_version = report_version.rsplit(" ", 1)[-1]
            if version.parse(report_version) < compatibility_threshold:
                samples_to_be_updated[sample_document["sample_id"]] = sample_document
        # reprocess functions on a per sample level
        total_samples = len(samples_to_be_updated)
        if progress_reporter:
            progress_reporter.set_total((total_samples))
        functions_updatable = 0
        functions_updated = 0
        picblockhashes_updatable = 0
        picblockhashes_updated = 0
        xcfg_missing = 0
        for sample_id, sample_info in samples_to_be_updated.items():
            pic_hash_updates = []
            for function_document in self._getDb().functions.find({"sample_id": sample_id}, {"function_id": 1, "_pichash": 1, "_picblockhashes": 1, "_xcfg": 1, "_id": 0}):
                update_document = {}
                functions_updatable += 1
                # create all relevant objects
                binary_info = BinaryInfo(b"")
                binary_info.architecture = sample_info["architecture"]
                binary_info.base_addr = sample_info["base_addr"]
                binary_info.binary_size = sample_info["binary_size"]
                binary_info.bitness = sample_info["bitness"]
                if "_xcfg" not in function_document or not function_document["_xcfg"]:
                    xcfg_missing += 1
                    continue
                smda_xcfg = json.loads(function_document["_xcfg"])
                old_pichash = int(function_document["_pichash"], 16)
                old_blockhashes = []
                if "_picblockhashes" in function_document:
                    for blockhash in function_document["_picblockhashes"]:
                        blockhash["hash"] = int(blockhash["hash"], 16)
                        old_blockhashes.append(blockhash)
                    picblockhashes_updatable += len(old_blockhashes)
                smda_function = SmdaFunction.fromDict(smda_xcfg, binary_info=binary_info)
                new_pichash = smda_function.getPicHash(binary_info)
                if old_pichash != new_pichash:
                    functions_updated += 1
                    update_document["pichash"] = new_pichash
                # check if any blockhashes changed and possibly stage for update
                picblockhashes = []
                for hash_entry in self.blockhasher.getBlockhashesForFunction(smda_function, binary_info.base_addr, binary_info.base_addr + binary_info.binary_size, hash_size=8):
                    for block_entry in hash_entry["offset_tuples"]:
                        block_entry["hash"] = hash_entry["hash"]
                        picblockhashes.append(block_entry)
                set_old = set([(pbh['offset'],pbh["hash"])  for pbh in old_blockhashes])
                set_new = set([(pbh['offset'],pbh["hash"]) for pbh in picblockhashes])
                if len(set_new) != len(set_old.intersection(set_new)):
                    picblockhashes_updated += len(picblockhashes)
                    update_document["picblockhashes"] = picblockhashes
                # prepare single function entry update
                if update_document:
                    self._encodePichash(update_document)
                    update_command = {"$set": update_document}
                    pic_hash_updates.append(UpdateOne({"function_id": function_document["function_id"]}, update_command, upsert=True))
            # batch insert updates for function_entries
            if pic_hash_updates:
                self._getDb().samples.update_one({"sample_id": sample_id}, {"$set": {"smda_version": smda_version}})
                self._getDb().functions.bulk_write(pic_hash_updates, ordered=False)
            if progress_reporter:
                progress_reporter.step()
        self._getDb().command("reIndex", "functions")
        LOGGER.info(f"Found {total_samples} outdated samples, {functions_updated}/{functions_updatable} PicHashes and {picblockhashes_updated}/{picblockhashes_updatable} PicBlockHashes were updated.")
        if xcfg_missing:
            LOGGER.warn(f"{xcfg_missing} functions could not be updated as there was not CFG available.")
        return {"outdated_samples": total_samples, "functions_updatable": functions_updatable, "functions_updated": functions_updated, "picblockhashes_updatable": picblockhashes_updatable, "picblockhashes_updated": picblockhashes_updated, "xcfg_missing": xcfg_missing}

    def getUniqueBlocks(self, sample_ids: Optional[List[int]] = None, progress_reporter=None) -> Dict:
        # query once to get all blocks from the functions of our samples
        block_statistics = {
            "by_sample_id": {
                sample_id: {
                    "sample_id": sample_id,
                    "total_blocks": 0,
                    "characteristic_blocks": 0,
                    "unique_blocks": 0
                } for sample_id in sample_ids
            },
            "unique_blocks_overall": 0,
            "num_samples": len(sample_ids)
        }
        candidate_picblockhashes = {}
        for entry in self._getDb().functions.find({"sample_id": {"$in": sample_ids}, "_picblockhashes": {"$exists": True, "$ne": [] }}, {"function_id": 1, "sample_id": 1, "_picblockhashes": 1, "_id": 0}):
            sample_id = entry["sample_id"]
            for block_entry in entry["_picblockhashes"]:
                block_hash = block_entry["hash"]
                if block_hash not in candidate_picblockhashes:
                    candidate_picblockhashes[block_hash] = {
                        "samples": set(),
                        "length": block_entry["length"],
                        "function_id": entry["function_id"],
                        "sample_id": sample_id,
                        "offset": decode_two_complement(block_entry["offset"]),
                        "instructions": [],
                        "escaped_sequence": "",
                        "score": 0
                    }
                candidate_picblockhashes[block_hash]["samples"].add(sample_id)
        # update statistics based on candidates
        for picblockhash, entry in candidate_picblockhashes.items():
            for sample_id in entry["samples"]:
                block_statistics["by_sample_id"][sample_id]["total_blocks"] += 1
        LOGGER.info(f"Found {len(candidate_picblockhashes)} candidate picblock hashes")
        if progress_reporter is not None:
            progress_reporter.set_total(self._getDb().functions.count_documents(filter={}))
        # remove those that are not unique
        for entry in self._getDb().functions.find({"_picblockhashes": {"$exists": True, "$ne": [] }}, {"sample_id": 1, "_picblockhashes": 1, "_id": 0}):
            if progress_reporter is not None:
                progress_reporter.step()
            sample_id = entry["sample_id"]
            if sample_id not in sample_ids:
                for block_entry in entry["_picblockhashes"]:
                    candidate_picblockhashes.pop(block_entry["hash"], None)
        # update statistics again after having reduced to results
        for picblockhash, entry in candidate_picblockhashes.items():
            if len(entry["samples"]) == 1:
                single_sample_id = list(entry["samples"])[0]
                block_statistics["by_sample_id"][single_sample_id]["unique_blocks"] += 1
            for sample_id in entry["samples"]:
                block_statistics["by_sample_id"][sample_id]["characteristic_blocks"] += 1
        block_statistics["unique_blocks_overall"] = len(candidate_picblockhashes)
        LOGGER.info(f"Reduced to {len(candidate_picblockhashes)} unique picblock hashes")
        # we are basically finished when we reached this step, so set progress to 100%
        if progress_reporter is not None:
            progress_reporter.set_total(1)
            progress_reporter.step()
        # iterate over candidates by function_id and extract instructions
        function_id_to_block_offsets = {}
        for picblockhash, entry in candidate_picblockhashes.items():
            candidate_picblockhashes[picblockhash]["samples"] = sorted(list(entry["samples"]))
            # we calculate the score for this block as 80% of how well it covers the samples and 20% how far its size is away from an "ideal" signature block
            sample_score = 100.0 * len(entry["samples"]) / len(sample_ids)
            length_score = 100.0
            if entry["length"] < 7:
                length_score = 100.0 - (100.0 * (7 - entry["length"]) / 7)
            elif entry["length"] > 10:
                length_score = 100.0 * (1 / (entry["length"] - 10))
            candidate_picblockhashes[picblockhash]["score"] = 0.8 * sample_score + 0.2 * length_score
            if entry["function_id"] not in function_id_to_block_offsets:
                function_id_to_block_offsets[entry["function_id"]] = []
            function_id_to_block_offsets[entry["function_id"]].append((entry["offset"], picblockhash))
        for entry in self._getDb().functions.find({"function_id": {"$in": list(function_id_to_block_offsets.keys())}}, {"function_id": 1, "_xcfg": 1, "_id": 0}):
            function_id = entry["function_id"]
            self._decodeXcfg(entry)
            for block_offset, picblockhash in function_id_to_block_offsets[function_id]:
                candidate_picblockhashes[picblockhash]["instructions"] = entry["xcfg"]["blocks"][str(block_offset)]
        LOGGER.info(f"Instructions for {len(candidate_picblockhashes)} blocks extracted.")
        return {"statistics": block_statistics, "unique_blocks": candidate_picblockhashes}


    ##### helpers for search ######

    @staticmethod
    def _get_sort_list_from_cursor(full_cursor: Optional[FullSearchCursor]):
        if full_cursor is None:
            return None
        is_backward_search = not full_cursor.is_forward_search
        sort_list = [(key, 1 if direction ^ is_backward_search else -1) for key, direction in full_cursor.sort_by_list]
        return sort_list


    def _get_search_query(self, search_fields:List[str], search_tree: NodeType, cursor: Optional[FullSearchCursor], conditional_search_fields=None):
        if cursor is not None:
            full_tree = AndNode([search_tree, cursor.toTree()])
        else:
            full_tree = search_tree
        full_tree = SearchFieldResolver(search_fields, conditional_search_fields=conditional_search_fields).visit(full_tree)
        full_tree = FilterSingleElementLists().visit(full_tree)
        full_tree = PropagateNot().visit(full_tree)
        query = MongoSearchTranspiler().visit(full_tree)
        return query

    ##### search ####

    def findFamilyByString(self, search_tree: NodeType, cursor: Optional[FullSearchCursor] = None, max_num_results: int = 100) -> Dict[int, "FamilyEntry"]:
        result_dict = {}
        search_fields = ["family_name"]
        query = self._get_search_query(search_fields, search_tree, cursor)
        sort_list = self._get_sort_list_from_cursor(cursor)
        for family_document in self._getDb().families.find(query, {"_id":0}, sort=sort_list, limit=max_num_results):
            entry = FamilyEntry.fromDict(family_document)
            result_dict[family_document["family_id"]] = entry
        return result_dict

    def findSampleByString(self, search_tree: NodeType, cursor: Optional[FullSearchCursor] = None, max_num_results: int = 100) -> Dict[int, "SampleEntry"]:
        result_dict = {}
        search_fields = ["filename", "family", "component", "version",]
        conditional_field = ("sha256", lambda search_term: len(search_term)>=3)
        query = self._get_search_query(search_fields, search_tree, cursor, conditional_search_fields=[conditional_field])
        sort_list = self._get_sort_list_from_cursor(cursor)
        for sample_document in self._getDb().samples.find(query, {"_id":0}, sort=sort_list, limit=max_num_results):
            entry = SampleEntry.fromDict(sample_document)
            result_dict[entry.sample_id] = entry
        return result_dict

    def findFunctionByString(self, search_tree: NodeType, cursor: Optional[FullSearchCursor] = None, max_num_results: int = 100) -> Dict[int, "FunctionEntry"]:
        result_dict = {}
        # TODO also search through function labels once we have implemented them
        search_fields = ["function_name"]
        query = self._get_search_query(search_fields, search_tree, cursor)
        sort_list = self._get_sort_list_from_cursor(cursor)
        for function_document in self._getDb().functions.find(query, {"_id":0, "_xcfg":0}, sort=sort_list, limit=max_num_results):
            self._decodeFunction(function_document)
            entry = FunctionEntry.fromDict(function_document)
            result_dict[entry.function_id] = entry
        return result_dict

    def cleanup_orphan_gridfs_objects(self) -> int:
        """
        Finds and deletes orphan GridFS objects that are no longer referenced by any SampleEntry.
        Returns the number of deleted orphan objects.
        """
        if not self.fs:
            LOGGER.error("GridFS not initialized. Cannot cleanup orphans.")
            return 0

        db = self._getDb()
        if db is None:
            LOGGER.error("Database not initialized. Cannot cleanup orphans.")
            return 0

        orphan_count = 0
        try:
            # Ensure fs.files exists before trying to find()
            if "fs.files" not in db.list_collection_names():
                LOGGER.info("No GridFS files collection found (fs.files). Nothing to cleanup.")
                return 0

            gridfs_files_cursor = self.fs.find()
            for grid_file in gridfs_files_cursor:
                file_id_str = str(grid_file._id)
                # Check if any sample references this gridfs_id
                # Use count_documents for efficiency
                count = db.samples.count_documents({"gridfs_id": file_id_str})
                if count == 0:
                    try:
                        self.fs.delete(grid_file._id)
                        orphan_count += 1
                        LOGGER.info(f"Deleted orphan GridFS file: {file_id_str} (filename: {grid_file.filename if hasattr(grid_file, 'filename') else 'N/A'})")
                    except Exception as e:
                        LOGGER.error(f"Error deleting GridFS file {file_id_str}: {e}")

            if orphan_count > 0:
                LOGGER.info(f"Successfully deleted {orphan_count} orphan GridFS objects.")
            else:
                LOGGER.info("No orphan GridFS objects found to delete.")

        except Exception as e:
            LOGGER.error(f"An error occurred during GridFS orphan cleanup: {e}", exc_info=True)
            return -1 # Indicate error

        return orphan_count
