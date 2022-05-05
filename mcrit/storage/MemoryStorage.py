import logging
from collections import defaultdict
from copy import deepcopy
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple, Union

from picblocks.blockhasher import BlockHasher

from mcrit.storage.FunctionEntry import FunctionEntry
from mcrit.storage.SampleEntry import SampleEntry
from mcrit.storage.StorageInterface import StorageInterface

if TYPE_CHECKING: # pragma: no cover
    from mcrit.config.StorageConfig import StorageConfig
    from mcrit.minhash.MinHash import MinHash
    from mcrit.storage.MatchingCache import MatchingCache
    from smda.common.SmdaFunction import SmdaFunction
    from smda.common.SmdaReport import SmdaReport

LOGGER = logging.getLogger(__name__)


class MemoryStorage(StorageInterface):
    _families: Dict[int, str]
    _samples: Dict[int, "SampleEntry"]
    _functions: Dict[int, "FunctionEntry"]
    _pichashes: Dict[int, Set[Tuple[int, int]]]
    # Dict[band_number, Dict[?, List[function_id]]]
    _bands: Dict[int, Dict[int, List[int]]]
    _counters: Dict[str, int]
    _sample_by_sha256: Dict[str, int]
    _sample_id_to_function_ids: Dict[int, List[int]]

    def __init__(self, config: "StorageConfig") -> None:
        super().__init__(config)  # sets config
        self._setupEmptyStorage()
        self.blockhasher = BlockHasher()

    def clearStorage(self) -> None:
        self._setupEmptyStorage()

    def _setupEmptyStorage(self) -> None:
        self._families = {}
        self._samples = {}
        self._functions = {}
        self._pichashes = {}
        self._bands = {band_number: {} for band_number in range(self._config.STORAGE_NUM_BANDS)}
        self._counters = defaultdict(lambda: 0)
        # caches
        self._sample_by_sha256 = {}
        self._sample_id_to_function_ids = defaultdict(list)
        unknown_family_id = self.addFamily("")
        assert unknown_family_id == 0

    def _useCounter(self, name: str) -> int:
        result = self._counters[name]
        self._counters[name] += 1
        return result

    # TODO check if this works
    def deleteSample(self, sample_id: int) -> bool:
        if not self.isSampleId(sample_id):
            return False
        function_ids = self._sample_id_to_function_ids[sample_id]
        for function_id in function_ids:
            function_entry = self._functions[function_id]
            # remove function
            del self._functions[function_id]
            # remove pichash entries
            if function_entry.pichash:
                self._pichashes[function_entry.pichash].remove((sample_id, function_id))
            minhash = function_entry.getMinHash()
            # remove minhash entries, if necessary
            if not minhash:
                continue
            band_hashes = self.getBandHashesForMinHash(minhash)
            for band_number, band_hash in sorted(band_hashes.items()):
                if band_hash not in self._bands[band_number]:
                    continue
                # delete function id from bandhash
                self._bands[band_number][band_hash].remove(function_id)
                # delete bandhash if empty
                if not self._bands[band_number][band_hash]:
                    del self._bands[band_number][band_hash]
        # remove references
        del self._sample_id_to_function_ids[sample_id]
        # in case to samples with same sha256 are added and then removed, it could crash, so remove entry safely
        self._sample_by_sha256.pop(self._samples[sample_id].sha256, None)
        # remove sample
        del self._samples[sample_id]
        return True

    def addSmdaReport(self, smda_report: "SmdaReport") -> Optional["SampleEntry"]:
        sample_entry = None
        if not self.getSampleBySha256(smda_report.sha256):
            sample_entry = SampleEntry(
                smda_report, sample_id=self._useCounter("samples"), family_id=self.addFamily(smda_report.family)
            )
            self._samples[sample_entry.sample_id] = sample_entry
            self._sample_by_sha256[sample_entry.sha256] = sample_entry.sample_id
            function_ids = []
            for smda_function in smda_report.getFunctions():
                function_entry = self._addFunction(sample_entry, smda_function)
                function_ids.append(function_entry.function_id)
            self._sample_id_to_function_ids[sample_entry.sample_id] = function_ids
        else:
            LOGGER.warn("Sample %s already existed, skipping.", smda_report.sha256)
        return sample_entry

    def importSampleEntry(self, sample_entry: "SampleEntry") -> Optional["SampleEntry"]:
        if not self.getSampleBySha256(sample_entry.sha256):
            sample_id = self._useCounter("samples")
            sample_entry.sample_id = sample_id
            self._samples[sample_id] = sample_entry
            self._sample_by_sha256[sample_entry.sha256] = sample_id
        else:
            LOGGER.warn("Sample %s already existed, skipping.", sample_entry.sha256)
        return sample_entry

    def importFunctionEntry(self, function_entry: "FunctionEntry") -> Optional["FunctionEntry"]:
        function_entry.function_id = self._useCounter("functions")
        # add function to regular storage
        self._functions[function_entry.function_id] = function_entry
        if function_entry.sample_id not in self._sample_id_to_function_ids:
            self._sample_id_to_function_ids[function_entry.sample_id] = []
        self._sample_id_to_function_ids[function_entry.sample_id].append(function_entry.function_id)
        if function_entry.pichash:
            if function_entry.pichash not in self._pichashes:
                self._pichashes[function_entry.pichash] = set()
            self._pichashes[function_entry.pichash].add((function_entry.sample_id, function_entry.function_id))
        return function_entry

    # TODO return type?
    def getLibraryInfoForSampleId(self, sample_id: int) -> Optional[Dict[str, str]]:
        if sample_id not in self._samples:
            return None
        sample_entry = self._samples[sample_id]
        return {"family": sample_entry.family, "version": sample_entry.version} if sample_entry.is_library else None

    def _addFunction(
        self, sample_entry: "SampleEntry", smda_function: "SmdaFunction", minhash: Optional["MinHash"] = None
    ) -> "FunctionEntry":
        function_entry = FunctionEntry(sample_entry, smda_function, self._useCounter("functions"), minhash=minhash)
        image_lower = sample_entry.base_addr
        image_upper = image_lower + sample_entry.binary_size
        function_entry.picblockhashes = self.blockhasher.getBlockhashesForFunction(smda_function, image_lower, image_upper, hash_size=8)
        self._functions[function_entry.function_id] = function_entry
        if minhash and minhash.hasMinHash():
            minhash.function_id = function_entry.function_id
            self._addMinHashToBands(minhash)
        if function_entry.pichash:
            if function_entry.pichash not in self._pichashes:
                self._pichashes[function_entry.pichash] = set()
            self._pichashes[function_entry.pichash].add((sample_entry.sample_id, function_entry.function_id))
        return function_entry

    def addMinHash(self, minhash: "MinHash") -> bool:
        if minhash.function_id is None or minhash.function_id not in self._functions:
            return False
        self._functions[minhash.function_id].minhash = minhash.getMinHash()
        self._functions[minhash.function_id].minhash_shingle_composition = minhash.getComposition()
        self._addMinHashToBands(minhash)
        return True

    def addMinHashes(self, minhashes: List["MinHash"]) -> None:
        for minhash in minhashes:
            self.addMinHash(minhash)

    def createMatchingCache(self, function_ids: List[int]) -> "MemoryStorage":
        """We are already memory-only and won't gain anything using a cache"""
        return self

    def clearMatchingCache(self) -> None:
        """no dedicated cache - no cleanup"""
        return

    def getSampleIds(self) -> List[int]:
        # TODO is deepcopy necessary?
        return deepcopy(list(self._samples.keys()))

    def getSamplesByFamilyId(self, family_id: int) -> Optional[List[SampleEntry]]:
        if family_id not in self._families:
            return None
        return [
            self._samples[sample_id] for sample_id in self._samples if self._samples[sample_id].family_id == family_id
        ]

    def getFamilyIds(self) -> List[int]:
        # TODO is deepcopy necessary?
        return deepcopy(list(self._families.keys()))

    def isSampleId(self, sample_id: int) -> bool:
        return sample_id in self._samples

    def isFunctionId(self, function_id: int) -> bool:
        return function_id in self._functions

    def isFamilyId(self, family_id: int) -> bool:
        return family_id in self._families

    def isPicHash(self, pichash: int) -> bool:
        return pichash in self._pichashes

    def getMatchesForPicHash(self, pichash: int) -> Optional[Set[Tuple[int, int]]]:
        if pichash not in self._pichashes:
            return set()
        return deepcopy(self._pichashes[pichash])

    def getFamily(self, family_id: int) -> Optional[str]:
        if family_id in self._families:
            return deepcopy(self._families[family_id])
        return None

    def getFamilyId(self, family_name: str) -> Optional[int]:
        for fam_id, fam_name in self._families.items():
            if fam_name == family_name:
                return fam_id
        return None

    def addFamily(self, family_name: str) -> int:
        family_id = self.getFamilyId(family_name)
        if family_id is None:
            family_id = self._useCounter("families")
            self._families[family_id] = family_name
        return family_id

    def getFunctionById(self, function_id: int) -> Optional["FunctionEntry"]:
        if function_id in self._functions:
            return deepcopy(self._functions[function_id])
        return None

    # TODO does this need to be more efficient?
    def getFunctionsBySampleId(self, sample_id: int) -> Optional[List["FunctionEntry"]]:
        if sample_id in self._samples:
            function_ids = self._sample_id_to_function_ids[sample_id]
            function_entries = []
            for function_id in function_ids:
                function_entry = self._functions[function_id]
                function_entries.append(function_entry)
            # TODO is deepcopy necessary?
            return deepcopy(function_entries)
        return None

    def getFunctions(self, start_index: int, limit: int) -> Optional["FunctionEntry"]:
        index = 0
        function_entries = []
        for _, function_entry in self._functions.items():
            if index >= start_index:
                if (limit == 0) or (len(function_entries) < limit):
                    function_entries.append(function_entry)
                else:
                    break
            index += 1
        return deepcopy(function_entries)

    def getSampleById(self, sample_id: int) -> Optional["SampleEntry"]:
        if sample_id in self._samples:
            return deepcopy(self._samples[sample_id])

    def getSampleBySha256(self, sha256: str) -> Optional["SampleEntry"]:
        sample_entry = None
        if sha256 in self._sample_by_sha256:
            sample_id = self._sample_by_sha256[sha256]
            sample_entry = deepcopy(self._samples[sample_id])
        return sample_entry

    def getSampleIdByFunctionId(self, function_id: int) -> Optional[int]:
        sample_id = None
        if function_id in self._functions:
            sample_id = self._functions[function_id].sample_id
        return sample_id

    def getSamples(self, start_index: int, limit: int) -> Optional["SampleEntry"]:
        index = 0
        sample_entries = []
        for _, sample_entry in self._samples.items():
            if index >= start_index:
                if (limit == 0) or (len(sample_entries) < limit):
                    sample_entries.append(sample_entry)
                else:
                    break
            index += 1
        return deepcopy(sample_entries)

    def getPicHashMatchesByFunctionId(self, function_id: int) -> Optional[Dict[int, Set[Tuple[int, int]]]]:
        if function_id not in self._functions:
            return None
        pichash = self._functions[function_id].pichash
        if pichash is None:
            return None
        return {pichash: deepcopy(self._pichashes[pichash])}

    def getPicHashMatchesByFunctionIds(self, function_ids: List[int]) -> Dict[int, Set[Tuple[int, int]]]:
        pichashes = {}
        for function_id in function_ids:
            if function_id in self._functions:
                pichash = self._functions[function_id].pichash
                if pichash is None:
                    continue
                pichashes[pichash] = deepcopy(self._pichashes[pichash])
        return pichashes

    def getPicHashMatchesBySampleId(self, sample_id: int) -> Optional[Dict[int, Set[Tuple[int, int]]]]:
        function_entries = self.getFunctionsBySampleId(sample_id)
        if function_entries is None:
            return None
        function_ids = [fe.function_id for fe in function_entries]
        return self.getPicHashMatchesByFunctionIds(function_ids)

    def getMinHashByFunctionId(self, function_id: int) -> Optional[bytes]:
        if function_id in self._functions:
            function_entry = self._functions[function_id]
            return function_entry.minhash
        return None

    # -> Dict[function_id, Set[function_id]]
    # TODO optimize or move to interface
    def getCandidatesForMinHashes(self, function_id_to_minhash: Dict[int, "MinHash"]) -> Dict[int, Set[int]]:
        candidates = {}
        for function_id, minhash in function_id_to_minhash.items():
            candidates[function_id] = self.getCandidatesForMinHash(minhash)
        return candidates

    # -> Set[function_id]
    def getCandidatesForMinHash(self, minhash: "MinHash") -> Set[int]:
        candidates = set([])
        band_hashes = self.getBandHashesForMinHash(minhash)
        for band_number, band_hash in sorted(band_hashes.items()):
            if band_hash in self._bands[band_number]:
                candidates.update(self._bands[band_number][band_hash])
        return candidates

    def getUnhashedFunctions(self, function_ids: Optional[List[int]] = None) -> List["FunctionEntry"]:
        if function_ids is None:
            return [
                function_entry
                for _, function_entry in self._functions.items()
                if function_entry.xcfg and not function_entry.minhash
            ]
        return [
            function_entry
            for _, function_entry in self._functions.items()
            if (not function_entry.minhash and function_entry.function_id in function_ids)
        ]

    def deleteXcfgData(self) -> None:
        for function_id, function_entry in self._functions.items():
            self._functions[function_id].xcfg = {}

    def deleteXcfgForSampleId(self, sample_id: int) -> None:
        for function_id, function_entry in self._functions.items():
            if sample_id == function_entry.sample_id:
                self._functions[function_id].xcfg = {}

    # TODO dict of what?
    def getContent(self) -> Dict[str, Any]:
        content = {
            "families": self._families,
            "samples": {sample_id: sample.toDict() for sample_id, sample in self._samples.items()},
            "functions": {function_id: function.toDict() for function_id, function in self._functions.items()},
            "bands": self._bands,
        }
        return content

    # TODO dict of what?
    def setContent(self, content: Dict[str, Any]) -> None:
        self._families = {int(k): v for k, v in content["families"].items()}
        self._samples = {int(k): SampleEntry.fromDict(v) for k, v in content["samples"].items()}
        self._bands = {int(k): {int(ik): iv for ik, iv in v.items()} for k, v in content["bands"].items()}
        self._sample_by_sha256 = {sample.sha256: sample_id for sample_id, sample in self._samples.items()}
        self._sample_id_to_function_ids = defaultdict(list)
        self._pichashes = {}
        for function_id, function in content["functions"].items():
            function_id = int(function_id)
            function_entry = FunctionEntry.fromDict(function)
            self._functions[function_id] = function_entry
            self._sample_id_to_function_ids[function_entry.sample_id].append(function_id)
            if function_entry.pichash:
                if function_entry.pichash not in self._pichashes:
                    self._pichashes[function_entry.pichash] = set()
                self._pichashes[function_entry.pichash].add((function_entry.sample_id, function_entry.function_id))

    def getStats(self) -> Dict[str, Union[int, Dict[int, int]]]:
        stats = {
            "num_families": len(self._families),
            "num_samples": len(self._samples),
            "num_functions": len(self._functions),
            "bands": {k: len(v) for k, v in self._bands.items()},
            "num_pichashes": len(self._pichashes),
        }
        return stats

    def _addMinHashToBands(self, minhash: "MinHash") -> None:
        band_hashes = self.getBandHashesForMinHash(minhash)
        for band_number, band_hash in sorted(band_hashes.items()):
            if band_hash not in self._bands[band_number]:
                self._bands[band_number][band_hash] = []
            self._bands[band_number][band_hash].append(minhash.function_id)

    def findFamilyByString(self, needle: str, max_num_results: int = 100) -> Dict[int, str]:
        result_dict = {}
        self._families
        for family_id, family_name in self._families.items():
            if needle in family_name:
                result_dict[family_id] = family_name
            if len(result_dict) > max_num_results:
                break
        return result_dict

    def findSampleByString(self, needle: str, max_num_results: int = 100) -> Dict[int, "SampleEntry"]:
        result_dict = {}
        for sample_id, sample_entry in self._samples.items():
            if needle in sample_entry.filename:
                result_dict[sample_id] = sample_entry
            elif len(needle) >= 3 and needle in entry.sha256:
                result_dict[entry.sample_id] = entry
            elif needle in sample_entry.component:
                result_dict[sample_id] = sample_entry
            elif needle in sample_entry.version:
                result_dict[sample_id] = sample_entry
            if len(result_dict) > max_num_results:
                break
        return result_dict

    def findFunctionByString(self, needle: str, max_num_results: int = 100) -> Dict[int, "FunctionEntry"]:
        result_dict = {}
        for function_id, function_entry in self._functions.items():
            if needle in function_entry.function_name:
                result_dict[function_id] = function_entry
        # TODO also search through function labels once we have implemented them
            if len(result_dict) > max_num_results:
                break
        return result_dict
