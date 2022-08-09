from typing import Dict, Set, TYPE_CHECKING, Tuple
from mcrit.matchers.MatcherInterface import MatcherInterface, add_duration
from mcrit.storage.FunctionEntry import FunctionEntry
from mcrit.storage.MatchingCache import MatchingCache
from mcrit.storage.SampleEntry import SampleEntry

if TYPE_CHECKING:
    from smda.common.SmdaReport import SmdaReport

class MatcherQuery(MatcherInterface):
    def _additional_setup(self):
        self._sample_entry = None
        self._sample_id = -1
        # initialize with query object
        self._sample_to_lib_info = {-1: False}
        self._sample_to_family_id = {-1: 0}

    @add_duration
    def getMatchesForSmdaReport(self, smda_report: "SmdaReport"):
        # create temporary objects similar to the stored samples/functions
        self._sample_entry = SampleEntry(smda_report, sample_id=-1)
        self._sample_info = self._sample_entry.toDict()
        tmp_function_entries_dict = {}
        for smda_function in smda_report.getFunctions():
            function_entry = FunctionEntry(self._sample_entry, smda_function, -1 * len(tmp_function_entries_dict) - 1)
            tmp_function_entries_dict[function_entry.function_id] = function_entry

        minhashes = self._worker.calculateMinHashes(tmp_function_entries_dict.values())
        for minhash in minhashes:
            tmp_function_entries_dict[minhash.function_id].minhash = minhash.getMinHash()
            tmp_function_entries_dict[minhash.function_id].minhash_shingle_composition = minhash.getComposition()
        self._function_entries = tmp_function_entries_dict.values()

        return self._getMatchesRoutine()

    def _getPicHashMatches(self) -> Dict[int, Set[Tuple[int, int, int]]]:
        pichash_matches = {}
        for function_entry in self._function_entries:
            if function_entry.pichash and self._storage.isPicHash(function_entry.pichash):
                pichash_matches[function_entry.pichash] = self._storage.getMatchesForPicHash(function_entry.pichash)
                pichash_matches[function_entry.pichash].add((function_entry.family_id, function_entry.sample_id, function_entry.function_id))
        return pichash_matches

    def _createMatchingCache(self, function_ids):
        cache_data = {"func_id_to_minhash": {}, "func_id_to_sample_id": {}}
        for function_entry in self._function_entries:
            cache_data["func_id_to_minhash"][function_entry.function_id] = function_entry.minhash
            cache_data["func_id_to_sample_id"][function_entry.function_id] = function_entry.sample_id
        for function_id in function_ids:
            if function_id >= 0:
                function_entry = self._storage.getFunctionById(function_id)
                cache_data["func_id_to_minhash"][function_id] = function_entry.minhash
                cache_data["func_id_to_sample_id"][function_id] = function_entry.sample_id
        cache = MatchingCache(cache_data)
        return cache
