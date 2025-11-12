from typing import Dict, Set, Tuple
from mcrit.matchers.MatcherInterface import MatcherInterface, add_duration


class MatcherSample(MatcherInterface):
    def _additional_setup(self):
        self._sample_to_lib_info = {}
        self._sample_id_to_entry = {}

    @add_duration
    def getMatchesForSample(self, sample_id: int):
        self._function_entries = self._storage.getFunctionsBySampleId(sample_id)
        self._sample_id = sample_id
        sample_entry = self._storage.getSampleById(sample_id)
        self._sample_info = sample_entry.toDict()
        match_report = self._getMatchesRoutine()
        match_report["info"]["type"] = "matcher_sample"
        return match_report

    def _getPicHashMatches(self) -> Dict[int, Set[Tuple[int, int, int]]]:
        return self._storage.getPicHashMatchesBySampleId(self._sample_id)
