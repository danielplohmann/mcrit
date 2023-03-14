from random import sample
from typing import TYPE_CHECKING, Dict, List, Optional

from mcrit.storage.SampleEntry import SampleEntry
from mcrit.storage.MatchedSampleEntry import MatchedSampleEntry
from mcrit.storage.MatchedFunctionEntry import MatchedFunctionEntry
import mcrit.matchers.MatcherInterface as MatcherInterface

if TYPE_CHECKING:  # pragma: no cover
    from mcrit.storage.SampleEntry import SampleEntry

# Dataclass, post init
# constructor -> .fromSmdaFunction
# assume sample_entry, smda_function always available

class MatchingResult(object):
    reference_sample_entry: "SampleEntry"
    other_sample_entry: "SampleEntry"
    match_aggregation: Dict
    sample_matches: List["MatchedSampleEntry"]
    function_matches: List["MatchedFunctionEntry"]
    num_original_function_matches: int
    num_original_sample_matches: int
    num_original_family_matches: int
    num_original_library_matches: int
    # function_id -> [(family_id, sample_id), ...]
    library_matches: Dict
    # function_id -> {family_id_a, family_id_b, ...}
    function_id_to_family_ids_matched: Dict
    unique_family_scores_per_sample: Dict
    family_id_to_name_map: Dict
    is_family_filtered: bool
    is_sample_filtered: bool
    is_function_filtered: bool
    is_score_filtered: bool
    is_sample_count_filtered: bool
    is_family_count_filtered: bool
    is_library_filtered: bool
    is_pic_filtered: bool
    is_query: bool
    filter_values: Dict

    def __init__(self, sample_entry: "SampleEntry") -> None:
        self.reference_sample_entry = sample_entry
        self.unique_family_scores_per_sample = None
        self.family_id_to_name_map = None
        self.is_query = False
        self.filter_values = {}
        self.function_id_to_family_ids_matched = {}

    def setFilterValues(self, filter_dict):
        self.filter_values = filter_dict

    def getFilterValue(self, filter_name):
        return self.filter_values[filter_name] if filter_name in self.filter_values else 0

    def getFamilyNameByFamilyId(self, family_id):
        if self.family_id_to_name_map is None:
            self.family_id_to_name_map = {}
            for sample_match in self.sample_matches:
                self.family_id_to_name_map[sample_match.family_id] = sample_match.family
        return self.family_id_to_name_map[family_id] if family_id in self.family_id_to_name_map else ""
    
    def getFamilyIdsMatchedByFunctionId(self, function_id):
        if function_id not in self.function_id_to_family_ids_matched:
            return 0
        return self.function_id_to_family_ids_matched[function_id]

    def getFilteredSampleMatch(self):
        if not self.is_sample_filtered or not len(self.sample_matches):
            return None
        else:
            return self.sample_matches[0]

    def filterToDirectMinScore(self, min_score, nonlib=False):
        """ reduce aggregated sample matches to those with direct score of min_score or higher """
        filtered_sample_matches = []
        for sample_match in self.sample_matches:
            if nonlib:
                if sample_match.matched_percent_nonlib_score_weighted >= min_score:
                    filtered_sample_matches.append(sample_match)
            else:
                if sample_match.matched_percent_score_weighted >= min_score:
                    filtered_sample_matches.append(sample_match)
        self.sample_matches = filtered_sample_matches

    def filterToFrequencyMinScore(self, min_score, nonlib=False):
        """ reduce aggregated sample matches to those with frequency score of min_score or higher """
        filtered_sample_matches = []
        for sample_match in self.sample_matches:
            if nonlib:
                if sample_match.matched_percent_nonlib_frequency_weighted >= min_score:
                    filtered_sample_matches.append(sample_match)
            else:
                if sample_match.matched_percent_frequency_weighted >= min_score:
                    filtered_sample_matches.append(sample_match)
        self.sample_matches = filtered_sample_matches

    def filterToUniqueMatchesOnly(self):
        """ reduce aggregated sample matches to those with unique matches only """
        filtered_sample_matches = []
        for sample_match in self.sample_matches:
            unique_info = self.getUniqueFamilyMatchInfoForSample(sample_match.sample_id)
            if unique_info["unique_score"] > 0 or sample_match.is_library:
                filtered_sample_matches.append(sample_match)
        self.sample_matches = filtered_sample_matches

    def excludeOwnFamily(self):
        """ remove all sample matches with the same family_id as the reference samples"""
        filtered_sample_matches = []
        for sample_match in self.sample_matches:
            if sample_match.family_id != self.reference_sample_entry.family_id:
                filtered_sample_matches.append(sample_match)
        self.sample_matches = filtered_sample_matches

    def excludeLibraryMatches(self):
        """ reduce contained matches to those where none of the matches is with a library (transitive library identification) """
        library_matches = [matches for matches in self.library_matches.values() if matches]
        library_samples = set([match[1] for match_list in library_matches for match in match_list])
        library_matched_functions = [key for key in self.library_matches if self.library_matches[key]]
        self.sample_matches = [sample_match for sample_match in self.sample_matches if sample_match.sample_id not in library_samples]
        self.function_matches = [function_match for function_match in self.function_matches if function_match.function_id not in library_matched_functions]
        self.is_library_filtered = True

    def excludePicMatches(self):
        """ reduce contained matches to those which are not identified as quasi-identical via PIC matching """
        self.function_matches = [function_match for function_match in self.function_matches if not function_match.match_is_pichash]
        self.is_pic_filtered = True

    def filterToSampleCount(self, max_sample_count):
        """ reduce contained matches to those with a maximum of <max_sample_count> matched samples """
        matched_samples_by_function_id = {}
        for function_match in self.function_matches:
            if not function_match.function_id in matched_samples_by_function_id:
                matched_samples_by_function_id[function_match.function_id] = []
            if not function_match.matched_sample_id in matched_samples_by_function_id[function_match.function_id]:
                matched_samples_by_function_id[function_match.function_id].append(function_match.matched_family_id)
        self.function_matches = [function_match for function_match in self.function_matches if len(matched_samples_by_function_id[function_match.function_id]) <= max_sample_count]
        self.is_sample_count_filtered = True

    def filterToFamilyCount(self, max_family_count):
        """ reduce contained matches to those with a maximum of <max_family_count> matched families """
        matched_families_by_function_id = {}
        for function_match in self.function_matches:
            if not function_match.function_id in matched_families_by_function_id:
                matched_families_by_function_id[function_match.function_id] = []
            if not function_match.matched_family_id in matched_families_by_function_id[function_match.function_id]:
                matched_families_by_function_id[function_match.function_id].append(function_match.matched_family_id)
        self.function_matches = [function_match for function_match in self.function_matches if len(matched_families_by_function_id[function_match.function_id]) <= max_family_count]
        self.is_family_count_filtered = True

    def filterToFunctionScore(self, min_score=None, max_score=None):
        """ reduce contained matches to those with a minimum score of <threshold> """
        if min_score is not None:
            self.function_matches = [function_match for function_match in self.function_matches if function_match.matched_score >= min_score]
        if max_score is not None:
            self.function_matches = [function_match for function_match in self.function_matches if function_match.matched_score <= max_score]
        self.is_score_filtered = True

    def filterToFamilyId(self, family_id):
        """ reduce contained matches to chosen family_id by deleting the other sample and function matches """
        self.sample_matches = [sample_match for sample_match in self.sample_matches if sample_match.family_id == family_id]
        self.function_matches = [function_match for function_match in self.function_matches if function_match.matched_family_id == family_id]
        self.is_family_filtered = True

    def filterToSampleId(self, sample_id):
        """ reduce contained matches to chosen sample_id by deleting the other sample and function matches """
        self.sample_matches = [sample_match for sample_match in self.sample_matches if sample_match.sample_id == sample_id]
        self.function_matches = [function_match for function_match in self.function_matches if function_match.matched_sample_id == sample_id]
        self.is_sample_filtered = True

    def filterToFunctionId(self, function_id):
        """ reduce contained matches to chosen function_id by deleting the other sample and function matches """
        # self.sample_matches = [sample_match for sample_match in self.sample_matches if sample_match.sample_id == sample_id]
        self.function_matches = [function_match for function_match in self.function_matches if function_match.function_id == function_id]
        self.is_function_filtered = True

    def hasLibraryMatch(self, function_id):
        return function_id in self.library_matches and self.library_matches[function_id]

    def getBestSampleMatchesPerFamily(self, start=None, limit=None, library_only=False, malware_only=False):
        by_family = {}
        for sample_match in self.sample_matches:
            if library_only and not sample_match.is_library:
                continue
            if malware_only and sample_match.is_library:
                continue
            if sample_match.family not in by_family:
                by_family[sample_match.family] = {
                    "score": sample_match.matched_percent_frequency_weighted,
                    "report": sample_match
                }
            elif sample_match.matched_percent_frequency_weighted > by_family[sample_match.family]["score"]:
                by_family[sample_match.family]["score"] = sample_match.matched_percent_frequency_weighted
                by_family[sample_match.family]["report"] = sample_match
        result_list = []
        for family, score_entry in sorted(by_family.items(), key=lambda e: e[1]["score"], reverse=True):
            result_list.append(score_entry["report"])
        if start is not None:
            result_list = result_list[start:]
        if limit is not None:
            result_list = result_list[:limit]
        return result_list

    def getUniqueFamilyMatchInfoForSample(self, sample_id):
        if self.unique_family_scores_per_sample is None:
            self.unique_family_scores_per_sample = {entry.sample_id: {"functions_matched": 0, "bytes_matched": 0, "unique_score": 0} for entry in self.sample_matches}
            families_matched_by_function_id = {}
            samples_matched_by_function_id = {}
            weighted_bytes_per_function_id = {}
            for function_match_summary in self.function_matches:
                if function_match_summary.function_id not in families_matched_by_function_id:
                    families_matched_by_function_id[function_match_summary.function_id] = set()
                    samples_matched_by_function_id[function_match_summary.function_id] = set()
                    weighted_bytes_per_function_id[function_match_summary.function_id] = 0
                families_matched_by_function_id[function_match_summary.function_id].add(function_match_summary.matched_family_id)
                samples_matched_by_function_id[function_match_summary.function_id].add(function_match_summary.matched_sample_id)
                # matches should be weighted by match score
                weighted_bytes_per_function_id[function_match_summary.function_id] = function_match_summary.num_bytes * function_match_summary.matched_score / 100.0
            for function_id in families_matched_by_function_id:
                if len(families_matched_by_function_id[function_id]) == 1:
                    for sid in samples_matched_by_function_id[function_id]:
                        self.unique_family_scores_per_sample[sid]["functions_matched"] += 1
                        self.unique_family_scores_per_sample[sid]["bytes_matched"] += weighted_bytes_per_function_id[function_id]
            for sid in self.unique_family_scores_per_sample:
                self.unique_family_scores_per_sample[sid]["unique_score"] = 100.0 * self.unique_family_scores_per_sample[sid]["bytes_matched"] / self.reference_sample_entry.binweight
        if sample_id in self.unique_family_scores_per_sample:
            return self.unique_family_scores_per_sample[sample_id]
        else:
            return {"functions_matched": 0, "bytes_matched": 0, "unique_score": 0}


    def getSampleMatches(self, start=None, limit=None, library_only=False, malware_only=False):
        by_sample_id = {}
        for sample_match in self.sample_matches:
            if library_only and not sample_match.is_library:
                continue
            if malware_only and sample_match.is_library:
                continue
            by_sample_id[sample_match.sample_id] = {
                "score": sample_match.matched_percent_frequency_weighted,
                "report": sample_match
            }
        result_list = []
        for sample_id, score_entry in sorted(by_sample_id.items(), key=lambda e: e[1]["score"], reverse=True):
            result_list.append(score_entry["report"])
        if start is not None:
            result_list = result_list[start:]
        if limit is not None:
            result_list = result_list[:limit]
        return result_list

    def getAggregatedFunctionMatches(self, start=None, limit=None):
        by_function_id = {}
        for function_match in self.function_matches:
            if function_match.function_id not in by_function_id:
                by_function_id[function_match.function_id] = {
                    "function_id": function_match.function_id,
                    "num_bytes": 0,
                    "offset": 0,
                    "best_score": 0,
                    "num_families_matched": 0,
                    "family_ids_matched": set([]),
                    "families_matched": set([]),
                    "num_samples_matched": 0,
                    "sample_ids_matched": set([]),
                    "num_functions_matched": 0,
                    "function_ids_matched": set([]),
                    "minhash_matches": 0,
                    "pichash_matches": 0,
                    "library_matches": 0,
                }
            by_function_id[function_match.function_id]["num_bytes"] = function_match.num_bytes
            by_function_id[function_match.function_id]["offset"] = function_match.offset
            by_function_id[function_match.function_id]["best_score"] = max(function_match.matched_score, by_function_id[function_match.function_id]["best_score"])
            by_function_id[function_match.function_id]["family_ids_matched"].add(function_match.matched_family_id)
            by_function_id[function_match.function_id]["families_matched"].add(self.getFamilyNameByFamilyId(function_match.matched_family_id))
            by_function_id[function_match.function_id]["sample_ids_matched"].add(function_match.matched_sample_id)
            by_function_id[function_match.function_id]["function_ids_matched"].add(function_match.matched_function_id)
            by_function_id[function_match.function_id]["num_families_matched"] = len(by_function_id[function_match.function_id]["family_ids_matched"])
            by_function_id[function_match.function_id]["num_samples_matched"] = len(by_function_id[function_match.function_id]["sample_ids_matched"])
            by_function_id[function_match.function_id]["num_functions_matched"] = len(by_function_id[function_match.function_id]["function_ids_matched"])
            by_function_id[function_match.function_id]["minhash_matches"] += 1 if function_match.match_is_minhash else 0
            by_function_id[function_match.function_id]["pichash_matches"] += 1 if function_match.match_is_pichash else 0
            by_function_id[function_match.function_id]["library_matches"] += 1 if function_match.match_is_library else 0
            by_function_id[function_match.function_id]["is_family_unique"] = True if len(by_function_id[function_match.function_id]["family_ids_matched"]) == 1 else False
        aggregated_matched = [v for k, v in sorted(by_function_id.items())]
        if start is not None:
            aggregated_matched = aggregated_matched[start:]
        if limit is not None:
            aggregated_matched = aggregated_matched[:limit]
        return aggregated_matched

    def getFunctionsSlice(self, start, limit):
        return self.function_matches[start:start+limit]

    def toDict(self):
        # we need to aggregate by function_id here
        summarized_function_match_summaries = {}
        for function_match_entry in self.function_matches:
            if function_match_entry.function_id not in summarized_function_match_summaries:
                summarized_function_match_summaries[function_match_entry.function_id] = {
                    "num_bytes": function_match_entry.num_bytes,
                    "offset": function_match_entry.offset,
                    "fid": function_match_entry.function_id,
                    "matches": [function_match_entry.getMatchTuple()]
                }
            else:
                summarized_function_match_summaries[function_match_entry.function_id]["matches"].append(function_match_entry.getMatchTuple())
        # build the dictionary
        matching_entry = {
            "info": {
                "sample": self.reference_sample_entry.toDict()
            },
            "matches": {
                "aggregation": self.match_aggregation,
                "functions": summarized_function_match_summaries,
                "samples": [match.toDict() for match in self.sample_matches]
            }
        }
        if self.other_sample_entry is not None:
            matching_entry["other_sample_info"] = self.other_sample_entry.toDict()
        return matching_entry

    @classmethod
    def fromDict(cls, entry_dict):
        matching_entry = cls(None)
        matching_entry.reference_sample_entry = SampleEntry.fromDict(entry_dict["info"]["sample"])
        if "other_sample_info" in entry_dict:
            matching_entry.other_sample_entry = SampleEntry.fromDict(entry_dict["other_sample_info"])
        else:
            matching_entry.other_sample_entry = None
        matching_entry.match_aggregation = entry_dict["matches"]["aggregation"]
        matching_entry.sample_matches = [MatchedSampleEntry.fromDict(entry) for entry in entry_dict["matches"]["samples"]]
        # expand function matches into individual entries
        list_of_function_matches = []
        matching_entry.library_matches = {abs(entry["fid"]): [] for entry in entry_dict["matches"]["functions"]}
        matching_entry.unique_family_scores_per_sample = None
        matching_entry.num_original_function_matches = len(entry_dict["matches"]["functions"])
        matching_entry.num_original_sample_matches = len(matching_entry.sample_matches)
        matching_entry.num_original_family_matches = len(set([sample.family_id for sample in matching_entry.sample_matches if not sample.is_library]))
        matching_entry.num_original_library_matches = len(set([sample.family_id for sample in matching_entry.sample_matches if sample.is_library]))
        for function_match_summary in entry_dict["matches"]["functions"]:
            num_bytes = function_match_summary["num_bytes"]
            offset = function_match_summary["offset"]
            function_id = function_match_summary["fid"]
            # ensure that we have all function_ids in increasing order, regardless of whether they come from a query or regular match.
            matching_entry.is_query = True if function_id < 0 else False
            function_id = abs(function_id)
            if function_id not in matching_entry.function_id_to_family_ids_matched:
                matching_entry.function_id_to_family_ids_matched[function_id] = []
            for match_tuple in function_match_summary["matches"]:
                list_of_function_matches.append(MatchedFunctionEntry(function_id, num_bytes, offset, match_tuple))
                if match_tuple[0] not in matching_entry.function_id_to_family_ids_matched[function_id]:
                    matching_entry.function_id_to_family_ids_matched[function_id].append(match_tuple[0])
                if match_tuple[4] & MatcherInterface.IS_LIBRARY_FLAG:
                    if (match_tuple[0], match_tuple[1]) not in matching_entry.library_matches[function_id]:
                        matching_entry.library_matches[function_id].append((match_tuple[0], match_tuple[1]))
        matching_entry.function_matches = sorted(list_of_function_matches, key=lambda x: x.function_id)
        return matching_entry

    def __str__(self):
        return "Matched: Samples: {} Functions: {}".format(
            len(self.sample_matches),
            len(self.function_matches),
        )
