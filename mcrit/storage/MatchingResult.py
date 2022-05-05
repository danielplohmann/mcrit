from random import sample
from typing import TYPE_CHECKING, Dict, List, Optional

from mcrit.storage.SampleEntry import SampleEntry
from mcrit.storage.MatchedSampleEntry import MatchedSampleEntry
from mcrit.storage.MatchedFunctionEntry import MatchedFunctionEntry

if TYPE_CHECKING:  # pragma: no cover
    from mcrit.storage.SampleEntry import SampleEntry

# Dataclass, post init
# constructor -> .fromSmdaFunction
# assume sample_entry, smda_function always available

class MatchingResult(object):
    job_id: str
    result_id: str
    job_duration: int
    job_timestamp: int
    job_parameters: int
    reference_sample_entry: "SampleEntry"
    other_sample_entry: "SampleEntry"
    match_aggregation: Dict
    function_matches: List["MatchedFunctionEntry"]
    sample_matches: List["MatchedSampleEntry"]

    def __init__(self, sample_entry: "SampleEntry") -> None:
        self.reference_sample_entry = sample_entry

    def getBestSampleMatchesPerFamily(self, start=None, limit=None):
        by_family = {}
        for sample_match in self.sample_matches:
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
            by_function_id[function_match.function_id]["sample_ids_matched"].add(function_match.matched_sample_id)
            by_function_id[function_match.function_id]["function_ids_matched"].add(function_match.matched_function_id)
            by_function_id[function_match.function_id]["num_families_matched"] = len(by_function_id[function_match.function_id]["family_ids_matched"])
            by_function_id[function_match.function_id]["num_samples_matched"] = len(by_function_id[function_match.function_id]["sample_ids_matched"])
            by_function_id[function_match.function_id]["num_functions_matched"] = len(by_function_id[function_match.function_id]["function_ids_matched"])
            by_function_id[function_match.function_id]["minhash_matches"] += 1 if function_match.match_is_minhash else 0
            by_function_id[function_match.function_id]["pichash_matches"] += 1 if function_match.match_is_pichash else 0
            by_function_id[function_match.function_id]["library_matches"] += 1 if function_match.match_is_library else 0
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
                function_match_entry[function_match_entry.function_id] = {
                    "num_bytes": function_match_entry.num_bytes,
                    "fid": function_match_entry.function_id,
                    "matches": [function_match_entry.getMatchTuple()]
                }
            else:
                function_match_entry[function_match_entry.function_id]["matches"].append(function_match_entry.getMatchTuple())
        # build the dictionary
        matching_entry = {
            "info": {
                "job": {
                    "job_id": self.job_id,
                    "result_id": self.result_id,
                    "duration": self.job_duration,
                    "timestamp": self.job_timestamp,
                    "parameters": self.job_parameters,
                },
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
        matching_entry.job_id = entry_dict["info"]["job"]["job_id"]
        matching_entry.result_id = entry_dict["info"]["job"]["result_id"]
        matching_entry.job_duration = entry_dict["info"]["job"]["duration"]
        matching_entry.job_timestamp = entry_dict["info"]["job"]["timestamp"]
        matching_entry.job_parameters = entry_dict["info"]["job"]["parameters"]

        matching_entry.reference_sample_entry = SampleEntry.fromDict(entry_dict["info"]["sample"])
        if "other_sample_info" in entry_dict:
            matching_entry.other_sample_entry = SampleEntry.fromDict(entry_dict["other_sample_info"])
        else:
            matching_entry.other_sample_entry = None
        matching_entry.match_aggregation = entry_dict["matches"]["aggregation"]
        matching_entry.sample_matches = [MatchedSampleEntry.fromDict(entry) for entry in entry_dict["matches"]["samples"]]
        # expand function matches into individual entries
        list_of_function_matches = []
        for function_match_summary in entry_dict["matches"]["functions"]:
            num_bytes = function_match_summary["num_bytes"]
            offset = function_match_summary["offset"]
            function_id = function_match_summary["fid"]
            for match_tuple in function_match_summary["matches"]:
                list_of_function_matches.append(MatchedFunctionEntry(function_id, num_bytes, offset, match_tuple))
        matching_entry.function_matches = list_of_function_matches
        return matching_entry

    def __str__(self):
        return "Job: {} / {} - Matched: Samples: {} Functions: {}".format(
            self.job_timestamp,
            self.job_parameters,
            len(self.sample_matches),
            len(self.function_matches),
        )
