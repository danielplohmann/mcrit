import datetime
import functools
import logging
import math
from collections import defaultdict, Counter
from multiprocessing import Pool, cpu_count
from timeit import default_timer as timer
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Set, Tuple, Union

import tqdm
from mcrit.queue.QueueRemoteCalls import NoProgressReporter

if TYPE_CHECKING:  # pragma: no cover
    from mcrit.storage.FunctionEntry import FunctionEntry
    from mcrit.storage.SampleEntry import SampleEntry
    from mcrit.storage.MatchingCache import MatchingCache
    from mcrit.storage.MemoryStorage import MemoryStorage
    from mcrit.Worker import Worker


# Only do basicConfig if no handlers have been configured
if len(logging._handlerList) == 0:
    logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOGGER = logging.getLogger(__name__)

# function_id_own, sample_id_foreign, function_id_foreign, score, is_pic_match, is_min_match
HarmonizedMatches = Dict[Tuple[int, int, int], Tuple[float, bool, bool]]
PichashMatches = Dict[int, Set[Tuple[int, int, int]]]
MinhashMatches = List[Tuple[int, int, int, int, float]]

IS_MINHASH_FLAG = 1
IS_PICHASH_FLAG = 1 << 1
IS_LIBRARY_FLAG = 1 << 2


def build_method_str_from_args(args):
    # extract the job parameters
    method_str = ""
    try:
        method_type = f"{type(args[0])}"[8:-2]
        method_str = method_type.split(".")[-1]
        if len(args) > 1:
            method_str += "(" + ", ".join([str(i) for i in list(args)[1:]]) + ")"
    except:
        pass
    return method_str


def add_duration(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = timer()
        result = func(*args, **kwargs)
        time = timer() - start
        result["info"]["job"] = {
            "duration": time, 
            "timestamp": datetime.datetime.now().isoformat(),
            "parameters": build_method_str_from_args(args)
        }
        return result

    return wrapper


class MatcherInterface(object):
    def __init__(
        self, worker: "Worker", minhash_threshold=None, pichash_size=None, band_matches_required=None, progress_reporter=NoProgressReporter()
    ):
        # Extended by Query, VS, Sample
        self._worker: "Worker" = worker
        self._storage = worker.getStorage()
        self._function_entries: List["FunctionEntry"] = []
        self._sample_info: Optional[Dict] = None
        self._sample_id: Optional[int] = None
        self._progress_reporter = progress_reporter
        self._minhash_threshold = minhash_threshold
        if pichash_size is None:
            pichash_size = self._worker.config.MINHASH_CONFIG.PICHASH_SIZE
        if band_matches_required is None:
            band_matches_required = self._worker.config.MINHASH_CONFIG.BAND_MATCHES_REQUIRED
        self._band_matches_required = band_matches_required
        self._pichash_size = pichash_size
        self._additional_setup()
        self._sample_to_lib_info: Dict[int, bool]
        self._sample_id_to_entry: Dict[int, SampleEntry]

    def _additional_setup(self):
        pass

    def getMatchesForSample(self, sample_id, other_sample_id, minhash_threshold=None):
        # VS, Sample
        raise NotImplementedError

    def getMatchesForSmdaReport(self, smda_report, minhash_threshold=None):
        # Query
        raise NotImplementedError

    def _getPicHashMatches(self) -> Dict[int, Set[Tuple[int, int]]]:
        # Query, VS, Sample
        # Every Matcher has own implementation
        raise NotImplementedError

    def _createMinHashCandidateGroups(self, start=0, end=None) -> Dict[int, Set[int]]:
        # Query, VS, Sample
        # Sample , Query have this plain version
        # VS adds another intersection step to this version
        # find candidates based on bands
        if end is None:
            end = len(self._function_entries)
        candidate_groups = {}
        function_id_to_minhash = {}
        for function_entry in self._function_entries[start:end]:
            function_id_to_minhash[function_entry.function_id] = function_entry.getMinHash(
                minhash_bits=self._worker._minhash_config.MINHASH_SIGNATURE_BITS
            )
        candidate_groups = self._storage.getCandidatesForMinHashes(function_id_to_minhash, band_matches_required=self._band_matches_required)

        return candidate_groups

    def _createMatchingCache(self, candidate_groups):
        # Query, VS, Sample
        # This version is used by VS, Sample
        # Own version by Query
        cache_function_ids = set()
        for candidate_key, candidate_functions in candidate_groups.items():
            cache_function_ids.add(candidate_key)
            cache_function_ids.update(candidate_functions)
        LOGGER.info("creating cache for %d functions", len(cache_function_ids))
        return self._storage.createMatchingCache(cache_function_ids)

    ######## Below this line, nothing will be overwritten by Subclasses #########

    def filter_pichashes_from_candidate_groups(self, matching_cache, candidate_groups, pichash_matches):
        finished_tuples = set()
        for pichash_match in pichash_matches:
            own_fid, foreign_sid, foreign_fid = pichash_match
            if own_fid in candidate_groups:
                # remove all candidates of the respective sample instead
                if (own_fid, foreign_sid) not in finished_tuples:
                    if matching_cache.isSampleId(foreign_sid):
                        pichash_match_sid_fids = matching_cache.getFunctionIdsBySampleId(foreign_sid)
                        candidate_groups[own_fid].difference_update(pichash_match_sid_fids)
                        finished_tuples.add((own_fid, foreign_sid))
        return candidate_groups

    def _getMatchesRoutine(self):
        # Query, VS, Sample
        # All use this version
        pichash_matches = self._harmonizePicHashMatches(self._getPicHashMatches())
        LOGGER.info("Calculated PicHash matches")
        all_minhash_matches = {}
        # if we have an exceedingly large number of functions, we need to process in batches...
        for start_index in range(0, len(self._function_entries), 10000):
            candidate_groups = self._createMinHashCandidateGroups(start=start_index, end=start_index+10000)
            LOGGER.info("Created candidate groups from MinHash bands")
            matching_cache = self._createMatchingCache(candidate_groups)
            LOGGER.info("Created MatchingCache")
            if self._worker._minhash_config.PICHASH_IMPLIES_MINHASH_MATCH:
                LOGGER.info("Removing PicHash matches")
                candidate_groups = self.filter_pichashes_from_candidate_groups(matching_cache, candidate_groups, pichash_matches)
                LOGGER.info("Removed PicHash matches from CandidateGroups")
            LOGGER.info("Now starting MinHash matching")
            minhash_matches = self._harmonizeMinHashMatches(self._sample_id, self._performMinHashMatching(candidate_groups, matching_cache))
            all_minhash_matches.update(minhash_matches)
        LOGGER.info("Calculated MinHash matches.")
        matching_report = self._craftResultDict(pichash_matches, all_minhash_matches)
        LOGGER.info("Returning aggregated match report.")
        return matching_report

    # Reports PROGRESS
    def _performMinHashMatching(self, candidate_groups: Dict[int, Set[int]], cache) -> List[Tuple[int, int, int, int, float]]:
        # Query, VS, Sample
        # All use the same version
        """perform matching between candidates, provided as candidate_groups in the form of a dict: {function_id: [function_ids]}"""
        # result format: sample_id_a, function_id_a, sample_id_b, function_id_b, score
        matching_results: List[Tuple[int, int, int, int, float]] = []
        organized_matching_results: Dict[Tuple[int, int, int], Tuple[int, float]] = defaultdict(lambda: (-1, -1.0))
        packed_tuples = self._unrollGroupsAsPackedTuples(cache, candidate_groups)
        num_packed_tuples = self._countPackedTuples(candidate_groups)
        self._progress_reporter.set_total(num_packed_tuples)
        calculation_function = functools.partial(
            self._worker.minhasher.calculateScoresFromPackedTuples, ignore_threshold=True, minhash_threshold=self._minhash_threshold
        )
        packed_tuples = [p for p in packed_tuples]
        counted_scores = Counter()
        if self._worker._minhash_config.MINHASH_POOL_MATCHING:
            with Pool(cpu_count()) as pool:
                for pool_result in tqdm.tqdm(
                    pool.imap_unordered(calculation_function, packed_tuples),
                    total=num_packed_tuples,
                ):
                    # for key, new_value in pool_result.items():
                    for single_result in pool_result:
                        sample_id_a, function_id_a, sample_id_b, function_id_b, score = single_result
                        counted_scores[score] += 1
                        if score > self._worker.config.MINHASH_CONFIG.MINHASH_MATCHING_THRESHOLD:
                            key = (sample_id_a, function_id_a, sample_id_b)
                            new_value = (function_id_b, score)
                            original_value = organized_matching_results[key]
                            organized_matching_results[key] = max([original_value, new_value], key=lambda x:x[1])
                    self._progress_reporter.step()
        else:
            packed_tuple: List[Tuple[int, int, bytes, int, int, bytes]]
            for packed_tuple in tqdm.tqdm(packed_tuples, total=num_packed_tuples):
                pool_result = calculation_function(packed_tuple)
                for key, new_value in pool_result.items():
                    original_value = organized_matching_results[key]
                    organized_matching_results[key] = max([original_value, new_value], key=lambda x:x[1])
                self._progress_reporter.step()
        full_score_counts = sorted([(item[0]*64/100, item[1]) for item in dict(counted_scores).items()])
        LOGGER.info("Minhash Signature Field Match Counts: " + ", ".join([f"({i[0]}: {i[1]})" for i in full_score_counts]))
        matching_results = [k+v for k, v in organized_matching_results.items()]
        self._storage.clearMatchingCache()
        return matching_results

    def _countPackedTuples(self, candidate_pairs, packsize=20000) -> int:
        count = 0
        for candidate_ids in candidate_pairs.values():
            count += len(candidate_ids) 
        quotient, remainder = divmod(count, packsize)
        LOGGER.info("Processing a total of %d candidates.", count)
        return quotient + int(bool(remainder)) # always round up

    def _unrollGroupsAsPackedTuples(
        self, cache: Union["MatchingCache", "MemoryStorage"], candidate_pairs, packsize=20000
    ) -> Iterable[List[Tuple[int, int, bytes, int, int, bytes]]]:
        # Query, VS, Sample
        # All were identical
        packed_tuples: List[List[Tuple[int, int, bytes, int, int, bytes]]] = []
        current_pack: List[Tuple[int, int, bytes, int, int, bytes]] = []
        count = 0
        for function_id_a, candidate_ids in sorted(candidate_pairs.items()):
            for function_id_b in sorted(candidate_ids):
                if function_id_a == function_id_b:
                    continue
                minhash_a = cache.getMinHashByFunctionId(function_id_a)
                minhash_b = cache.getMinHashByFunctionId(function_id_b)
                sample_id_a = cache.getSampleIdByFunctionId(function_id_a)
                sample_id_b = cache.getSampleIdByFunctionId(function_id_b)
                current_pack.append((sample_id_a, function_id_a, minhash_a, sample_id_b, function_id_b, minhash_b))
                if count < packsize:
                    count += 1
                else:
                    # packed_tuples.append(current_pack)
                    yield current_pack
                    current_pack = []
                    count = 0
        if current_pack:
            # packed_tuples.append(current_pack)
            yield current_pack
        return packed_tuples

    def _harmonizePicHashMatches(self, pichash_matches: PichashMatches) -> HarmonizedMatches:
        # Query, VS, Sample
        # all use this version
        pichash_match_mapping: HarmonizedMatches = {}
        cached_function_id_to_sample_id: Dict[int, int] = {}
        # all_own_function_ids = {entry.function_id for entry in self._function_entries}
        sample_function_id_to_size = {entry.function_id: entry.num_instructions for entry in self._function_entries}
        for _, pichash_tuples in pichash_matches.items():
            current_own_function_ids: List[int] = []
            current_foreign_function_ids: List[int] = []
            function_size = 0
            for pichash_tuple in pichash_tuples:
                bh_family_id, bh_sample_id, bh_function_id = pichash_tuple
                cached_function_id_to_sample_id[bh_function_id] = bh_sample_id
                if bh_function_id in sample_function_id_to_size:
                    current_own_function_ids.append(bh_function_id)
                    function_size = sample_function_id_to_size[bh_function_id]
                else:
                    current_foreign_function_ids.append(bh_function_id)
            if function_size < self._pichash_size:
                continue
            # eval matches for this set of tuples
            if len(pichash_tuples) > 1:
                for own_function_id in current_own_function_ids:
                    for foreign_function_id in current_foreign_function_ids:
                        foreign_sample_id = cached_function_id_to_sample_id[foreign_function_id]
                        foreign_tuple = (foreign_sample_id, foreign_function_id)
                        pichash_match_mapping[(own_function_id, *foreign_tuple)] = (100, True, False)
                    # include self matches
                    for own_function_id_2 in current_own_function_ids:
                        if own_function_id == own_function_id_2:
                            continue
                        foreign_sample_id = cached_function_id_to_sample_id[own_function_id_2]
                        foreign_tuple = (foreign_sample_id, own_function_id_2)
                        pichash_match_mapping[(own_function_id, *foreign_tuple)] = (100, True, False)
        return pichash_match_mapping

    def _harmonizeMinHashMatches(self, sample_id, minhash_matches: MinhashMatches) -> HarmonizedMatches:
        # Query, VS, Sample
        # all use this version
        # handle minhashes
        minhash_mapping: HarmonizedMatches = {}

        for match in minhash_matches:
            sample_id_a, function_id_a, sample_id_b, function_id_b, minhash_score = match
            if sample_id_a == sample_id:
                own_function_id = function_id_a
                foreign_function_id = function_id_b
                foreign_sample_id = sample_id_b
                minhash_mapping[(own_function_id, foreign_sample_id, foreign_function_id)] = (
                    minhash_score,
                    False,
                    True,
                )
            if sample_id_b == sample_id:
                own_function_id = function_id_b
                foreign_function_id = function_id_a
                foreign_sample_id = sample_id_a
                minhash_mapping[(own_function_id, foreign_sample_id, foreign_function_id)] = (
                    minhash_score,
                    False,
                    True,
                )

        return minhash_mapping

    # summarizing, formatting starts here:

    def _summarizeMatches(
        self, sample_id, matches: HarmonizedMatches, aggregation_only: bool
    ) -> Tuple[List, Dict, Dict, float]:
        # Query, VS, Sample
        # all use this version
        sample_fid_to_binweight = {entry.function_id: entry.binweight for entry in self._function_entries}
        sample_fid_to_offset = {entry.function_id: entry.offset for entry in self._function_entries}
        aggregation = {
            "num_own_functions_matched": 0,
            "num_foreign_functions_matched": 0,
            "num_own_functions_matched_as_library": 0,
            "num_self_matches": 0,
            "bytes_matched": 0.0,
        }
        # handle minhashes
        match_function_mapping: Dict[int, Dict] = {}
        match_sample_mapping: Dict[int, Any]
        matches_sample_list = []
        # from here on structure the stuff in the same way as pichash result
        self_matched_functions: Set[int] = set()
        own_functions_with_matches: Set[int] = set()
        own_functions_with_library_matches: Set[int] = set()
        foreign_functions_matched: Set[int] = set()

        for match_ids, match_strength in matches.items():
            own_function_id, foreign_sample_id, foreign_function_id = match_ids
            minhash_score, is_pichash_match, is_minhash_match = match_strength

            if foreign_sample_id == sample_id:
                self_matched_functions.add(own_function_id)
                self_matched_functions.add(foreign_function_id)
            else:
                if foreign_sample_id not in self._sample_to_lib_info:
                    self._sample_to_lib_info[foreign_sample_id] = (
                        self._storage.getLibraryInfoForSampleId(foreign_sample_id) is not None
                    )
                has_libinfo = self._sample_to_lib_info[foreign_sample_id]

                if foreign_sample_id not in self._sample_id_to_entry:
                    self._sample_id_to_entry[foreign_sample_id] = self._storage.getSampleById(foreign_sample_id)
                foreign_family_id = self._sample_id_to_entry[foreign_sample_id].family_id

                if own_function_id not in match_function_mapping:
                    match_function_mapping[own_function_id] = {
                        "num_bytes": sample_fid_to_binweight[own_function_id],
                        "offset": sample_fid_to_offset[own_function_id],
                        "matches": [],
                    }

                flags = (
                    is_pichash_match * IS_PICHASH_FLAG
                    + is_minhash_match * IS_MINHASH_FLAG
                    + has_libinfo * IS_LIBRARY_FLAG
                )
                match_function_mapping[own_function_id]["matches"].append(
                    (
                        foreign_family_id,
                        foreign_sample_id,
                        foreign_function_id,
                        minhash_score,
                        flags,
                    )
                )
                foreign_functions_matched.add(foreign_function_id)
                own_functions_with_matches.add(own_function_id)
                if has_libinfo:
                    own_functions_with_library_matches.add(own_function_id)

        # Anti-Value-Key post processing
        matches_function_list = []
        for function_id, dict in match_function_mapping.items():
            dict["fid"] = function_id
            # this creates additional stability for tests and processing
            dict["matches"] = sorted(dict["matches"])
            matches_function_list.append(dict)

        aggregation["num_self_matches"] = len(self_matched_functions)
        aggregation["num_own_functions_matched"] = len(own_functions_with_matches)
        aggregation["bytes_matched"] = sum(
            [sample_fid_to_binweight[own_function_id] for own_function_id in own_functions_with_matches]
        )
        aggregation["num_foreign_functions_matched"] = len(foreign_functions_matched)
        aggregation["num_own_functions_matched_as_library"] = len(own_functions_with_library_matches)

        num_library_match_bytes = sum(
            [match_function_mapping[function_id]["num_bytes"] for function_id in own_functions_with_library_matches]
        )

        return matches_function_list, match_function_mapping, aggregation, num_library_match_bytes

    def _get_family_adjustment(self, match_report) -> Dict[int, float]:
        adjustments: Dict[int, float] = {}
        for fid, function_data in match_report.items():
            families = {match[0] for match in function_data["matches"]}
            family_adjustment_value = 1 if len(families) < 3 else 1 + int(math.log(len(families), 2))
            adjustments[fid] = family_adjustment_value
        return adjustments

    def _aggregateMatchSampleSummary(self, match_report, own_sample_info, num_library_bytes):
        own_sample_num_bytes = own_sample_info["binweight"]
        own_sample_num_nonlibrary_bytes = own_sample_num_bytes - num_library_bytes
        # aggregate sample byte sizes
        function_num_bytes = {}
        for own_function_id, function_data in match_report.items():
            function_num_bytes[own_function_id] = function_data["num_bytes"]
        # summarize samples
        matches_per_sample = self._aggregateMatchesPerSample(match_report)
        sample_summary = {}

        family_adjustment = self._get_family_adjustment(match_report)

        for foreign_sample_id in matches_per_sample:
            if not foreign_sample_id in self._sample_id_to_entry:
                self._sample_id_to_entry[foreign_sample_id] = self._storage.getSampleById(foreign_sample_id)
            sample_info = self._sample_id_to_entry[foreign_sample_id]
            sample_summary[foreign_sample_id] = {
                "family": sample_info.family,
                "family_id": sample_info.family_id,
                "version": sample_info.version,
                "bitness": sample_info.bitness,
                "sha256": sample_info.sha256,
                "filename": sample_info.filename,
                "sample_id": foreign_sample_id,
                "num_bytes": sample_info.binweight,
                "is_library": sample_info.is_library,
                "num_functions": sample_info.statistics["num_functions"],
                "matched": {
                    "functions": {
                        "minhashes": 0,
                        "pichashes": 0,
                        "combined": 0,
                        "library": 0,
                    },
                    "bytes": {
                        "unweighted": 0,
                        "score_weighted": 0,
                        "frequency_weighted": 0,
                        "nonlib_unweighted": 0,
                        "nonlib_score_weighted": 0,
                        "nonlib_frequency_weighted": 0,
                    },
                    "percent": {
                        "unweighted": 0,
                        "score_weighted": 0,
                        "frequency_weighted": 0,
                        "nonlib_unweighted": 0,
                        "nonlib_score_weighted": 0,
                        "nonlib_frequency_weighted": 0,
                    },
                },
            }
            current_matched = sample_summary[foreign_sample_id]["matched"]
            for own_function_id, matches in matches_per_sample[foreign_sample_id].items():
                current_matched["functions"]["combined"] += 1
                has_library_match = "library" in [match[0] for match in matches]
                current_matched["functions"]["library"] += 1 if has_library_match else 0
                current_matched["functions"]["minhashes"] += 1 if "minhash" in [match[0] for match in matches] else 0
                current_matched["functions"]["pichashes"] += 1 if "pichash" in [match[0] for match in matches] else 0

                match_max = max([match[1] for match in matches])
                unweighted_inc = function_num_bytes[own_function_id]
                score_weighted_inc = 1.0 * unweighted_inc * match_max / 100.0
                frequency_weighted_inc = score_weighted_inc / family_adjustment[own_function_id]

                current_matched["bytes"]["unweighted"] += unweighted_inc
                current_matched["bytes"]["score_weighted"] += score_weighted_inc
                current_matched["bytes"]["frequency_weighted"] += frequency_weighted_inc
                if not has_library_match:
                    current_matched["bytes"]["nonlib_unweighted"] += unweighted_inc
                    current_matched["bytes"]["nonlib_score_weighted"] += score_weighted_inc
                    current_matched["bytes"]["nonlib_frequency_weighted"] += frequency_weighted_inc

            for kind in "unweighted", "score_weighted", "frequency_weighted":
                current_matched["percent"][kind] = 100.0 * current_matched["bytes"][kind] / own_sample_num_bytes
                current_matched["percent"]["nonlib_" + kind] = (
                    100.0 * current_matched["bytes"]["nonlib_" + kind] / own_sample_num_nonlibrary_bytes
                )

        return list(sample_summary.values())

    def _aggregateMatchesPerSample(self, match_report):
        matches_per_sample: Dict[int, Dict[int, List[Tuple[str, float]]]] = defaultdict(lambda: defaultdict(list))
        for own_function_id, function_data in match_report.items():
            function_has_libinfo = any([bool(match[-1] & IS_LIBRARY_FLAG) for match in function_data["matches"]])
            for match in function_data["matches"]:
                (
                    foreign_family_id,
                    foreign_sample_id,
                    foreign_function_id,
                    minhash_score,
                    flags,
                ) = match
                is_pichash_match = flags & IS_PICHASH_FLAG
                is_minhash_match = flags & IS_MINHASH_FLAG
                match_types = []
                if is_pichash_match:
                    match_types.append("pichash")
                if is_minhash_match:
                    match_types.append("minhash")
                for match_type in match_types:
                    matches_per_sample[foreign_sample_id][own_function_id].append((match_type, minhash_score))
                if function_has_libinfo:
                    matches_per_sample[foreign_sample_id][own_function_id].append(("library", 0))
        return matches_per_sample

    def _craftResultDict(
        self, pichash_matches: HarmonizedMatches, minhash_matches: HarmonizedMatches, num_matches=None
    ) -> Dict:
        # Query, VS, Sample
        # All use this version
        if self._worker._minhash_config.PICHASH_IMPLIES_MINHASH_MATCH:
            for key, new_entry in pichash_matches.items():
                if key not in minhash_matches:
                    minhash_matches[key] = (100.0, 0, 1)
        all_matches = minhash_matches.copy()
        for key, new_entry in pichash_matches.items():
            if key in all_matches:
                old_entry = all_matches[key]
                # update values: score, is_pic, is_min
                all_matches[key] = tuple([max(old_entry[i], new_entry[i]) for i in range(3)])
            else:
                all_matches[key] = new_entry

        _, _, pichash_aggregation, _ = self._summarizeMatches(self._sample_id, pichash_matches, False)
        # Assume that every pichash is also a min hash:
        _, _, minhash_aggregation, _ = self._summarizeMatches(self._sample_id, minhash_matches, False)

        (all_functions_summary, all_functions_list, all_aggregation, num_library_bytes) = self._summarizeMatches(
            self._sample_id, all_matches, False
        )
        sample_summary = self._aggregateMatchSampleSummary(all_functions_list, self._sample_info, num_library_bytes)
        summary = {
            "info": {
                "job": None,
                "sample": self._sample_info,
            },
            "matches": {
                "aggregation": {
                    # assume all pichashes are also minhashes
                    "minhash": minhash_aggregation,
                    "pichash": pichash_aggregation,
                },
                "functions": all_functions_summary,
                "samples": sample_summary,
            },
        }
        return summary
