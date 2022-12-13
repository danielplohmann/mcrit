from typing import TYPE_CHECKING, Dict, List, Optional

from mcrit.storage.SampleEntry import SampleEntry
import mcrit.matchers.MatcherInterface as MatcherInterface

if TYPE_CHECKING:  # pragma: no cover
    from mcrit.storage.SampleEntry import SampleEntry

# Dataclass, post init
# constructor -> .fromSmdaFunction
# assume sample_entry, smda_function always available

class MatchedFunctionEntry(object):
    # basic information
    function_id: int
    num_bytes: int
    offset: int
    matched_family_id: int
    matched_sample_id: int
    matched_function_id: int
    matched_score: float
    match_is_minhash: bool
    match_is_pichash: bool
    match_is_library: bool


    def __init__(self, function_id: int, num_bytes:int, offset:int, match_tuple: List) -> None:
        self.function_id = function_id
        self.num_bytes = num_bytes
        self.offset = offset
        self.matched_family_id = match_tuple[0]
        self.matched_sample_id = match_tuple[1]
        self.matched_function_id = match_tuple[2]
        self.matched_score = match_tuple[3]
        self.match_is_minhash = match_tuple[4] & MatcherInterface.IS_MINHASH_FLAG
        self.match_is_pichash = match_tuple[4] & MatcherInterface.IS_PICHASH_FLAG
        self.match_is_library = match_tuple[4] & MatcherInterface.IS_LIBRARY_FLAG

    def getMatchTuple(self):
        return [
                self.matched_family_id,
                self.matched_sample_id,
                self.matched_function_id,
                self.matched_score,
                self.match_is_minhash * MatcherInterface.IS_MINHASH_FLAG
                + self.match_is_pichash * MatcherInterface.IS_PICHASH_FLAG
                + self.match_is_library * MatcherInterface.IS_LIBRARY_FLAG
            ]

    def toDict(self):
        matching_entry = {
            "fid": self.function_id,
            "num_bytes": self.num_bytes,
            "offset": self.offset,
            "matches": self.getMatchTuple()
        }
        return matching_entry

    @classmethod
    def fromDict(cls, entry_dict):
        matching_entry = cls(entry_dict["fid"], entry_dict["num_bytes"], entry_dict["offset"], entry_dict["matches"])
        return matching_entry

    def __str__(self):
        flag_str = "m" if self.match_is_minhash else "."
        flag_str += "p" if self.match_is_pichash else "."
        flag_str += "l" if self.match_is_library else "."
        return "Function: fid({}) num_bytes({}) - Matched: family_id({}) sample_id({}) function_id({}) score({}) flags({})".format(
            self.function_id,
            self.num_bytes,
            self.matched_family_id,
            self.matched_sample_id,
            self.matched_function_id,
            self.matched_score,
            flag_str
        )
