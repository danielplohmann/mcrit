from typing import List, Optional

import mcrit.matchers.MatcherFlags as MatcherFlags

_ALL_MATCH_FLAGS = MatcherFlags.IS_MINHASH_FLAG | MatcherFlags.IS_PICHASH_FLAG | MatcherFlags.IS_LIBRARY_FLAG


class MatchedFunctionEntry:
    """One (own function, matched function) pair of a MatchingResult.

    A large result holds hundreds of thousands of these, so the class is kept lean (#44):
    slots instead of a per-instance dict, and the match flags are kept as the integer the
    wire format carries, with the match_is_* booleans derived from it on access. That also
    makes the round trip exact by construction: getMatchTuple hands the flags back as they
    came in (#155).
    """

    __slots__ = (
        "function_id",
        "num_bytes",
        "offset",
        "matched_family_id",
        "matched_family",
        "matched_sample_id",
        "matched_function_id",
        "matched_score",
        "matched_link_score",
        "matched_unique",
        "matched_offset",
        "match_flags",
    )

    # basic information
    function_id: int
    num_bytes: int
    offset: int
    matched_family_id: int
    matched_family: Optional[str]
    matched_sample_id: int
    matched_function_id: int
    matched_score: float
    matched_link_score: float
    matched_unique: Optional[bool]
    matched_offset: Optional[int]
    match_flags: int

    def __init__(self, function_id: int, num_bytes: int, offset: int, match_tuple: List) -> None:
        self.function_id = function_id
        self.num_bytes = num_bytes
        self.offset = offset
        self.matched_family_id = match_tuple[0]
        self.matched_sample_id = match_tuple[1]
        self.matched_function_id = match_tuple[2]
        self.matched_score = match_tuple[3]
        self.match_flags = match_tuple[4] & _ALL_MATCH_FLAGS
        self.matched_family = None
        self.matched_link_score = 0
        self.matched_unique = None
        self.matched_offset = None

    @property
    def match_is_minhash(self) -> bool:
        return bool(self.match_flags & MatcherFlags.IS_MINHASH_FLAG)

    @property
    def match_is_pichash(self) -> bool:
        return bool(self.match_flags & MatcherFlags.IS_PICHASH_FLAG)

    @property
    def match_is_library(self) -> bool:
        return bool(self.match_flags & MatcherFlags.IS_LIBRARY_FLAG)

    def getMatchTuple(self) -> List:
        return [self.matched_family_id, self.matched_sample_id, self.matched_function_id, self.matched_score, self.match_flags]

    def toDict(self):
        matching_entry = {"fid": self.function_id, "num_bytes": self.num_bytes, "offset": self.offset, "matches": self.getMatchTuple()}
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
            self.function_id, self.num_bytes, self.matched_family_id, self.matched_sample_id, self.matched_function_id, self.matched_score, flag_str
        )
