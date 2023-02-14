from typing import TYPE_CHECKING, Dict, List, Optional

from mcrit.storage.SampleEntry import SampleEntry

if TYPE_CHECKING:  # pragma: no cover
    from mcrit.storage.SampleEntry import SampleEntry

# Dataclass, post init
# constructor -> .fromSmdaFunction
# assume sample_entry, smda_function always available

class MatchedSampleEntry(object):
    # basic information
    family: str
    family_id: int
    version: str
    bitness: int
    sha256: str
    filename: str
    sample_id: int
    num_bytes: int
    num_functions: int
    is_library: bool
    # related to matching
    matched_functions_minhash: int
    matched_functions_pichash: int
    matched_functions_combined: int
    matched_functions_library: int
    # scores
    matched_bytes_unweighted: float
    matched_bytes_score_weighted: float
    matched_bytes_frequency_weighted: float
    matched_bytes_nonlib_unweighted: float
    matched_bytes_nonlib_score_weighted: float
    matched_bytes_nonlib_frequency_weighted: float
    matched_percent_unweighted: float
    matched_percent_score_weighted: float
    matched_percent_frequency_weighted: float
    matched_percent_nonlib_unweighted: float
    matched_percent_nonlib_score_weighted: float
    matched_percent_nonlib_frequency_weighted: float

    def __init__(self, sample_id: int) -> None:
        self.sample_id = sample_id


    def getShortSha256(self, prefix=8, border=0):
        if border > 0:
            return self.sha256[:border] + "..." + self.sha256[-border:]
        elif prefix > 0:
            return self.sha256[:prefix]
        return self.sha256

    def getShortFilename(self, size_visible=20):
        if (len(self.filename) > 2 * size_visible):
            return self.filename[:size_visible] + "..." + self.filename[-size_visible:]
        return self.filename

    def toDict(self):
        matching_entry = {
            "family": self.family,
            "family_id": self.family_id,
            "version": self.version,
            "bitness": self.bitness,
            "sha256": self.sha256,
            "filename": self.filename,
            "sample_id": self.sample_id,
            "num_bytes": self.num_bytes,
            "num_functions": self.num_functions,
            "matched": {
                "functions": {
                    "minhashes": self.matched_functions_minhash,
                    "pichashes": self.matched_functions_pichash,
                    "combined": self.matched_functions_combined,
                    "library": self.matched_functions_library,
                },
                "bytes": {
                    "unweighted": self.matched_bytes_unweighted,
                    "score_weighted": self.matched_bytes_score_weighted,
                    "frequency_weighted": self.matched_bytes_frequency_weighted,
                    "nonlib_unweighted": self.matched_bytes_nonlib_unweighted,
                    "nonlib_score_weighted": self.matched_bytes_nonlib_score_weighted,
                    "nonlib_frequency_weighted": self.matched_bytes_nonlib_frequency_weighted
                },
                "percent": {
                    "unweighted": self.matched_percent_unweighted,
                    "score_weighted": self.matched_percent_score_weighted,
                    "frequency_weighted": self.matched_percent_frequency_weighted,
                    "nonlib_unweighted": self.matched_percent_nonlib_unweighted,
                    "nonlib_score_weighted": self.matched_percent_nonlib_score_weighted,
                    "nonlib_frequency_weighted": self.matched_percent_nonlib_frequency_weighted
                }
            }
        }
        return matching_entry

    @classmethod
    def fromDict(cls, entry_dict):
        matching_entry = cls(None)
        matching_entry.family = entry_dict["family"]
        matching_entry.family_id = entry_dict["family_id"]
        matching_entry.version = entry_dict["version"]
        matching_entry.bitness = entry_dict["bitness"]
        matching_entry.sha256 = entry_dict["sha256"]
        matching_entry.filename = entry_dict["filename"]
        matching_entry.sample_id = entry_dict["sample_id"]
        matching_entry.num_bytes = entry_dict["num_bytes"]
        matching_entry.num_functions = entry_dict["num_functions"]
        matching_entry.is_library = entry_dict["is_library"] if "is_library" in entry_dict else False

        matching_entry.matched_functions_minhash = entry_dict["matched"]["functions"]["minhashes"]
        matching_entry.matched_functions_pichash = entry_dict["matched"]["functions"]["pichashes"]
        matching_entry.matched_functions_combined = entry_dict["matched"]["functions"]["combined"]
        matching_entry.matched_functions_library = entry_dict["matched"]["functions"]["library"]

        matching_entry.matched_bytes_unweighted = entry_dict["matched"]["bytes"]["unweighted"]
        matching_entry.matched_bytes_score_weighted = entry_dict["matched"]["bytes"]["score_weighted"]
        matching_entry.matched_bytes_frequency_weighted = entry_dict["matched"]["bytes"]["frequency_weighted"]
        matching_entry.matched_bytes_nonlib_unweighted = entry_dict["matched"]["bytes"]["nonlib_unweighted"]
        matching_entry.matched_bytes_nonlib_score_weighted = entry_dict["matched"]["bytes"]["nonlib_score_weighted"]
        matching_entry.matched_bytes_nonlib_frequency_weighted = entry_dict["matched"]["bytes"]["nonlib_frequency_weighted"]

        matching_entry.matched_percent_unweighted = entry_dict["matched"]["percent"]["unweighted"]
        matching_entry.matched_percent_score_weighted = entry_dict["matched"]["percent"]["score_weighted"]
        matching_entry.matched_percent_frequency_weighted = entry_dict["matched"]["percent"]["frequency_weighted"]
        matching_entry.matched_percent_nonlib_unweighted = entry_dict["matched"]["percent"]["nonlib_unweighted"]
        matching_entry.matched_percent_nonlib_score_weighted = entry_dict["matched"]["percent"]["nonlib_score_weighted"]
        matching_entry.matched_percent_nonlib_frequency_weighted = entry_dict["matched"]["percent"]["nonlib_frequency_weighted"]

        return matching_entry

    def __str__(self):
        return "Matched Sample: id({}) family({}) - Matched: {} ({}) - {} ({}) {} ({})".format(
            self.sample_id,
            self.family,
            self.matched_bytes_unweighted,
            self.matched_percent_unweighted,
            self.matched_bytes_score_weighted,
            self.matched_percent_score_weighted,
            self.matched_bytes_frequency_weighted,
            self.matched_percent_frequency_weighted,
        )
