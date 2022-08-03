from typing import Dict, List, Optional

from mcrit.storage.SampleEntry import SampleEntry


class FamilyEntry(object):

    family_id: int
    family_name: str
    num_samples: int
    num_functions: int
    num_library_samples: int
    # This is not supposed to be stored in storage
    samples: Optional[Dict[int, SampleEntry]]

    def __init__(self, family_name="", family_id=0, num_samples=0, num_functions=0, num_library_samples=0, samples=None):
        self.family_id = family_id
        self.family_name = family_name
        self.num_samples = num_samples
        self.num_functions = num_functions
        self.num_library_samples = num_library_samples 
        self.samples = samples

    @property
    def is_library(self):
        return self.num_library_samples > 0

    @property
    def family(self):
        return self.family_name

    def toDict(self):
        family_entry = {
            "family_id": self.family_id,
            "family_name": self.family_name,
            "num_samples": self.num_samples,
            "num_functions": self.num_functions,
            "num_library_samples": self.num_library_samples,
        }
        if self.samples is not None:
            family_entry["samples"] = {id: sample.toDict() for id, sample in self.samples.items()}
        return family_entry

    @classmethod
    def fromDict(cls, entry_dict: Dict):
        family_entry = cls(None) #type: ignore
        family_entry.family_id = entry_dict["family_id"]
        family_entry.family_name = entry_dict["family_name"]
        family_entry.num_samples = entry_dict["num_samples"]
        family_entry.num_functions = entry_dict["num_functions"]
        family_entry.num_library_samples = entry_dict["num_library_samples"]
        samples = entry_dict.get("samples", None)
        if samples is not None:
            family_entry.samples = {id: SampleEntry.fromDict(sample) for id, sample in samples.items()}
        return family_entry

    def __str__(self):
        return "Famliy {} ({}): ".format(
            self.family_id, self.family_name
        )

