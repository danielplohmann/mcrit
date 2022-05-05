from dataclasses import dataclass
import datetime
from typing import Dict, TYPE_CHECKING

if TYPE_CHECKING: # pragma: no cover
    from smda.common.SmdaReport import SmdaReport

#@dataclass
class SampleEntry(object):

    family_id: int
    sample_id: int
    architecture: str
    base_addr: int
    binary_size: int
    binweight: float
    bitness: int
    component: str
    family: str
    version: str
    is_library: bool
    filename: str
    sha256: str
    smda_version: str
    summary: None
    statistics: Dict[str, int]
    timestamp: datetime.datetime

    # TODO -> rename to fromSmdaReport
    def __init__(self, smda_report: "SmdaReport", sample_id=-1, family_id=0):
        self.sample_id = sample_id
        self.family_id = family_id
        if smda_report:
            self.architecture = smda_report.architecture
            self.base_addr = smda_report.base_addr
            self.binary_size = smda_report.binary_size
            self.binweight = smda_report.binweight
            self.bitness = smda_report.bitness
            self.component = smda_report.component
            self.family = smda_report.family
            self.filename = smda_report.filename
            self.is_library = smda_report.is_library
            self.sha256 = smda_report.sha256
            self.smda_version = smda_report.smda_version
            self.statistics = smda_report.statistics.toDict()
            self.timestamp = smda_report.timestamp
            self.version = smda_report.version

    def getShortSha256(self, prefix=8, border=0):
        if border > 0:
            return self.sha256[:border] + "..." + self.sha256[-border:]
        elif prefix > 0:
            return self.sha256[:prefix]
        return self.sha256

    def getShortFilename(self, size_visible=20):
        if len(self.filename) > 2 * size_visible:
            return self.filename[:size_visible] + "..." + self.filename[-size_visible:]
        return self.filename


    def toDict(self):
        sample_entry = {
            "architecture": self.architecture,
            "base_addr": self.base_addr,
            "binary_size": self.binary_size,
            "binweight": self.binweight,
            "bitness": self.bitness,
            "component": self.component,
            "family_id": self.family_id,
            "family": self.family,
            "filename": self.filename,
            "is_library": self.is_library,
            "sample_id": self.sample_id,
            "sha256": self.sha256,
            "smda_version": self.smda_version,
            "statistics": self.statistics,
            "timestamp": self.timestamp.strftime("%Y-%m-%dT%H-%M-%S"),
            "version": self.version,
        }
        return sample_entry

    @classmethod
    def fromDict(cls, entry_dict):
        sample_entry = cls(None) #type: ignore
        sample_entry.family_id = entry_dict["family_id"]
        sample_entry.sample_id = entry_dict["sample_id"]
        sample_entry.architecture = entry_dict["architecture"]
        sample_entry.base_addr = entry_dict["base_addr"]
        sample_entry.binary_size = entry_dict["binary_size"]
        sample_entry.binweight = entry_dict["binweight"]
        sample_entry.bitness = entry_dict["bitness"]
        sample_entry.component = entry_dict["component"]
        sample_entry.family = entry_dict["family"]
        sample_entry.version = entry_dict["version"]
        sample_entry.is_library = entry_dict["is_library"]
        sample_entry.filename = entry_dict["filename"]
        sample_entry.sha256 = entry_dict["sha256"]
        sample_entry.smda_version = entry_dict["smda_version"]
        sample_entry.statistics = entry_dict["statistics"]
        sample_entry.timestamp = datetime.datetime.strptime(entry_dict["timestamp"], "%Y-%m-%dT%H-%M-%S")
        return sample_entry

    @classmethod
    def fromAlchemySample(cls, sample):
        sample_entry = cls(None) #type:ignore
        sample_entry.sample_id = sample.id
        sample_entry.family_id = sample.family.id
        sample_entry.family = sample.family.name
        sample_entry.architecture = sample.architecture.name
        sample_entry.base_addr = sample.base_addr
        sample_entry.binary_size = sample.binary_size
        sample_entry.component = sample.component
        sample_entry.binweight = sample.binweight
        sample_entry.bitness = sample.bitness.name
        sample_entry.version = sample.version
        sample_entry.is_library = sample.is_library
        sample_entry.filename = sample.filename
        sample_entry.sha256 = sample.sha256
        sample_entry.smda_version = sample.smda_version
        sample_entry.statistics = sample.statistics
        sample_entry.timestamp = sample.timestamp
        return sample_entry

    def __str__(self):
        return "Sample {} ({}, {} bit) - {} ({}): ".format(
            self.sample_id, self.architecture, self.bitness, self.filename, self.family
        )
