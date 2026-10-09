from typing import Any, Dict, List

from smda.common.SmdaReport import SmdaReport


class RebuiltSmdaReport:
    """An SMDA report rebuilt from storage (#94), and what of it could not be rebuilt.

    `complete` is False when anything is missing; `incomplete_reasons` says what:
    - "extras_missing": the sample was stored before the report's extras were kept, so the
      top-level fields SampleEntry holds no field for (code_areas, xdata_refs_from/to,
      xmetadata, ...) are an empty report's defaults
    - "disassembly_missing": `num_functions_without_disassembly` functions had no stored xcfg
      (STORAGE_DROP_DISASSEMBLY, or a blob over the 16 MiB document limit) and are absent from
      the report's xcfg
    """

    EXTRAS_MISSING = "extras_missing"
    DISASSEMBLY_MISSING = "disassembly_missing"

    smda_report: SmdaReport
    extras_missing: bool
    num_functions_without_disassembly: int

    def __init__(self, smda_report: SmdaReport, extras_missing: bool = False, num_functions_without_disassembly: int = 0):
        self.smda_report = smda_report
        self.extras_missing = extras_missing
        self.num_functions_without_disassembly = num_functions_without_disassembly

    @property
    def incomplete_reasons(self) -> List[str]:
        reasons = []
        if self.extras_missing:
            reasons.append(self.EXTRAS_MISSING)
        if self.num_functions_without_disassembly:
            reasons.append(self.DISASSEMBLY_MISSING)
        return reasons

    @property
    def complete(self) -> bool:
        return not self.incomplete_reasons

    def toDict(self) -> Dict[str, Any]:
        return {
            "complete": self.complete,
            "incomplete_reasons": self.incomplete_reasons,
            "num_functions_without_disassembly": self.num_functions_without_disassembly,
            "smda_report": self.smda_report.toDict(),
        }

    @classmethod
    def fromDict(cls, entry_dict: Dict[str, Any]) -> "RebuiltSmdaReport":
        smda_report = SmdaReport.fromDict(entry_dict["smda_report"])
        assert smda_report is not None
        return cls(
            smda_report,
            extras_missing=cls.EXTRAS_MISSING in entry_dict["incomplete_reasons"],
            num_functions_without_disassembly=entry_dict["num_functions_without_disassembly"],
        )
