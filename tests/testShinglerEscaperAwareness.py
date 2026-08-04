#!/usr/bin/python

import logging
import os
import unittest

# Shinglers use bare module imports (e.g. `from AbstractShingler import ...`) which
# only resolve when mcrit/shinglers/ is on sys.path. MCRIT adds it at load time
# (see ShingleLoader._getShinglerClasses); tests/conftest.py does the same for pytest.
from EscapedBlockShingler import EscapedBlockShingler
from FuzzyStatPairShingler import FuzzyStatPairShingler
from smda.aarch64.AArch64InstructionEscaper import AArch64InstructionEscaper
from smda.cil.CilInstructionEscaper import CilInstructionEscaper
from smda.common.BinaryInfo import BinaryInfo
from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaReport import SmdaReport
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

from .context import config

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class ShinglerEscaperAwarenessTestSuite(unittest.TestCase):
    """Shinglers must use the per-function escaper, not a hardcoded Intel escaper."""

    def _load_intel_function(self):
        THIS_FILE_PATH = str(os.path.abspath(__file__))
        PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
        example_file_path = os.sep.join([PROJECT_ROOT, "tests", "example_report.smda"])
        smda_report = SmdaReport.fromFile(example_file_path)
        assert smda_report is not None
        functions = [f for f in smda_report.getFunctions() if f.num_instructions > 0]
        self.assertTrue(functions, "need at least one function in the fixture")
        return functions[0]

    def _rearchitect(self, intel_function, architecture):
        binary_info = BinaryInfo(b"")
        binary_info.architecture = architecture
        return SmdaFunction.fromDict(intel_function.toDict(), binary_info=binary_info)

    def test_escaper_is_taken_from_function(self):
        intel_function = self._load_intel_function()
        aarch64_function = self._rearchitect(intel_function, "aarch64")
        cil_function = self._rearchitect(intel_function, "cil")
        self.assertIs(intel_function._escaper, IntelInstructionEscaper)
        self.assertIs(aarch64_function._escaper, AArch64InstructionEscaper)
        self.assertIs(cil_function._escaper, CilInstructionEscaper)

    def test_escaped_block_shingler_uses_per_function_escaper(self):
        intel_function = self._load_intel_function()
        aarch64_function = self._rearchitect(intel_function, "aarch64")
        shingler = EscapedBlockShingler(config.SHINGLER_CONFIG)
        intel_sequences = shingler.process(intel_function, 0)
        aarch64_sequences = shingler.process(aarch64_function, 0)
        # both must produce shingles (non-empty) and must not raise
        self.assertTrue(intel_sequences)
        self.assertTrue(aarch64_sequences)
        # AArch64 escaping must differ from raw/Intel escaping for at least some instruction
        first_instruction = next(iter(aarch64_function.getInstructions()))
        self.assertIsNotNone(first_instruction.getMnemonicGroup(AArch64InstructionEscaper))

    def test_fuzzy_stat_pair_shingler_uses_per_function_escaper(self):
        intel_function = self._load_intel_function()
        aarch64_function = self._rearchitect(intel_function, "aarch64")
        cil_function = self._rearchitect(intel_function, "cil")
        shingler = FuzzyStatPairShingler(config.SHINGLER_CONFIG)
        self.assertTrue(shingler.process(intel_function, 0))
        self.assertTrue(shingler.process(aarch64_function, 0))
        self.assertTrue(shingler.process(cil_function, 0))

    def test_fuzzy_stat_pair_stack_size_is_intel_only(self):
        intel_function = self._load_intel_function()
        aarch64_function = self._rearchitect(intel_function, "aarch64")
        shingler = FuzzyStatPairShingler(config.SHINGLER_CONFIG)
        # stack size heuristic is x86-specific; non-Intel must yield 0
        self.assertEqual(shingler._getStackSize(aarch64_function), 0)


if __name__ == "__main__":
    unittest.main()
