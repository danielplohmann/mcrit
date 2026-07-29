#!/usr/bin/python

import unittest

from smda.aarch64.AArch64InstructionEscaper import AArch64InstructionEscaper
from smda.cil.CilInstructionEscaper import CilInstructionEscaper
from smda.common.SmdaFunction import SmdaFunction
from smda.dalvik.DalvikInstructionEscaper import DalvikInstructionEscaper
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper


class EscaperDispatchTestSuite(unittest.TestCase):
    """Ensure the architecture -> Escaper dispatch is wired correctly and stays that way."""

    def test_intel(self):
        self.assertIs(SmdaFunction.getInstructionEscaper("intel"), IntelInstructionEscaper)

    def test_aarch64(self):
        self.assertIs(SmdaFunction.getInstructionEscaper("aarch64"), AArch64InstructionEscaper)

    def test_cil(self):
        self.assertIs(SmdaFunction.getInstructionEscaper("cil"), CilInstructionEscaper)

    def test_dalvik(self):
        self.assertIs(SmdaFunction.getInstructionEscaper("dalvik"), DalvikInstructionEscaper)

    def test_unknown_architecture_has_no_escaper(self):
        self.assertIsNone(SmdaFunction.getInstructionEscaper("does-not-exist"))


if __name__ == "__main__":
    unittest.main()
