#!/usr/bin/python

import logging
import unittest

from smda.common.SmdaFunction import SmdaFunction

from mcrit.minhash.EscaperFingerprint import (
    ESCAPER_PROBE_INSTRUCTIONS,
    FINGERPRINT_UNAVAILABLE,
    getEscapedProbe,
    getEscaperFingerprint,
)

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
logging.disable(logging.CRITICAL)


class EscaperFingerprintTestSuite(unittest.TestCase):
    """MinHashes are only comparable across functions escaped by the same smda, so the escaper's
    observable behaviour needs to be expressible as a value that can be compared."""

    def testFingerprintIsDeterministic(self):
        self.assertEqual(getEscaperFingerprint(), getEscaperFingerprint())

    def testFingerprintIsAvailableForSupportedSmda(self):
        # MCRIT requires smda >= 4.2.13, which exposes SmdaFunction.getInstructionEscaper
        self.assertTrue(hasattr(SmdaFunction, "getInstructionEscaper"))
        self.assertNotEqual(FINGERPRINT_UNAVAILABLE, getEscaperFingerprint())

    def testFingerprintIsShortAndHexadecimal(self):
        fingerprint = getEscaperFingerprint()
        self.assertEqual(16, len(fingerprint))
        int(fingerprint, 16)

    def testProbeCoversEveryInstruction(self):
        escaped = getEscapedProbe("intel")
        self.assertEqual(len(ESCAPER_PROBE_INSTRUCTIONS["intel"]), len(escaped))
        self.assertTrue(all(line.strip() for line in escaped))

    def testUnknownArchitectureIsRejected(self):
        with self.assertRaises(ValueError):
            getEscapedProbe("not-an-architecture")

    def testFingerprintIsUnavailableWhenEscaperCannotBeResolved(self):
        # smda releases before 4.2.13 have no getInstructionEscaper; the fingerprint is a
        # diagnostic and must degrade instead of breaking callers such as getStatus()
        original = SmdaFunction.getInstructionEscaper
        try:
            del SmdaFunction.getInstructionEscaper
            self.assertEqual(FINGERPRINT_UNAVAILABLE, getEscaperFingerprint())
        finally:
            SmdaFunction.getInstructionEscaper = original

    def testFingerprintReactsToAnEscaperChange(self):
        """The regression this exists to catch: smda 4.4.5 stopped escaping segment-qualified
        memory operands as CONST, which silently changed ~20% of minhashes on a real corpus."""
        baseline = getEscaperFingerprint()
        escaper = SmdaFunction.getInstructionEscaper("intel")
        original = escaper.escapeOperands.__func__ if hasattr(escaper.escapeOperands, "__func__") else escaper.escapeOperands
        try:
            escaper.escapeOperands = staticmethod(lambda instruction: "CHANGED")
            self.assertNotEqual(baseline, getEscaperFingerprint())
        finally:
            escaper.escapeOperands = staticmethod(original)
        self.assertEqual(baseline, getEscaperFingerprint())

    def testProbeExercisesSegmentQualifiedMemoryOperands(self):
        """The probe must keep covering the operand class behind the 4.4.5 change, otherwise the
        fingerprint would not have noticed it."""
        operands = [instruction[3] for instruction in ESCAPER_PROBE_INSTRUCTIONS["intel"]]
        segment_memory = [operand for operand in operands if ":" in operand and "[" in operand]
        self.assertTrue(segment_memory, "probe lost its segment-qualified memory operands")
        far_pointer = [operand for operand in operands if ":" in operand and "[" not in operand]
        self.assertTrue(far_pointer, "probe lost its far-pointer operand")


if __name__ == "__main__":
    unittest.main()
