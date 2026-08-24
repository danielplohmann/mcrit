#!/usr/bin/env python3
"""A stable fingerprint of smda's observable escaping behaviour.

MinHashes are derived from smda's *escaped* instruction representation: the shinglers build their
tokens from `SmdaInstruction.getMnemonicGroup()` and `SmdaInstruction.getEscapedOperands()`. That
makes the escaper as much an input to a minhash as MINHASH_SEED is - but unlike the seed it lives
in a separate, independently versioned package, and it is not covered by any config hash. When
smda changes how it escapes, previously stored minhashes silently stop being comparable to newly
computed ones: they remain valid-looking and still match each other, while identical code
submitted afterwards no longer finds them.

smda 4.4.5 is the worked example. It corrected three escaper classifications - most notably it
stopped escaping segment-qualified memory operands (`gs:[0x60]`, `fs:[0x30]`, `es:[edi]`) as
CONST - which changed roughly a fifth of the minhashes on a real corpus, with a small share of
functions losing every LSH band and becoming unretrievable. The change was correct; the problem is
that nothing announced it.

This module runs the escaper over a fixed, committed probe of instructions chosen to exercise the
operand and mnemonic classes escaping actually distinguishes, and hashes the result. Comparing the
fingerprint across smda versions turns "escaping changed" from an invisible condition into a
value that can be recorded, exported and compared.

The probe deliberately depends on as little of smda as possible: `SmdaInstruction` is constructed
directly from four-field lists (offset, bytes, mnemonic, operands), so no report, binary or
disassembly is needed and the fingerprint is computable at import time.
"""

import hashlib
import logging
from typing import Dict, List, Sequence

from smda.common.SmdaFunction import SmdaFunction
from smda.common.SmdaInstruction import SmdaInstruction

LOGGER = logging.getLogger(__name__)

# returned instead of a hash when the running smda does not expose an escaper we can drive;
# this is a diagnostic, so it degrades to "unknown" rather than breaking a status call
FINGERPRINT_UNAVAILABLE = "unavailable"

# Probe instructions as [offset, bytes, mnemonic, operands], the same four-field form used in
# serialized SMDA functions. Chosen to cover the classes escaping distinguishes; the byte fields
# are realistic so that byte-level escaping (jump/call targets, ptr refs, immediates) also runs.
# Only "intel" is probed for now - MCRIT corpora are x86-dominated and the 4.4.5 regression was
# x86-only. An escaper change touching other architectures would go unnoticed here; extend this
# mapping deliberately if non-x86 corpora start mattering.
# Adding entries changes the fingerprint, so only extend this at a deliberate version boundary.
ESCAPER_PROBE_INSTRUCTIONS: Dict[str, List[List]] = {
    "intel": [
        # plain registers across widths
        [0x401000, "4053", "push", "rbx"],
        [0x401002, "89c8", "mov", "eax, ecx"],
        [0x401004, "6689c8", "mov", "ax, cx"],
        [0x401007, "88c4", "mov", "ah, al"],
        # segment-qualified memory operands: the class 4.4.5 reclassified
        [0x401009, "65488b042560000000", "mov", "rax, qword ptr gs:[0x60]"],
        [0x401012, "64a130000000", "mov", "eax, dword ptr fs:[0x30]"],
        [0x401018, "648b0d00000000", "mov", "ecx, dword ptr fs:[0]"],
        [0x40101F, "65488b042528000000", "mov", "rax, qword ptr gs:[0x28]"],
        [0x401028, "268b07", "mov", "eax, dword ptr es:[edi]"],
        [0x40102B, "268a07", "mov", "al, byte ptr es:[edi]"],
        # a true far pointer: seg:off with no memory operand
        [0x40102E, "ea0010400033", "jmp", "0x33:0x401000"],
        # absolute and rip-relative pointer references
        [0x401034, "8b0d00104000", "mov", "ecx, dword ptr [0x401000]"],
        [0x40103A, "488b0d34120000", "mov", "rcx, qword ptr [rip + 0x1234]"],
        [0x401041, "488b0dccedffff", "mov", "rcx, qword ptr [rip - 0x1234]"],
        # complex effective addresses
        [0x401048, "8b448820", "mov", "eax, dword ptr [eax + ecx*4 + 0x20]"],
        [0x40104C, "8d0c8500000000", "lea", "ecx, [eax*4]"],
        # immediates, small and wide
        [0x401053, "b801000000", "mov", "eax, 1"],
        [0x401058, "b800104000", "mov", "eax, 0x401000"],
        [0x40105D, "48b8efcdab8967452301", "movabs", "rax, 0x123456789abcdef"],
        # vector file, including the AVX-512 range and mask registers 4.4.5 widened
        [0x401067, "0f28c1", "movaps", "xmm0, xmm1"],
        [0x40106A, "c5f428c1", "vmovaps", "ymm0, ymm1"],
        [0x40106E, "62f17c48280d00000000", "vmovaps", "zmm1, zmm2"],
        [0x401078, "62f17c4928c1", "vmovaps", "zmm0 {k1}, zmm1"],
        [0x40107E, "62f17cc928c1", "vmovaps", "zmm0 {k1} {z}, zmm1"],
        [0x401084, "62f17c48284d00", "vmovaps", "xmm17, xmm18"],
        [0x40108B, "c5f841c9", "kandw", "k1, k2, k3"],
        # string, stack, privileged and BMI mnemonics whose grouping 4.4.5 corrected
        [0x40108F, "f348a5", "rep movsq", "qword ptr es:[rdi], qword ptr [rsi]"],
        [0x401092, "f348a7", "repe cmpsq", "qword ptr [rsi], qword ptr es:[rdi]"],
        [0x401095, "6660", "pushaw", ""],
        [0x401097, "6661", "popaw", ""],
        [0x401099, "0f01d0", "xgetbv", ""],
        [0x40109C, "0f01d1", "xsetbv", ""],
        [0x40109F, "c4e37bf0c108", "rorx", "eax, ecx, 8"],
        [0x4010A5, "c4e262f7c1", "sarx", "eax, ecx, edx"],
        # control, debug and segment registers
        [0x4010AA, "0f20c0", "mov", "eax, cr0"],
        [0x4010AD, "0f21f8", "mov", "eax, dr7"],
        [0x4010B0, "8cc0", "mov", "eax, es"],
        # control flow: intraprocedural and outbound
        [0x4010B2, "e809000000", "call", "0x4010c0"],
        [0x4010B7, "eb05", "jmp", "0x4010be"],
        [0x4010B9, "0f8505000000", "jne", "0x4010c4"],
        [0x4010BF, "ff1500204000", "call", "qword ptr [rip + 0x2000]"],
        [0x4010C5, "c3", "ret", ""],
    ]
}


def getEscapedProbe(architecture: str = "intel") -> List[str]:
    """Escape the probe instructions exactly as EscapedBlockShingler does, one line each."""
    instructions = ESCAPER_PROBE_INSTRUCTIONS.get(architecture)
    if not instructions:
        raise ValueError("no escaper probe defined for architecture: %s" % architecture)
    # resolving the escaper this way predates smda 4.2.13 only; MCRIT requires >= 4.2.13
    escaper = SmdaFunction.getInstructionEscaper(architecture)
    escaped = []
    for instruction_list in instructions:
        instruction = SmdaInstruction(instruction_list)
        escaped.append("%s %s" % (instruction.getMnemonicGroup(escaper), instruction.getEscapedOperands(escaper)))
    return escaped


def getEscaperFingerprints(architectures: Sequence[str] = ("intel",)) -> Dict[str, str]:
    """Per-architecture fingerprints - the shape that gets persisted in exports and status.

    A mapping rather than a combined hash, and deliberately so: the value is *stored*, so a
    later widening of the default probe (adding an aarch64 entry, say) must not change what is
    recorded for the architectures already covered. A combined hash would flip for everyone the
    moment the tuple grows, making every export produced before that point mismatch on import
    even though intel escaping never changed - and false positives are the one failure mode a
    diagnostic cannot afford, because they teach operators to ignore it.
    """
    fingerprints = {}
    for architecture in architectures:
        hasher = hashlib.sha256()
        try:
            hasher.update(("[%s]\n" % architecture).encode("utf-8"))
            for line in getEscapedProbe(architecture):
                hasher.update((line + "\n").encode("utf-8"))
        except Exception as exc:
            LOGGER.warning("Could not compute escaper fingerprint for %s (smda too old or API changed): %s", architecture, exc)
            fingerprints[architecture] = FINGERPRINT_UNAVAILABLE
        else:
            fingerprints[architecture] = hasher.hexdigest()[:16]
    return fingerprints


def getEscaperFingerprint(architectures: Sequence[str] = ("intel",)) -> str:
    """A short, stable hash of how the running smda escapes the probe.

    Any change to mnemonic grouping or operand escaping that touches the probe changes this value.
    It says nothing about *how* escaping changed, only that stored minhashes computed under a
    different fingerprint are no longer comparable to freshly computed ones.

    Convenience form over getEscaperFingerprints; for a single architecture both agree, which is
    what MCRIT ships today. Persistence should prefer the per-architecture mapping.
    """
    fingerprints = getEscaperFingerprints(architectures)
    if FINGERPRINT_UNAVAILABLE in fingerprints.values():
        return FINGERPRINT_UNAVAILABLE
    return fingerprints[sorted(fingerprints)[0]] if len(fingerprints) == 1 else _combineFingerprints(fingerprints)


def _combineFingerprints(fingerprints: Dict[str, str]) -> str:
    hasher = hashlib.sha256()
    for architecture in sorted(fingerprints):
        hasher.update(("%s:%s\n" % (architecture, fingerprints[architecture])).encode("utf-8"))
    return hasher.hexdigest()[:16]
