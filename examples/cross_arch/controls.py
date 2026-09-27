"""Controls: does the neutral-feature score separate a real port from unrelated code?

Positive control: Mirai built for i386 and for ARM from one source tree - the same program across
the same architecture gap as the Lazarus pair, but with far more shared surface.
Negative controls: samples with no common ancestry, which must not score like a port.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import statistics  # noqa: E402

from load import load  # noqa: E402
from score import compare  # noqa: E402
from smda.Disassembler import Disassembler  # noqa: E402
from smda.SmdaConfig import SmdaConfig  # noqa: E402

# The controls are smda's own xored test fixtures; point this at a checkout's tests/ directory.
FIXTURES = os.environ.get("SMDA_FIXTURES", os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures"))
CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")


def fixture(name):
    """tests/*_xored fixtures are stored xored with (index % 256)."""
    raw = open(os.path.join(FIXTURES, name), "rb").read()
    return bytes(b ^ (i % 256) for i, b in enumerate(raw))


def disassemble(name, data):
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, name + ".smda")
    if not os.path.exists(path):
        tmp = os.path.join(CACHE, name + ".bin")
        with open(tmp, "wb") as fh:
            fh.write(data)
        report = Disassembler(SmdaConfig()).disassembleFile(tmp)
        with open(path, "w") as fh:
            json.dump(report.toDict(), fh)
    from smda.common.SmdaReport import SmdaReport

    return SmdaReport.fromFile(path)


def prepare(name):
    data = fixture(name)
    report = disassemble(name, data)
    return load(name, data=data, report=report)


def background_sets(samples):
    from score import token_sets, with_callees

    return [with_callees(token_sets(s[2]), s[4]) for s in samples]


def summarize(label, left, right, background=(), drop_below=0):
    _, _, lfeats, _, lcalls = left
    _, _, rfeats, _, rcalls = right
    table, lsets, rsets = compare(lfeats, rfeats, lcalls, rcalls, background=background, drop_below=drop_below)
    bests = sorted((row[0][0] for row in table.values() if row), reverse=True)
    if not bests:
        print("%-34s no comparable functions" % label)
        return
    strong = [b for b in bests if b >= 30]
    print(
        "%-34s pairs %4dx%-4d  best %5.1f  top10 mean %5.1f  median best %5.1f  >=30: %d"
        % (label, len(lsets), len(rsets), bests[0], statistics.mean(bests[:10]), statistics.median(bests), len(strong))
    )


def main():
    lazarus_pe = load("91dcf7d4b28e88f8059f39f68d9a8b22")
    lazarus_elf = load("24f61120946ddac5e1d15cd64c48b7e6")
    mirai_x86 = prepare("mirai_i386_xored")
    mirai_arm = prepare("mirai_arm_xored")
    cutwail = prepare("cutwail_xored")
    bashlite = prepare("bashlite_xored")

    everything = [lazarus_pe, lazarus_elf, mirai_x86, mirai_arm, cutwail, bashlite]
    bg = background_sets(everything)

    variants = (
        ("all tokens", {}),
        ("dropping constants below 0x20", {"drop_below": 0x20}),
        ("dropping constants below 0x100", {"drop_below": 0x100}),
    )
    for title, opts in variants:
        weighting = bg
        print("\n==== %s ====" % title)
        print("\n-- positive controls (same program) --")
        summarize("mirai i386 vs mirai arm", mirai_x86, mirai_arm, weighting, **opts)
        summarize("lazarus PE vs lazarus ARM ELF", lazarus_pe, lazarus_elf, weighting, **opts)
        print("\n-- negative controls (unrelated code) --")
        summarize("lazarus PE vs mirai arm", lazarus_pe, mirai_arm, weighting, **opts)
        summarize("cutwail PE vs lazarus ARM ELF", cutwail, lazarus_elf, weighting, **opts)
        summarize("cutwail PE vs mirai arm", cutwail, mirai_arm, weighting, **opts)
        summarize("mirai i386 vs lazarus ARM ELF", mirai_x86, lazarus_elf, weighting, **opts)
        summarize("bashlite x64 vs lazarus ARM ELF", bashlite, lazarus_elf, weighting, **opts)


if __name__ == "__main__":
    main()
