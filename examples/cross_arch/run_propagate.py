"""Match the Lazarus PE to its ARM port by anchors plus call-graph propagation.

Reports each hand-verified pair as matched correctly, matched to something else, or left
unmatched, then how many functions the same procedure pairs up between samples that share no
code, which is the number that says whether a match count means anything.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from controls import background_sets, prepare  # noqa: E402
from load import load  # noqa: E402
from propagate import match  # noqa: E402
from score import compare  # noqa: E402
from truth import LOOSE, STRICT  # noqa: E402

PE = "91dcf7d4b28e88f8059f39f68d9a8b22"
ELF = "24f61120946ddac5e1d15cd64c48b7e6"


REACH = 3


def run(left, right, background=(), drop_below=0, reach=REACH):
    _, _, lfeats, _, lcalls = left
    _, _, rfeats, _, rcalls = right
    table, _, _ = compare(lfeats, rfeats, lcalls, rcalls, background=background, drop_below=drop_below, reach=reach)
    return match(lfeats, rfeats, lcalls, rcalls, table, background=background, drop_below=drop_below, reach=reach)


def report_truth(matched):
    print("%-10s %-10s %-12s %s" % ("pe", "elf", "result", "how"))
    counts = {"correct": 0, "wrong": 0, "unmatched": 0}
    for pe_off, el_off in sorted(STRICT.items()):
        if pe_off not in matched:
            result, how = "unmatched", ""
        else:
            got, how = matched[pe_off]
            result = "correct" if got == el_off else "wrong (%s)" % hex(got)
        counts[result.split()[0]] += 1
        print("%-10s %-10s %-12s %s" % (hex(pe_off), hex(el_off), result, how))
    print("\ncorrect %d/%d, wrong %d, unmatched %d" % (counts["correct"], len(STRICT), counts["wrong"], counts["unmatched"]))
    print("\n-- same role, different implementation --")
    for pe_off, el_off in sorted(LOOSE.items()):
        got = matched.get(pe_off)
        print("%-10s %-10s %s" % (hex(pe_off), hex(el_off), "unmatched" if got is None else "%s %s" % (hex(got[0]), got[1])))


def main():
    drop_below, reach = 0, REACH
    for arg in sys.argv[1:]:
        if arg.startswith("--drop="):
            drop_below = int(arg.split("=", 1)[1], 0)
        if arg.startswith("--reach="):
            reach = int(arg.split("=", 1)[1])
    lazarus_pe, lazarus_elf = load(PE), load(ELF)
    matched = run(lazarus_pe, lazarus_elf, drop_below=drop_below, reach=reach)
    anchors = sum(1 for _, how in matched.values() if how == "anchor")
    print("constants below %#x dropped, imports reached %d calls deep; %d pairs matched, %d of them anchors\n" % (drop_below, reach, len(matched), anchors))
    report_truth(matched)

    print("\n-- matches between samples, with the other samples as background --")
    mirai_x86, mirai_arm = prepare("mirai_i386_xored"), prepare("mirai_arm_xored")
    cutwail, bashlite = prepare("cutwail_xored"), prepare("bashlite_xored")
    everything = [lazarus_pe, lazarus_elf, mirai_x86, mirai_arm, cutwail, bashlite]
    bg = background_sets(everything)
    for label, left, right in (
        ("lazarus PE vs lazarus ARM ELF", lazarus_pe, lazarus_elf),
        ("mirai i386 vs mirai arm", mirai_x86, mirai_arm),
        ("lazarus PE vs mirai arm", lazarus_pe, mirai_arm),
        ("cutwail PE vs lazarus ARM ELF", cutwail, lazarus_elf),
        ("cutwail PE vs mirai arm", cutwail, mirai_arm),
        ("mirai i386 vs lazarus ARM ELF", mirai_x86, lazarus_elf),
        ("bashlite x64 vs lazarus ARM ELF", bashlite, lazarus_elf),
    ):
        pairs = run(left, right, background=bg, drop_below=drop_below, reach=reach)
        anchors = sum(1 for _, how in pairs.values() if how == "anchor")
        print("%-34s matched %3d  (anchors %2d, propagated %3d)" % (label, len(pairs), anchors, len(pairs) - anchors))


if __name__ == "__main__":
    main()
