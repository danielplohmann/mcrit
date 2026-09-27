"""Report neutral-feature scores between two samples, against the hand-verified pairs."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from load import load  # noqa: E402
from score import compare  # noqa: E402

PE = "91dcf7d4b28e88f8059f39f68d9a8b22"
ELF = "24f61120946ddac5e1d15cd64c48b7e6"


def main():
    expand = "--flat" not in sys.argv
    drop_below = 0
    for arg in sys.argv[1:]:
        if arg.startswith("--drop="):
            drop_below = int(arg.split("=", 1)[1], 0)
    pe_rep, _, pe_feats, _, pe_calls = load(PE)
    el_rep, _, el_feats, _, el_calls = load(ELF)
    if expand:
        table, lsets, rsets = compare(pe_feats, el_feats, pe_calls, el_calls, drop_below=drop_below)
    else:
        table, lsets, rsets = compare(pe_feats, el_feats, drop_below=drop_below)
    print("callee tokens: %s   constants below %#x dropped" % ("on" if expand else "off", drop_below))
    print("scored functions: PE %d, ELF %d" % (len(lsets), len(rsets)))

    from truth import LOOSE, STRICT

    print("\n-- hand-verified pairs (PE -> ELF) --")
    print("%-10s %-10s %7s %7s %7s" % ("pe", "elf", "score", "rank", "best"))
    ranks = []
    for pe_off, el_off in sorted(STRICT.items()):
        row = table.get(pe_off)
        if row is None:
            print("%-10s %-10s  not scored (too few tokens)" % (hex(pe_off), hex(el_off)))
            continue
        by_off = {ro: s for s, ro in row}
        if el_off not in by_off:
            print("%-10s %-10s  target not scored" % (hex(pe_off), hex(el_off)))
            continue
        s = by_off[el_off]
        rank = 1 + sum(1 for other, v in by_off.items() if v > s)
        ranks.append((rank, s))
        print("%-10s %-10s %7.1f %7d %7.1f" % (hex(pe_off), hex(el_off), s, rank, row[0][0]))

    if ranks:
        top1 = sum(1 for r, _ in ranks if r == 1)
        top5 = sum(1 for r, _ in ranks if r <= 5)
        print("\ntop-1: %d/%d   top-5: %d/%d   median rank: %d" % (top1, len(ranks), top5, len(ranks), sorted(r for r, _ in ranks)[len(ranks) // 2]))

    print("\n-- same role, different implementation --")
    for pe_off, el_off in sorted(LOOSE.items()):
        row = table.get(pe_off)
        if row is None:
            continue
        by_off = {ro: s for s, ro in row}
        if el_off in by_off:
            s = by_off[el_off]
            rank = 1 + sum(1 for v in by_off.values() if v > s)
            print("%-10s %-10s %7.1f %7d" % (hex(pe_off), hex(el_off), s, rank))

    print("\n-- highest-scoring pairs overall --")
    flat = sorted(((row[0][0], lo, row[0][1]) for lo, row in table.items() if row), reverse=True)
    truth = set(STRICT.items())
    for s, lo, ro in flat[:20]:
        mark = "  <-- correct" if (lo, ro) in truth else ""
        print("%7.1f  pe %-10s elf %-10s%s" % (s, hex(lo), hex(ro), mark))


if __name__ == "__main__":
    main()
