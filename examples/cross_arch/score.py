"""Score architecture-neutral feature sets between two binaries.

Each function is a set of tokens that survive recompilation for another instruction set:
constants, referenced strings, and OS calls mapped to a shared concept name. Functions are
compared by IDF-weighted cosine over those sets, so a token shared by many functions counts
for little and a rare one (a protocol constant, a distinctive string) counts for a lot.
"""

import math
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TRIVIAL = {"const:0x0", "const:0x1", "const:0x2", "const:0x3", "const:0x4", "const:0xffffffff"}
MIN_TOKENS = 2


def _keep(token, drop_below):
    if token in TRIVIAL:
        return False
    if drop_below and token.startswith("const:"):
        value = int(token[6:], 16)
        if value >= 0x80000000:
            value -= 1 << 32
        return abs(value) >= drop_below
    return True


def token_sets(feats, drop_below=0):
    return {off: frozenset(t for t in toks if _keep(t, drop_below)) for off, toks in feats.items()}


def with_callees(sets, calls):
    """Add each function's callees' tokens in a namespace of their own.

    What a function does is partly what it delegates: the routine that frames a record calls the
    one that writes bytes to the socket. Keeping the borrowed tokens under their own prefix lets
    them corroborate a pair without drowning out what the function itself references."""
    out = {}
    for off, toks in sets.items():
        borrowed = set()
        for callee in calls.get(off, ()):
            borrowed.update("via:" + t for t in sets.get(callee, ()))
        out[off] = frozenset(toks | borrowed)
    return out


def with_reach(sets, base, calls, depth):
    """Add the imports reachable within ``depth`` calls, in a namespace of their own.

    A port keeps which way data flows: the routine that frames an outgoing record ends in a
    socket write two or three calls down, its receiving twin in a read, while the two share
    every protocol constant. Only import tokens travel this far; constants two calls away say
    little about the caller."""
    out = {}
    for off, toks in sets.items():
        reached, frontier, seen = set(), set(calls.get(off, ())), {off}
        for _ in range(depth):
            frontier -= seen
            seen |= frontier
            for callee in frontier:
                reached.update("reach:" + t for t in base.get(callee, ()) if t.startswith("api:"))
            frontier = {n for callee in frontier for n in calls.get(callee, ())}
        out[off] = frozenset(toks | reached)
    return out


def idf(*token_set_dicts):
    df = Counter()
    total = 0
    for sets in token_set_dicts:
        for toks in sets.values():
            total += 1
            df.update(toks)
    return {t: math.log(total / n) for t, n in df.items()}


def norms(sets, weights):
    return {off: math.sqrt(sum(weights.get(t, 0.0) ** 2 for t in toks)) for off, toks in sets.items()}


def score(a, b, weights, na, nb):
    if not na or not nb:
        return 0.0
    shared = sum(weights.get(t, 0.0) ** 2 for t in a & b)
    return 100.0 * shared / (na * nb)


def compare(left, right, left_calls=None, right_calls=None, background=(), drop_below=0, reach=0):
    """Score every function of `left` against every function of `right`.

    `background` is other samples' token sets, used only to weight tokens. Two programs that both
    speak to a socket share `api:socket` and `const:0x100` whatever their ancestry, so weighting
    on the compared pair alone makes generic code look related. Counting those tokens across
    unrelated samples is what makes a rare one - a protocol constant, an odd buffer size - carry
    the score."""
    lsets, rsets = token_sets(left, drop_below), token_sets(right, drop_below)
    if left_calls is not None:
        lbase, rbase = lsets, rsets
        lsets, rsets = with_callees(lbase, left_calls), with_callees(rbase, right_calls)
        if reach:
            lsets, rsets = with_reach(lsets, lbase, left_calls, reach), with_reach(rsets, rbase, right_calls, reach)
    lsets = {o: t for o, t in lsets.items() if len(t) >= MIN_TOKENS}
    rsets = {o: t for o, t in rsets.items() if len(t) >= MIN_TOKENS}
    weights = idf(lsets, rsets, *background)
    ln, rn = norms(lsets, weights), norms(rsets, weights)
    table = {}
    for lo, lt in lsets.items():
        row = sorted(((score(lt, rt, weights, ln[lo], rn[ro]), ro) for ro, rt in rsets.items()), reverse=True)
        table[lo] = row
    return table, lsets, rsets
