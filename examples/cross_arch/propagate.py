"""Grow a function matching outward from confident pairs along the call graph.

Scoring each function on its own tokens leaves out the small helpers a port keeps but that
reference almost nothing: a loop that fills a buffer with rand() bytes has one import and no
constants. What such a helper does keep is its place in the call graph. Once the routine that
builds the ClientHello is matched on both sides, its unmatched callees on one side can only be
its unmatched callees on the other.

So matching starts from anchors, pairs that are each other's best match by a clear margin, and
then walks outward: for every matched pair, the unmatched callees (and callers) of one side are
paired with those of the other, by token score plus the number of already-matched neighbours
the two share. A pair is taken only when each is the other's single best choice, or when it is
the only unmatched neighbour on both sides.
"""

from collections import defaultdict

from score import MIN_TOKENS, idf, norms, score, token_sets, with_callees, with_reach

ANCHOR_SCORE = 20.0
ANCHOR_MARGIN = 1.25
NEIGHBOUR_BONUS = 10.0
REFINE_ROUNDS = 5
REFINE_CANDIDATES = 5


def _invert(calls):
    callers = defaultdict(set)
    for caller, callees in calls.items():
        for callee in callees:
            callers[callee].add(caller)
    return callers


def _anchors(table, min_score, margin):
    best_right = {}
    for lo, row in table.items():
        for s, ro in row:
            if s > best_right.get(ro, (0.0, None))[0]:
                best_right[ro] = (s, lo)
    anchors = []
    for lo, row in table.items():
        if not row:
            continue
        s, ro = row[0]
        runner_up = row[1][0] if len(row) > 1 else 0.0
        if s >= min_score and s >= margin * runner_up and best_right.get(ro, (0.0, None))[1] == lo:
            anchors.append((s, lo, ro))
    return sorted(anchors, reverse=True)


def match(
    left, right, left_calls, right_calls, table, background=(), drop_below=0, reach=0, anchor_score=ANCHOR_SCORE, anchor_margin=ANCHOR_MARGIN, neighbour_bonus=NEIGHBOUR_BONUS
):
    """Return ``{left offset: (right offset, how)}`` where how is "anchor" or "propagated"."""
    lbase, rbase = token_sets(left, drop_below), token_sets(right, drop_below)
    lsets, rsets = with_callees(lbase, left_calls), with_callees(rbase, right_calls)
    if reach:
        lsets, rsets = with_reach(lsets, lbase, left_calls, reach), with_reach(rsets, rbase, right_calls, reach)
    weights = idf(lsets, rsets, *background)
    lnorm, rnorm = norms(lsets, weights), norms(rsets, weights)

    def pair_score(a, b):
        return score(lsets.get(a, frozenset()), rsets.get(b, frozenset()), weights, lnorm.get(a, 0.0), rnorm.get(b, 0.0))

    relations = (
        ({k: set(v) for k, v in left_calls.items()}, {k: set(v) for k, v in right_calls.items()}),
        (_invert(left_calls), _invert(right_calls)),
    )
    matched, back = {}, {}
    for _s, lo, ro in _anchors(table, anchor_score, anchor_margin):
        if lo not in matched and ro not in back:
            matched[lo], back[ro] = (ro, "anchor"), lo

    def consistency(a, b):
        """Matched neighbours the pair agrees with, and those it contradicts."""
        agree = disagree = 0
        for lrel, rrel in relations:
            for n in lrel.get(a, ()):
                if n in matched and matched[n][0] != b:
                    if matched[n][0] in rrel.get(b, ()):
                        agree += 1
                    else:
                        disagree += 1
            for n in rrel.get(b, ()):
                if n in back and back[n] != a and back[n] not in lrel.get(a, ()):
                    disagree += 1
        return agree, disagree

    def propagate(queue):
        while queue:
            lo, ro = queue.pop(0)
            for lrel, rrel in relations:
                lefts = [a for a in lrel.get(lo, ()) if a not in matched and a in left]
                rights = [b for b in rrel.get(ro, ()) if b not in back and b in right]
                if not lefts or not rights:
                    continue
                only_choice = len(lefts) == 1 and len(rights) == 1
                scored = {}
                for a in lefts:
                    for b in rights:
                        agree, disagree = consistency(a, b)
                        scored[(a, b)] = pair_score(a, b) + neighbour_bonus * (agree - disagree)
                for (a, b), s in sorted(scored.items(), key=lambda item: -item[1]):
                    if a in matched or b in back:
                        continue
                    if not only_choice:
                        # each must be the other's single best, and the pair must rest on something
                        rivals_a = [v for (x, y), v in scored.items() if x == a and y != b and y not in back]
                        rivals_b = [v for (x, y), v in scored.items() if y == b and x != a and x not in matched]
                        if s <= 0 or any(v >= s for v in rivals_a + rivals_b):
                            continue
                    matched[a], back[b] = (b, "propagated"), a
                    queue.append((a, b))

    def refine():
        """Re-decide every pair with its neighbours' matches counted for or against it.

        Twins such as the routines that send and receive a handshake record share every
        protocol constant, and the first match between them can pick the wrong twin. The call
        graph gives it away: the wrong twin's callees are matched to the other twin's callees."""
        candidates = {}
        for lo, row in table.items():
            for s, ro in row[:REFINE_CANDIDATES]:
                if s > 0:
                    candidates[(lo, ro)] = s
        for lo, (ro, _how) in matched.items():
            candidates.setdefault((lo, ro), pair_score(lo, ro))
            for lrel, rrel in relations:
                for a in lrel.get(lo, ()):
                    for b in rrel.get(ro, ()):
                        if a in left and b in right:
                            candidates.setdefault((a, b), pair_score(a, b))
        support = {}
        for (a, b), token_score in candidates.items():
            agree, disagree = consistency(a, b)
            support[(a, b)] = (token_score + neighbour_bonus * (agree - disagree), token_score, agree)
        by_left, by_right = defaultdict(list), defaultdict(list)
        for (a, b), (total, _t, _agree) in support.items():
            by_left[a].append(total)
            by_right[b].append(total)
        revised, taken = {}, set()
        for (a, b), (total, token_score, agree) in sorted(support.items(), key=lambda item: -item[1][0]):
            if a in revised or b in taken or total <= 0:
                continue
            if agree == 0 and token_score < anchor_score:
                continue
            # strictly the best either side can do
            if sorted(by_left[a], reverse=True)[1:2] == [total] or sorted(by_right[b], reverse=True)[1:2] == [total]:
                continue
            how = matched[a][1] if a in matched and matched[a][0] == b else "revised"
            revised[a] = (b, how)
            taken.add(b)
        return revised

    propagate([(lo, ro) for lo, (ro, _how) in matched.items()])
    for _ in range(REFINE_ROUNDS):
        revised = refine()
        if revised == matched:
            break
        matched.clear()
        matched.update(revised)
        back.clear()
        back.update({ro: lo for lo, (ro, _how) in matched.items()})
        propagate([(lo, ro) for lo, (ro, _how) in matched.items()])
    return matched


def scorable(sets):
    return {off for off, toks in sets.items() if len(toks) >= MIN_TOKENS}
