#!/usr/bin/env python3
"""Named band projections for STORAGE_BAND_STRATEGY = "explicit".

A projection states, per band, which signature offsets feed it. Hand-writing twenty lists is not
a usable interface, so the evaluated schemes ship as names.

All presets here assume the default signature layout: MINHASH_SIGNATURE_LENGTH = 64 with
`generate_segmented_sequence` giving offsets 0-15 to FuzzyStatPairShingler (function metrics) and
16-63 to EscapedBlockShingler (escaped instruction n-grams). A different signature length or
shingler weighting changes what these offsets mean, which is why `validateBandProjection` reports
coverage rather than assuming it.

Why the segment matters: a band matches only if *all* its offsets match, so a band spanning both
segments fails when either segment changes. The two fail independently in practice - recompilation
moves the metric fields while block structure survives, and an escaper change moves block fields
while metrics stay put. A scheme with no single-segment bands has no fallback for either.
"""

_STAT = list(range(16))
_BLOCK = list(range(16, 64))


def _chunks(seq, size):
    return [seq[i : i + size] for i in range(0, len(seq), size)]


def _random_projection(num_bands, band_size, seed=0xDEADBEEF, length=64):
    """Replicates the historical "random" strategy exactly, for reproducing an existing index.

    The offsets are deliberately left in shuffled order. A band hash is
    `mmh3.hash("".join(str(value) for value in band_values))`, so the ORDER of offsets within a
    band changes the hash: sorting them here produces a projection that covers the same fields and
    still fingerprints as 20 bands of 4, yet queries an existing index with different keys and
    silently retrieves almost nothing. Measured while building this: sorting dropped a citadel
    match run from 4,631,845 candidate pairs to 120,358 and changed the result digest.
    """
    import random

    rng = random.Random(seed)
    projection = []
    for _ in range(num_bands):
        sequence = list(range(length))
        rng.shuffle(sequence)
        projection.append(sequence[:band_size])
    return projection


# a second grid of block bands offset by 2 from the disjoint one: more independent chances to
# retrieve without giving up segment purity or the uniform band size
_OFFSET_BLOCK = [list(range(offset, offset + 4)) for offset in range(18, 61, 8)]
# a few deliberately mixed bands: these fire when agreement is spread thinly across BOTH segments,
# the one case pure bands cannot cover
_MIXED = _random_projection(4, 4, seed=0x5EED1234)

BAND_PRESETS = {
    # ---- reproductions of what shipped before, for migrating an existing index -------------
    "legacy-random-20x4": _random_projection(20, 4),
    "legacy-linear-16x4": [[n * 16 + b for n in range(4)] for b in range(16)],
    # ---- segment-aware schemes ------------------------------------------------------------
    # 12 pure-block bands of 4 + 3 pure-metric bands of 6/5/5. Complete 64/64 coverage for
    # essentially no throughput cost (~1.03x measured), against the 45/64 the random default
    # reaches. Metric bands are wider than 4 because the metric segment is cheaper to probe when
    # its bands are fewer; the cost is that band keys are no longer uniformly 4 bytes.
    "segment-balanced-v1": _chunks(_BLOCK, 4) + [_STAT[0:6], _STAT[6:11], _STAT[11:16]],
    # 12 pure-block bands + 4 pure-metric bands. Complete coverage, uniform size 4.
    "segment-pure-v1": _chunks(_BLOCK, 4) + _chunks(_STAT, 4),
    # ... plus the offset block grid, which mainly buys retrieval back at k >= 2.
    "segment-overlap-v1": _chunks(_BLOCK, 4) + _chunks(_STAT, 4) + _OFFSET_BLOCK,
    # ... plus mixed bands. Measured best overall; see session-10/RESULTS-BANDING-RECALL.md.
    "segment-hybrid-v1": _chunks(_BLOCK, 4) + _chunks(_STAT, 4) + _OFFSET_BLOCK + _MIXED,
}


def describeBandProjection(projection, signature_length=64, stat_segment=16):
    """Summarise a projection: band count, coverage, and how many bands avoid the metric segment."""
    covered = set()
    for band in projection:
        covered.update(band)
    pure_block = sum(1 for band in projection if all(offset >= stat_segment for offset in band))
    pure_stat = sum(1 for band in projection if all(offset < stat_segment for offset in band))
    sizes = sorted({len(band) for band in projection})
    return {
        "num_bands": len(projection),
        "coverage": len(covered),
        "signature_length": signature_length,
        "uncovered": sorted(set(range(signature_length)) - covered),
        "pure_block_bands": pure_block,
        "pure_stat_bands": pure_stat,
        "band_sizes": sizes,
    }


def validateBandProjection(projection, signature_length=64):
    """Return (errors, warnings). Errors make the projection unusable; warnings are reported.

    Coverage is deliberately *reported*, not required: overlapping and partial projections are
    legitimate LSH - the long-shipped "random" default covers only 45 of 64 - but a scheme that
    silently ignores a third of the signature should say so at startup, since that is exactly how
    the situation went unnoticed for so long.
    """
    errors = []
    warnings = []
    if not projection:
        errors.append("STORAGE_BAND_PROJECTION is empty - at least one band is required.")
        return errors, warnings
    for index, band in enumerate(projection):
        if not band:
            errors.append("band %d is empty." % index)
            continue
        for offset in band:
            if not isinstance(offset, int) or not (0 <= offset < signature_length):
                errors.append("band %d contains offset %r outside 0..%d." % (index, offset, signature_length - 1))
        if len(set(band)) != len(band):
            errors.append("band %d repeats an offset: %s" % (index, band))
        if len(band) <= 2:
            warnings.append(
                "band %d has size %d; bands of 2 or fewer fields return on the order of 10^5 "
                "candidates per probe on a corpus of millions of functions, which is never a "
                "useful operating point." % (index, len(band))
            )
    description = describeBandProjection(projection, signature_length=signature_length)
    if description["uncovered"]:
        warnings.append("projection covers %d of %d signature fields; never indexed: %s" % (description["coverage"], signature_length, description["uncovered"]))
    if description["pure_block_bands"] == 0:
        warnings.append("no band avoids the metric segment - every band then depends on the function metrics, so a recompilation that shifts them can lose all bands at once.")
    return errors, warnings


def getBandProjectionFingerprint(projection, signature_length=64):
    """Stable fingerprint of a projection, for detecting an index built under a different one.

    Band keys are derived data exactly like minhashes: change the projection without rebuilding and
    the stored band index still resolves, still returns candidates, and is quietly wrong. Unlike a
    matching result that cannot be caught by comparing digests, so it has to be detected here.
    """
    import hashlib
    import json

    # Order is preserved deliberately, both of the bands and of the offsets within each band. A
    # band hash concatenates the field values in projection order, so two projections that differ
    # only in ordering produce different band keys and are NOT interchangeable - a fingerprint that
    # sorted them would call them identical and defeat its own purpose.
    normalised = [[int(offset) for offset in band] for band in projection]
    payload = json.dumps({"projection": normalised, "signature_length": int(signature_length)}, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
