import os
import sys

import lief

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from apis import concept, elf_plt, pe_iat, thumb_veneers
from peapi import resolved_apis
from smda.common.SmdaReport import SmdaReport
from xfeat import Image, features

HERE = os.path.dirname(os.path.abspath(__file__))
# The samples are malware and are not in this repository. Point these at your own copies:
# CROSS_ARCH_SAMPLES holds the binaries, CROSS_ARCH_REPORTS the SMDA reports named <sample>.smda.
SAMPLES = os.environ.get("CROSS_ARCH_SAMPLES", os.path.join(HERE, "samples"))
REPORTS = os.environ.get("CROSS_ARCH_REPORTS", os.path.join(HERE, "reports"))


def _thunks(rep, feats):
    """A tiny function whose whole body is one import call is a thunk for that import.

    Folding thunks into the import map moves the token to the caller that means it."""
    found = {}
    for f in rep.getFunctions():
        toks = feats.get(f.offset) or {}
        if f.num_instructions <= 3 and len(toks) == 1:
            token = next(iter(toks))
            if not token.startswith("api:"):
                continue
            found[f.offset] = found[f.offset | 1] = token[4:]
    return found


def load(name, data=None, report=None, keep_small=False):
    data = data or open(os.path.join(SAMPLES, name), "rb").read()
    rep = report or SmdaReport.fromFile(os.path.join(REPORTS, name + ".smda"))
    img = Image(data)
    raw = {}
    if isinstance(img.bin, lief.ELF.Binary):
        if img.bin.has_section(".plt"):
            raw.update(elf_plt(img.bin))
            raw.update(thumb_veneers(img.bin, raw))
    else:
        raw.update(pe_iat(img.bin))
        raw.update(resolved_apis(rep, img))
    imports = {a: concept(n) for a, n in raw.items() if concept(n)}

    rep, img, feats = features(rep, data, imports=imports, keep_small=keep_small)
    for _ in range(2):
        thunks = _thunks(rep, feats)
        new = {a: c for a, c in thunks.items() if a not in imports}
        if not new:
            break
        imports.update(new)
        rep, img, feats = features(rep, data, imports=imports, keep_small=keep_small)

    skip = set(_thunks(rep, feats))
    if isinstance(img.bin, lief.ELF.Binary) and img.bin.has_section(".plt"):
        plt = img.bin.get_section(".plt")
        skip |= {f.offset for f in rep.getFunctions() if plt.virtual_address <= f.offset < plt.virtual_address + plt.size}

    calls = {}
    for f in rep.getFunctions():
        targets = {t for group in f.outrefs.values() for t in group}
        calls[f.offset] = sorted(t for t in targets if t in feats and t != f.offset)
    feats = {off: toks for off, toks in feats.items() if off not in skip}
    return rep, img, feats, raw, calls
