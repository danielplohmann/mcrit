# Matching the same program across instruction sets

An experiment, not a feature. Nothing here is imported by MCRIT, and nothing here changes how
MCRIT matches.

## The question

MCRIT reports no matches between samples of different architectures, and [#230](https://github.com/familiary/mcrit/pull/230)
now filters the few that band collisions produced. That filter is only correct if there was
nothing real to find. This measures whether there was.

The test case is the Lazarus backdoor that McAfee tied from Windows to Android by its C2 protocol
(OPCDE 2018, *DPRK's eyes on mobile*): two PE32 builds and three ARM ELFs, one of them
`assets/while` from the APK. The link was established by hand, by reading the same disguised TLS
handshake in both. It is the fairest possible case for cross-architecture matching, because a
human analyst already found the answer.

## What MCRIT does today

Run on `main` with the architecture filter off:

| comparison | sample score |
| --- | --- |
| PE vs PE | 100 |
| ARM ELF vs ARM ELF | 99 |
| PE vs ARM ELF | no matches |

Comparing every PE function against every ELF function directly, the best pair reaches 39, under
the threshold of 50. The pair that is provably the same function - the routine that reads a record
header and checks for version `0x301` - scores about 3 and ranks 127th of 264.

The reason is in the features, not in MinHash. `EscapedBlockShingler` builds its tokens from
escaped instructions, which never agree across instruction sets: 0 of the 48 signature fields it
owns. `FuzzyStatPairShingler` is closer to neutral but agrees on only 1-2 of its 16. So **#230
filters noise, not signal**, and that is what this experiment was for.

## What does survive a port

A port preserves what the program *references*, not how it computes. This prototype builds a token
set per function from three things:

- **constants** - protocol values, buffer sizes, magic numbers. ARM literal pools and PC-relative
  addresses are resolved so that a value the compiler parked in a pool still counts.
- **strings** it references.
- **OS calls, by what they do.** `send` and `write` are one token, as are `CloseHandle`,
  `closesocket` and `close`. A port keeps the operation and changes the name.

Then each function also borrows its callees' tokens, in a namespace of their own, because what a
function does is partly what it delegates.

Two details did more for the result than the scoring did:

- **ARM import veneers.** ELF code reaches libc through a PLT entry, and Thumb code reaches the
  PLT through a `bx pc` veneer, so callers name the veneer and never the PLT entry. Before mapping
  veneers to their imports (`apis.thumb_veneers`), *no* ARM function had an import token at all.
- **The PE resolves its imports at runtime.** 118 API names are stored encrypted and decoded with
  a per-character cipher before `GetProcAddress`. Without recovering that table (`peapi.py`) the
  Windows side has almost no call tokens to compare.

## Result

Against 14 function pairs verified by hand in a decompiler (`truth.py`), scoring every PE function
against every ELF function:

- 11 pairs carry enough tokens to score.
- **8 of those 11 rank first** out of 44-61 candidates, and **all 11 rank in the top 5**.
- The two pairs that share a role but were genuinely rewritten - the beacon loop and the connect
  loop - correctly do not match.

Ranked first: the disconnect routine (72.3), ClientKeyExchange (51.6), the handshake driver
(32.5), both transfer loops, the fake ClientHello, and the `0x301` record reader. Full output is
in `results.txt`.

## The limitation, which is the point

At **sample** level this does not yet discriminate. With every token kept, this PE against an
unrelated Mirai ARM build scores 46.3 with 16 pairs at 30 or above - indistinguishable from the
true pair's 75.0 and 17. The tokens driving those false pairs are small integers (`0x22`, `0x2b`,
`0x30`, `0x78`) shared by libc number formatting on both sides.

Dropping constants below `0x100` separates the controls cleanly:

| comparison | top-10 mean | pairs >= 30 |
| --- | --- | --- |
| Mirai i386 vs Mirai ARM (positive) | 44.3 | 12 |
| Lazarus PE vs Lazarus ARM (positive) | 45.3 | 14 |
| Lazarus PE vs Mirai ARM | 24.8 | 2 |
| Mirai i386 vs Lazarus ARM | 6.1 | 0 |
| Bashlite x64 vs Lazarus ARM | 6.6 | 0 |
| Cutwail PE vs Lazarus ARM | 6.1 | 0 |

But it costs recall: only 8 of 14 pairs stay scorable, and ClientKeyExchange drops out. The TLS
record types this malware is identified by - `0x14`, `0x16`, `0x17` - are exactly the small
constants being discarded.

That trade-off is not a tuning bug. The distinctive tokens are small integers, and small integers
are also what unrelated code shares. Deciding it needs term frequencies from a real corpus, not
from the six samples weighted here.

## Growing the match along the call graph

Scoring functions one at a time leaves two kinds of pair behind. Small helpers - fill a buffer
with `rand()` bytes, reverse a length, wait on `select()` - reference too little to score at all.
And twins - the routines that send and receive a handshake record, or a TLS record - share every
protocol constant, so the first match between them can pick the wrong twin.

`propagate.py` handles both with the call graph:

1. **Anchors** are pairs that are each other's best match by a clear margin.
2. **Propagation** pairs the unmatched callees and callers of every matched pair, by token score
   plus the matched neighbours they share. A pair is taken when each is the other's single best,
   or when it is the only unmatched neighbour on both sides.
3. **Refinement** re-decides every pair with its neighbours' matches counted for it or against
   it, and propagates again, until nothing changes. The wrong twin gives itself away: its callees
   are matched to the other twin's callees.

It also adds one token family, the imports a function reaches within three calls (`reach:`), so
that data direction survives: the sending twin ends in a socket write, the receiving one in a
read.

On the same 14 hand-verified pairs (`run_propagate.py`):

| variant | correct | wrong | unmatched |
| --- | --- | --- | --- |
| ranking alone (above) | 8 ranked first | - | 3 unscorable |
| propagation, no `reach:` tokens | 9 | 4 | 1 |
| propagation and refinement with `reach:` | **14** | 0 | 0 |
| the same, constants below `0x100` dropped | 9 | 0 | 5 |

The three unscorable helpers are recovered from their callers, and both pairs of twins are
resolved. Two things to weigh against that:

- **It was tuned on the pairs it is scored on.** The `reach:` tokens and the refinement step were
  added after seeing the twins swap. Fourteen pairs from one sample pair are a demonstration, not a
  measurement; a second, independent sample pair is what would tell.
- **It amplifies whatever it anchors on.** The two rewritten routines that should stay unmatched
  (the beacon loop and the connect loop) are now paired with neighbours of theirs, and sample-level
  discrimination is no better than before:

| comparison | pairs matched |
| --- | --- |
| Lazarus PE vs Lazarus ARM (positive) | 48 |
| Mirai i386 vs Mirai ARM (positive) | 112 |
| Lazarus PE vs Mirai ARM | 45 |
| Bashlite x64 vs Lazarus ARM | 20 |
| Mirai i386 vs Lazarus ARM | 18 |
| Cutwail PE vs Lazarus ARM | 5 |

So propagation answers *which function is which* once two samples are known to be related, and
does nothing for *whether* they are. That second question still needs the corpus-wide term
frequencies described above.

## If this ever became a feature

It should be a separate, explicitly cross-architecture query path, entered only when the
instruction-based score is already zero - never a shingler in the normal pipeline, where the
existing features are far stronger, and never a reason to relax #230.

## Running it

The samples are malware and are not in this repository.

```
CROSS_ARCH_SAMPLES=/path/to/samples CROSS_ARCH_REPORTS=/path/to/smda/reports python run_pair.py
CROSS_ARCH_SAMPLES=... SMDA_FIXTURES=/path/to/smda/tests python controls.py
CROSS_ARCH_SAMPLES=... SMDA_FIXTURES=/path/to/smda/tests python run_propagate.py
```

`run_pair.py` takes `--flat` to switch off callee tokens and `--drop=0x100` to set the constant
threshold; `run_propagate.py` takes `--drop` too, and `--reach=0` to switch off `reach:` tokens.
Reports are SMDA reports named `<sample>.smda`; the ARM ones need an SMDA with the ARM backend.
`results.txt` was made with an ARM backend that follows libgcc's Thumb-1 switch helpers, which
recovers the ELF's command dispatcher and the three handlers only it calls.
