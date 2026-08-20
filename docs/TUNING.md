# Tuning an MCRIT deployment

> **Canonical copy:** `docs/TUNING.md` in the [mcrit](https://github.com/danielplohmann/mcrit)
> repository, which is where the config classes whose defaults this document describes live. The
> copy in [docker-mcrit](https://github.com/danielplohmann/docker-mcrit) is a verbatim mirror:
> edit mcrit's, then copy the file over, and never the other way round. A change to a default in
> `MinHashConfig` or `StorageConfig` should update this document in the same commit.

These recommendations come from a benchmarking campaign against a real Malpedia corpus
(11,697,468 functions / 8,483 samples / 2,175 families, 20 bands `{4:20}`, threshold 50) on an
8-core / 32 GiB host with mongod 5.0. Roughly 200 full matching jobs were measured across 81
distinct samples, spanning 50 to 5,482 functions and both `BAND_MATCHES_REQUIRED` regimes.
Every configuration change was verified result-preserving by comparing a SHA-256 digest of the
complete match report, so the settings below trade speed and memory only — never matches.

Two findings drive the sizing. First, **matching memory scales with how much a sample pulls
out of the corpus, not with how large the sample is**: peak RSS correlates 0.98 with bytes
fetched from MongoDB and only 0.62 with the sample's function count, so a 2,100-function
sample can cost more RAM than a 5,500-function one. Second, **matching is bound by MongoDB
read latency, not by CPU**: the hot query returns a 186-byte projection out of 4,188-byte
documents, so it spends its time waiting rather than computing. Spare cores are therefore worth
much more on I/O concurrency than on additional matching processes, and RAM is best spent on
mongod's cache and on retaining fetched signatures between batches.

## Recommended settings

Values are **per concurrent matching job** — multiply the worker budget if you run several.

| host | mongod WiredTiger cache | `MINHASH_MATCHING_FUNCTION_BATCH_SIZE` | `STORAGE_MATCHING_CACHE_MAX_BYTES` | `STORAGE_CACHE_FETCH_THREADS` | expected worker peak |
|---|---|---|---|---|---|
| 8 GiB / 2 cores | 3 GiB | 200 | 300 MiB (~1.0 M functions) | 2 | ~1.5–2 GiB |
| 16 GiB / 4 cores | 6 GiB | 500 | 640 MiB (~2.1 M functions) | 4 | ~2–3 GiB |
| 32 GiB / 8 cores | 12–15 GiB | 1000 | 1.5 GiB (~5.0 M functions) | 8 | ~3–5 GiB |
| 64 GiB / 16 cores | 24 GiB | 1000–5000 | 1.5 GiB | 8 | ~5–8 GiB, room for 2–3 jobs |

`STORAGE_MATCHING_CACHE_MAX_BYTES` is set as a plain byte count (`536870912` for the 512 MiB
default). It and `STORAGE_CACHE_FETCH_THREADS` are only worth setting where the table differs
from the shipped default: as of MCRIT 1.6.1 the budget defaults to 512 MiB, and fetch threads
defaults to `min(4, cpu_count / 2)` — deliberately below the values above, which assume mongod
is not shared with another workload. Both resolved values are logged at startup.

Always keep `WiredTiger cache + Σ worker peaks + 2 GiB` inside physical RAM, and set a
`mem_limit` on the worker service in `docker-compose.yml` — an unlimited container leaves any
overcommit to the host OOM killer, which may choose mongod.

These settings are strictly better and involve no trade-off. **As of MCRIT 1.6.1 they are the
defaults**, so on 1.6.1 or later there is nothing to set — they are listed here for what they
buy, and because the value is what you would restore to on 1.6.0:

| setting | value | effect |
|---|---|---|
| `STORAGE_CANDIDATE_ACCUMULATION` | `"numpy"` | 1.5–5.9x faster candidate retrieval, several hundred MB less peak memory |
| `MINHASH_MATCHING_VECTORIZED` | `True` | 27–29x faster scoring (59,500 → 1.59 M pairs/s) |
| `STORAGE_MATCHING_CACHE_PERSIST` | `True` | drops a 1.5–12.2x redundant per-batch cache rebuild |

`MINHASH_POOL_MATCHING` no longer needs setting either: with vectorised scoring the matching
phase runs single-process and ignores the flag, which also removes the run-to-run
non-determinism pooled matching caused. Indexing still honours `MINHASH_POOL_INDEXING`.

Notes on the individual knobs:

* **Batch size** trades memory for speed: `1000` is ~1.5x faster than `200` for ~1.5x the peak
  memory, while `10000` is no faster than `5000` and costs 2.4–3.7x the memory of `200`.
* **Pair budget** (`MINHASH_MATCHING_MAX_PAIRS`, default 50,000,000, new in 1.6.2) caps how many
  candidate pairs a batch accumulates before it is scored, at roughly ~250 B resident per pair.
  Candidate volume per query function spans five orders of magnitude, so a function count alone
  cannot bound the tail; the budget does, and at the default it only binds on runaway jobs. The
  batch size above stays an upper bound on query functions per batch, so both limits apply and
  lowering either one lowers peak memory. Lowering the budget buys memory with wall time - measured
  on a 53 M-pair sample: 10 M cost +68 % wall for -40 % peak, 2 M cost +203 % for -49 %, and most of
  that penalty is batches evicting each other from the MatchingCache when the budget sits far below
  the candidate union. Set it to `0` to restore fixed-size batches.
* **Cache ceiling** costs ~314 bytes per retained function. Size it above your largest sample's
  candidate set; when it binds it roughly halves the benefit. Since 1.6.1 evictions are logged,
  so a ceiling that binds is visible in the worker log rather than silent — entries needed by
  the batch being served are never evicted.
* **Fetch threads** overlap MongoDB read latency: 2.2x at 2 threads, 3.4x at 4, 6.8x at 8 on an
  isolated fetch. Where mongod is shared with other workloads, treat this as a politeness knob.
* **`BAND_MATCHES_REQUIRED` is not a tuning knob** — it changes results. Raising it from 2 to 3
  removed 62 % of the scoring work at a cost of 9.5 % of matches on the sample tested. Choose
  it for analysis quality, then tune around it.

## Caveats

* Constants are measured on one corpus and one host. The relationships generalise; the specific
  numbers are worth re-checking if your corpus differs substantially in size or in family
  composition.
* `STORAGE_CANDIDATE_ACCUMULATION`, `MINHASH_MATCHING_VECTORIZED`, `STORAGE_CACHE_FETCH_THREADS`
  and `STORAGE_MATCHING_CACHE_PERSIST` shipped opt-in (default off) in MCRIT 1.6.0 and are on by
  default from 1.6.1. `MINHASH_MATCHING_MAX_PAIRS` is 1.6.2 and later. `STORAGE_MATCHING_CACHE_MAX_BYTES` is 1.6.1 and later; on 1.6.0 size the
  cache with `STORAGE_MATCHING_CACHE_MAX_ENTRIES` instead, at ~314 B per entry. On 1.5.3 and
  earlier only the batch size, `BAND_MATCHES_REQUIRED` and the mongod cache size apply.
* All measurements used single-process matching; comparisons against a pooled configuration
  will differ.
