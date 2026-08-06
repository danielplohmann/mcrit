# AGENTS.md — MCRIT (core package)

MCRIT (MinHash-based Code Relationship & Investigation Toolkit) is a distributed framework for binary code similarity analysis. This repository is the **core `mcrit` package**: the REST server, the async worker, the Python client, and the `mcrit` CLI. It indexes and matches disassembled code using SMDA, storing results in MongoDB (or in-memory for development).

For the full methodology (PicHash/MinHash, LSH banding, case studies) see [`README.md`](README.md) and the [deepwiki overview](https://deepwiki.com/danielplohmann/mcrit/).

## Repository layout

- `mcrit/` — package source.
  - `mcrit/server/` — Falcon REST API (`application_routes.py`, `*Resource.py`).
  - `mcrit/storage/` — data model and storage backends (`MongoDbStorage`, `MemoryStorage`).
  - `mcrit/queue/` — job queue (`LocalQueue`, `MongoQueue`) and RPC plumbing.
  - `mcrit/libs/` — helpers (parallel processing, graph, hashing).
  - `Worker.py`, `__main__.py` — worker process and CLI entry point.
- `tests/` — pytest suite (unit + integration).
- `docs/` — CLI docs, migration guides.
- `examples/`, `experiments/`, `diagnosis/` — auxiliary scripts.
- `setup.py`, `requirements.txt`, `ruff.toml`, `pytest.ini` — build/config.

## Development setup

Requires **Python 3.11 or 3.12**.

```bash
pip install -r requirements.txt
pip install -e .
```

MongoDB 5.0+ is the recommended persistent backend, but the in-memory storage works for development without a database.

## Common commands

Lint (run before considering work done):

```bash
ruff format --check .
ruff check .
```

Unit tests (no database required):

```bash
python -m pytest -m "not mongo and not sleep"
```

Full/integration tests (requires a running MongoDB at `127.0.0.1:27017`):

```bash
python -m pytest
```

Run the backend (separate shells):

```bash
mcrit server     # REST API on http://127.0.0.1:8000/
mcrit worker     # processes queued jobs
```

Interact via the CLI:

```bash
mcrit client status
mcrit client submit <file> -f <family_name>
```

## Architecture primer

- **Server** (Falcon): synchronous endpoints for queries (families/samples/functions); long-running operations (disassembly, indexing, matching) create async **jobs**.
- **Worker + Queue**: jobs are pulled from a queue (`LocalQueue` in-process, `MongoQueue` in production) and executed by one or more workers.
- **Storage**: `MongoDbStorage` (persistent) or `MemoryStorage` (dev). Holds `FamilyEntry`, `SampleEntry`, `FunctionEntry`.
- **Matching**: `PicHash` / `PicBlockHash` give exact (position-independent) matches; `MinHash` signatures + LSH **banding** give fuzzy similarity. Feature extraction is done by `AbstractShingler` implementations.

## Key concepts

- **PicHash / PicBlockHash** — position-independent hashes (function- and basic-block-level). The hash comparison is exact; the code match it implies is quasi-exact, since identical position-independent bytes do not guarantee the same function.
- **MinHash signature** — fuzzy similarity estimate derived from shingled code features.
- **Shingler** — encodes properties of a disassembled function into a feature set for MinHashing.
- **Band** — LSH band used for candidate generation during matching.
- **Family / Sample / Function** — the three-tier storage hierarchy.
- **Job** — async unit of work (disassemble, index, match, cross-compare, unique-blocks).

## Code conventions

- Lint/format: `ruff` (line-length 180, `target-version = "py311"`, selects `E4/E7/E9/F/I/UP`). Run `ruff format .` to auto-format.
- Supported Python: 3.11–3.12 (`python_requires=">=3.11,<3.13"`).
- License: GPL-3.0-only. Version is bumped manually in `setup.py` and the `README.md` changelog — do not change unless asked.
- Never introduce or log secrets/API tokens/keys.

## Agent guardrails

- **Never** run `git commit`, `git push`, or open a PR unless explicitly instructed.
- **Do not** change MinHash/PicHash/shingler configuration or version numbers without explicit instruction — such changes require a full re-index of the database.
- Integration tests require a running MongoDB (`mongo:5.0` container is enough); the unit suite runs without one.
- Always run `ruff format`/`ruff check` and the unit test suite before considering work complete.

## Related repositories (reference only)

- [mcrit-web](https://github.com/fkie-cad/mcrit-web) — Flask browser front-end + user management.
- [docker-mcrit](https://github.com/danielplohmann/docker-mcrit) — containerized full-stack deployment (incl. NGINX).
- [mcrit-plugins](https://github.com/danielplohmann/mcrit-plugin) — IDA Pro integration plugin.
- [mcrit-data](https://github.com/danielplohmann/mcrit-data) — ready-to-use reference data for common compilers/libraries.
