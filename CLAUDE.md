# logmask — Claude Code Context

This file is loaded automatically by Claude Code. It complements `AGENTS.md`,
which is the authoritative agent context file. Read both before working on
this project. When the two files conflict, `AGENTS.md` wins.

## Quick orientation

- **What:** Python CLI — deterministic, offline, map-based anonymization of IT
  infrastructure identifiers in text files.
- **Who:** MSP engineers scrubbing logs/configs before sharing with third parties.
- **Spec:** `docs/logmask-buidl-spec-v1.md` — authoritative; defer to it.
- **Status:** v0.1 alpha — core complete, known bugs documented in `AGENTS.md`.

## Repo layout

```
src/logmask/
├── cli.py          argparse CLI — init, scan, anonymize, reveal, map show/add
├── scanner.py      Discovery engine — runs parsers, deduplicates, filters collisions
├── map_engine.py   CSV map CRUD, merge (global + project), fake-value generation
├── replacer.py     Aho-Corasick automaton + single-pass replace/reveal
├── models.py       Frozen dataclasses — DetectedIdentifier, MapEntry, Config
└── parsers/        ipv4, cidr, hostname, identity, network — pure detection only
tests/
├── conftest.py         Fixtures (synthetic data only — no real client data)
├── test_parsers.py
├── test_map_engine.py
├── test_replacer.py
├── test_roundtrip.py
├── test_scanner.py
└── test_cli.py
```

## Running tests

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=src/logmask

# Single file
pytest tests/test_scanner.py -v
```

## Critical invariants — do not break

| Rule | Location |
|------|----------|
| `_build_automaton()` and `_apply_automaton()` are correct — do not modify | `replacer.py` |
| `models.py` is a frozen contract — do not add or change fields | `models.py` |
| Parsers only detect — never generate fake values | `parsers/*` |
| All fake-value generation routes through `generate_fake_value()` | `map_engine.py` |
| Project map overrides global map on `original_value` key collision | `map_engine.py` |
| Merge never mutates source CSV files | `map_engine.py` |
| All file I/O is UTF-8 | throughout |

## Coding conventions

- Type hints on all function signatures.
- Docstrings on all public functions (Google style).
- `\b` word-boundary anchors on all regex patterns (prevents timestamp/version corruption).
- No new dependencies without explicit approval.
- Mark known issues with `# BUG:` or `# TODO:` at point of occurrence.
- `# [Agent context: ...]` block comments provide module-level orientation.

## Known open issues (as of v0.1)

See `AGENTS.md § Known Issues` for the full list with severity ratings.
Highest priority items:

- `_generate_fake_ipv4` collision check against anonymized values (fixed in v0.1.1).
- FQDN hostname domain suffix leakage (fixed in v0.1.1).
- `merge_maps()` redundant I/O in batch generation (fixed in v0.1.1).
- `test_roundtrip_file` fragile path dependency (`tests/test_roundtrip.py`).
- `reveal_text()` inconsistent lazy-loading vs `replace_text()` (`replacer.py`).

## Map format

CSV with columns: `identifier_type`, `original_value`, `anonymized_value`,
`scope`, `preserve_format`.

- **Global:** `%USERPROFILE%\.logmask\global_map.csv`
- **Project:** `./.logmask/project_map.csv`

## Dependencies

| Package | Purpose |
|---------|---------|
| `pyahocorasick` >=2.3.0 | Multi-pattern automaton (C extension, pre-built Win64 wheels) |
| `pandas` | CSV map load / merge / write |
| `rich` | Terminal table output |
| `pytest`, `pytest-cov` | Testing (dev only) |
