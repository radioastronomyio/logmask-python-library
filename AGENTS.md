# logmask — Agent Context

## Project Identity

**What:** Python CLI tool for deterministic, offline, map-based anonymization of IT infrastructure data in text files.

**Who for:** MSP engineers who paste logs, configs, and transcripts into external tools (Claude, vendor support portals) and need to strip infrastructure identifiers first.

**Repo:** `D:\development-repositories\logmask-python-library`

**Status:** v0.1 — core build complete, post-review fixes applied. Known bugs documented inline (see Known Issues below). Not yet tested against real client data.

## Architecture

Five modules, no framework. Parsers are internal callables in a dictionary registry.

```
src/logmask/
├── __init__.py          # Package exports: DetectedIdentifier, MapEntry, Config
├── __main__.py          # Entry: python -m logmask
├── cli.py               # argparse CLI — 6 commands (init, scan, anonymize, reveal, map show, map add)
├── scanner.py           # Discovery engine — runs parsers, deduplicates, filters hostname/UPN collisions
├── map_engine.py        # CSV map CRUD, scope merge (global + project), fake value generation
├── replacer.py          # Aho-Corasick automaton build + single-pass replace + reveal
├── models.py            # Frozen dataclasses: DetectedIdentifier, MapEntry, Config
└── parsers/
    ├── __init__.py      # PARSER_REGISTRY dict: name → callable
    ├── ipv4.py          # RFC1918 private IPs
    ├── cidr.py          # Subnet/CIDR notation
    ├── hostname.py      # NetBIOS (structural heuristics) + FQDN
    ├── identity.py      # UPNs, Entra GUIDs, Windows SIDs
    └── network.py       # MAC addresses, UNC paths
```

### Critical Path

The replacement engine is the core. Everything else feeds into it:

1. `map_engine` loads global + project CSVs, merges (project overrides global on key collision)
2. Merged map feeds `{original: anonymized}` dict to `replacer`
3. `replacer` builds Aho-Corasick automaton via `_build_automaton()`
4. `_apply_automaton()` performs single-pass replacement with longest-match-wins
5. For `reveal`, the dict is inverted (swap k↔v) before building automaton

The core algorithm lives in two module-level functions in `replacer.py`: `_build_automaton()` and `_apply_automaton()`. These are correct and should not be modified. All replacement paths (forward, reverse, class-based, convenience functions) delegate to them.

### Map Format

CSV with columns: `identifier_type`, `original_value`, `anonymized_value`, `scope`, `preserve_format`

- **Global map:** `%USERPROFILE%\.logmask\global_map.csv`
- **Project map:** `./.logmask/project_map.csv`
- Merge rule: project overrides global on `original_value` key collision, never mutates source files

### Parser Design

- Each parser is a pure function: `def parse(text: str, config: Config) -> list[DetectedIdentifier]`
- Parsers are registered in `PARSER_REGISTRY` in `parsers/__init__.py`
- Parsers only detect — they never generate fake values (that's `map_engine`'s job)
- Hostname parser uses structural heuristics (hyphen, known prefix, uppercase+digit) to minimize false positives
- Scanner resolves hostname/UPN collision via position-based overlap filtering in `_filter_contained_hostnames()`

## Known Issues

Bugs documented inline in source. Fix before production use.

### Fixed (uncommitted — applied by OpenCode/GLM-4.7)

**~~🔴 `Replacer.reveal_text()` corrupts forward automaton~~** (`replacer.py`)
- Fixed: `reveal_text()` now uses a local automaton variable, preserving `self._automaton` state

**~~🟡 `validate_rfc1918` doesn't validate octets 3-4~~** (`parsers/ipv4.py`)
- Fixed: added `all(0 <= int(o) <= 255 for o in octets)` check

**~~🟡 Dead code block in `parse_upn()`~~** (`parsers/identity.py`)
- Fixed: unreachable `generic_local_parts` block removed

### Open

**🔴 `_generate_fake_ipv4` collision check is wrong** (`map_engine.py`)
- Compares `fake_ip` against merged map *keys* (original values) instead of *anonymized* values
- Also: `merge_maps()` reads CSV from disk on every call — redundant I/O when generating multiple IPs

**🟡 `_generate_fake_hostname` domain suffix leakage** (`map_engine.py`)
- FQDN anonymization only replaces the first label; real domain suffix passes through unchanged
- Leaks real domain name into anonymized output

**🟡 `scope` parameter unused in `generate_fake_value`** (`map_engine.py`)
- Accepted but never threaded through to generation methods

**🟡 Inconsistent lazy-loading in `replace_text` vs `reveal_text`** (`replacer.py`)
- `replace_text()` auto-loads map if automaton is None; `reveal_text()` always reloads from disk

**🟡 `test_roundtrip_file` fragile path dependency** (`tests/test_roundtrip.py`)
- Uses `sample_config` which points at `~/.logmask/` — may pass for wrong reasons if CSVs exist there
- Fix: rewrite to match `TestRoundTripWithMapScopes` pattern

**🟢 Inline imports in `handle_anonymize()` and `handle_reveal()`** (`cli.py`)
- `from logmask.map_engine import load_merged_map` imported at function scope, not module top
- Functional but inconsistent

**🟢 No test coverage: scanner.py** — Scanner class, `_filter_contained_hostnames()`, extension filtering

**🟢 No test coverage: cli.py** — all handler functions untested

## Test Coverage

| Module | Coverage | Notes |
|--------|----------|-------|
| `models.py` | ✅ Full | Via conftest fixtures and unit tests |
| `map_engine.py` | ✅ Good | test_map_engine.py |
| `replacer.py` | ✅ Good | test_replacer.py — core algorithm, substring collision, determinism |
| `parsers/*` | ✅ Good | test_parsers.py — all 5 parsers, registry, false positive filtering |
| `test_roundtrip.py` | ✅ Full | 15 tests — text/file/directory, hash comparison, edge cases, map scopes |
| `scanner.py` | ❌ None | No unit tests. `_filter_contained_hostnames()` untested directly |
| `cli.py` | ❌ None | No unit tests. All handler functions untested |

## Commands

```bash
# Install in dev mode
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=src/logmask

# Run specific test files
pytest tests/test_replacer.py
pytest tests/test_roundtrip.py
pytest tests/test_parsers.py

# Run by name
pytest tests/test_parsers.py -k "test_name"

# CLI
logmask init [--client NAME]
logmask scan <dir> [--ext .log .txt .md .ps1]
logmask anonymize <dir> --out <output_dir>
logmask reveal <dir> --out <output_dir>
logmask map show [--scope global|project|merged]
logmask map add <type> <original> <anonymized>
```

## Critical Constraints

- **No build toolchain on endpoints** — all deps install via pip from pre-built wheels
- **Windows-first** — Entra-joined Win10/11, standard user context
- **Offline execution** — zero network calls at runtime
- **Deterministic** — same input + same map = byte-identical output, every time
- **Human-readable maps** — CSV, editable in Excel/Notepad
- **All file I/O is UTF-8** — encoding detection deferred to future version

## Coding Conventions

- Type hints on all function signatures
- Docstrings on all public functions (Google style)
- `models.py` is frozen — data contracts are stable, do not modify
- `map_engine.py` owns all fake value generation — parsers do not generate fakes
- All regex patterns use `\b` word boundary anchors to prevent timestamp/version corruption
- No new dependencies without explicit approval
- Inline `# BUG:` and `# TODO:` comments document known issues at point of occurrence
- `# [Agent context: ...]` comments provide module-level orientation for coding agents

## Dependencies

| Package | Purpose |
|---------|---------|
| `pyahocorasick` >=2.3.0 | Aho-Corasick automaton (C extension, pre-built Win64 wheels) |
| `pandas` | CSV map load/merge/write |
| `rich` | Terminal table output |
| `pytest` (dev) | Testing |
| `pytest-cov` (dev) | Coverage |

## Reference

Authoritative build spec: `docs/logmask-buidl-spec-v1.md`
