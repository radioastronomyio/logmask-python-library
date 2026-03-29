# AGENTS.md

Entry point for AI coding agents working on this repository.

## Project Identity

**Domain:** MSP Tooling / Security / CLI
**Repository:** https://github.com/radioastronomyio/logmask-python-library
**Purpose:** Python CLI tool for deterministic, offline, map-based anonymization of IT infrastructure data in text files. Designed for MSP engineers who paste logs, configs, and transcripts into external tools (Claude, vendor support portals) and need to strip infrastructure identifiers first.

**Status:** v0.1 alpha. Core build complete, post-review fixes applied. Known bugs documented inline (see Known Issues below). Not yet tested against real client data.

## Architecture

Five modules, no framework. Parsers are internal callables in a dictionary registry.

```
src/logmask/
├── __init__.py          # Package exports: DetectedIdentifier, MapEntry, Config
├── __main__.py          # Entry: python -m logmask
├── cli.py               # argparse CLI: 6 commands (init, scan, anonymize, reveal, map show, map add)
├── scanner.py           # Discovery engine: runs parsers, deduplicates, filters hostname/UPN collisions
├── map_engine.py        # CSV map CRUD, scope merge (global + project), fake value generation
├── replacer.py          # Aho-Corasick automaton build + single-pass replace + reveal
├── models.py            # Frozen dataclasses: DetectedIdentifier, MapEntry, Config
└── parsers/
    ├── __init__.py      # PARSER_REGISTRY dict: name to callable
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
5. For `reveal`, the dict is inverted (swap k/v) before building automaton

The core algorithm lives in two module-level functions in `replacer.py`: `_build_automaton()` and `_apply_automaton()`. These are correct and should not be modified. All replacement paths delegate to them.

### Map Format

CSV with columns: `identifier_type`, `original_value`, `anonymized_value`, `scope`, `preserve_format`

- **Global map:** `%USERPROFILE%\.logmask\global_map.csv`
- **Project map:** `./.logmask/project_map.csv`
- Merge rule: project overrides global on `original_value` key collision, never mutates source files

### Parser Design

- Each parser is a pure function: `def parse(text: str, config: Config) -> list[DetectedIdentifier]`
- Parsers are registered in `PARSER_REGISTRY` in `parsers/__init__.py`
- Parsers only detect; they never generate fake values (that's `map_engine`'s job)
- Hostname parser uses structural heuristics (hyphen, known prefix, uppercase+digit) to minimize false positives
- Scanner resolves hostname/UPN collision via position-based overlap filtering

## Known Issues

Bugs documented inline in source. Fix before production use.

### Fixed (uncommitted)

- ~~`Replacer.reveal_text()` corrupts forward automaton~~ (now uses local automaton variable)
- ~~`validate_rfc1918` doesn't validate octets 3-4~~ (added octet range check)
- ~~Dead code block in `parse_upn()`~~ (unreachable block removed)

### Open

| Severity | Issue | Location |
|----------|-------|----------|
| 🔴 | `_generate_fake_ipv4` collision check compares against map keys instead of anonymized values | `map_engine.py` |
| 🟡 | FQDN anonymization only replaces first label; real domain suffix passes through | `map_engine.py` |
| 🟡 | `scope` parameter unused in `generate_fake_value` | `map_engine.py` |
| 🟡 | Inconsistent lazy-loading in `replace_text` vs `reveal_text` | `replacer.py` |
| 🟡 | `test_roundtrip_file` fragile path dependency | `tests/test_roundtrip.py` |
| 🟢 | Inline imports in `handle_anonymize()` and `handle_reveal()` | `cli.py` |
| 🟢 | No test coverage for scanner.py | `scanner.py` |
| 🟢 | No test coverage for cli.py | `cli.py` |

## Test Coverage

| Module | Coverage | Notes |
|--------|----------|-------|
| `models.py` | ✅ Full | Via conftest fixtures and unit tests |
| `map_engine.py` | ✅ Good | test_map_engine.py |
| `replacer.py` | ✅ Good | Core algorithm, substring collision, determinism |
| `parsers/*` | ✅ Good | All 5 parsers, registry, false positive filtering |
| `test_roundtrip.py` | ✅ Full | 15 tests: text/file/directory, hash comparison, edge cases |
| `scanner.py` | ❌ None | `_filter_contained_hostnames()` untested |
| `cli.py` | ❌ None | All handler functions untested |

## Commands

```bash
# Install in dev mode
pip install -e ".[dev]"

# Run all tests
pytest

# With coverage
pytest --cov=src/logmask

# CLI
logmask init [--client NAME]
logmask scan <dir> [--ext .log .txt .md .ps1]
logmask anonymize <dir> --out <output_dir>
logmask reveal <dir> --out <output_dir>
logmask map show [--scope global|project|merged]
logmask map add <type> <original> <anonymized>
```

## Critical Constraints

- **No build toolchain on endpoints:** all deps install via pip from pre-built wheels
- **Windows-first:** Entra-joined Win10/11, standard user context
- **Offline execution:** zero network calls at runtime
- **Deterministic:** same input + same map = byte-identical output, every time
- **Human-readable maps:** CSV, editable in Excel/Notepad
- **All file I/O is UTF-8:** encoding detection deferred to future version

## Critical Invariants

| Rule | Location |
|------|----------|
| `_build_automaton()` and `_apply_automaton()` are correct; do not modify | `replacer.py` |
| `models.py` is a frozen contract; do not add or change fields | `models.py` |
| Parsers only detect; never generate fake values | `parsers/*` |
| All fake-value generation routes through `generate_fake_value()` | `map_engine.py` |
| Project map overrides global map on `original_value` key collision | `map_engine.py` |
| Merge never mutates source CSV files | `map_engine.py` |

## Coding Conventions

- Type hints on all function signatures
- Docstrings on all public functions (Google style)
- `\b` word-boundary anchors on all regex patterns (prevents timestamp/version corruption)
- No new dependencies without explicit approval
- Mark known issues with `# BUG:` or `# TODO:` at point of occurrence
- `# [Agent context: ...]` comments provide module-level orientation

## Execution Environment

**Primary execution:** ML01 (`/opt/repos/logmask-python-library/`)
**Agent runtime:** OpenCode (global config at `~/.config/opencode/opencode.json`)
**Session management:** aoe (Agent of Empires)
**Strategic work:** Claude.ai Projects
**Agentic coding:** Claude Code, OpenCode

## Repository Structure

```
logmask-python-library/
├── assets/                         # Repository images
├── docs/
│   ├── documentation-standards/    # Templates, tagging strategy
│   └── logmask-buidl-spec-v1.md    # Authoritative build specification
├── internal-files/                 # Working documents
├── shared/                         # Cross-project utilities
├── spec/                           # Specifications
├── src/logmask/                    # Source (PEP 621 src layout)
│   ├── cli.py
│   ├── scanner.py
│   ├── map_engine.py
│   ├── replacer.py
│   ├── models.py
│   └── parsers/
├── staging/                        # Staged work (gitignored)
├── tests/                          # Unit tests
├── work-logs/                      # Development history
├── AGENTS.md                       # This file
├── CLAUDE.md                       # Pointer to AGENTS.md
├── pyproject.toml                  # PEP 621 project config
├── LICENSE                         # MIT (code)
└── LICENSE-DATA                    # CC BY 4.0 (documentation)
```

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

## Session Pattern

1. Read this file
2. Read the build spec if working on core functionality
3. Check known issues before modifying map_engine or replacer
4. Do work
5. Run `pytest` before committing; all tests must pass
6. Update this file's Known Issues or Test Coverage if state changed
