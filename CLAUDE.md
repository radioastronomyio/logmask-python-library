# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

logmask — Deterministic, offline, map-based anonymization of IT infrastructure data in text files. Python CLI tool for MSP engineers who need to strip infrastructure identifiers from logs/configs before sharing externally.

## Commands

```bash
# Install in dev mode
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=src/logmask

# Run a single test file
pytest tests/test_parsers.py

# Run a single test by name
pytest tests/test_parsers.py -k "test_name"

# Run the CLI
logmask <command>
python -m logmask <command>
```

## Architecture

Five modules, no framework. Source layout: `src/logmask/`.

**Critical path (replacement engine):**
1. `map_engine.py` loads global + project CSVs, merges them (project overrides global on `original_value` key collision)
2. Merged map feeds `{original: anonymized}` dict to `replacer.py`
3. `replacer.py` builds Aho-Corasick automaton, performs single-pass replacement with longest-match-wins
4. For `reveal`, the dict is inverted (swap k↔v) before building automaton

**Key modules:**
- `models.py` — Frozen dataclasses: `DetectedIdentifier`, `MapEntry`, `Config`. **Do not modify** — data contracts are stable.
- `map_engine.py` — Owns all fake value generation. Parsers never generate fakes.
- `parsers/__init__.py` — `PARSER_REGISTRY` dict maps name → callable. Parser contract: `def parse(text: str, config: Config) -> list[DetectedIdentifier]`
- `replacer.py` — Aho-Corasick automaton build + single-pass replace
- `cli.py` — argparse CLI (not Typer, despite pyproject.toml listing it)
- `scanner.py` — Discovery engine, runs parsers against files

**Identifier types:** ipv4, cidr, hostname, upn, guid, sid, mac, unc

## Conventions

- Type hints on all function signatures
- Google-style docstrings on public functions
- All regex patterns use `\b` word boundary anchors to prevent timestamp/version corruption
- All file I/O is UTF-8
- No new dependencies without explicit approval
- Round-trip property must hold: `anonymize(text, map)` → `reveal(result, map)` = byte-identical to original

## Constraints

- **No build toolchain on endpoints** — deps install via pip from pre-built wheels only
- **Windows-first** — Entra-joined Win10/11, standard user context
- **Offline execution** — zero network calls at runtime
- **Deterministic** — same input + same map = byte-identical output

## Reference

Authoritative build spec: `docs/logmask-buidl-spec-v1.md`
