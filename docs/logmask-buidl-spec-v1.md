# logmask v1 — Build Spec

**Domain:** Python CLI tool / MSP operational security
**Status:** Active — build target: this afternoon (2025-03-01)
**Date:** 2025-03-01
**Version:** 0.1

---

## Vision

Deterministic, offline, map-based anonymization of IT infrastructure data in text files. MSP engineers paste logs, configs, and transcripts into external tools (Claude, vendor support portals). This tool scans files for infrastructure identifiers, builds a persistent translation map, and performs single-pass replacement using an Aho-Corasick automaton. Bidirectional — anonymize out, reveal back.

---

## Critical Constraints

| Constraint | Detail |
|---|---|
| **No build toolchain on endpoints** | All dependencies must install via `pip install` from pre-built wheels. No C/Rust compilation. No admin elevation. |
| **Windows-first** | Primary target: Entra-joined Windows 10/11 endpoints. Must work in standard user context. |
| **Offline execution** | Zero network calls at runtime. No cloud APIs, no telemetry, no update checks. |
| **Deterministic** | Same input + same map = byte-identical output. Every time. No randomness at replacement time. |
| **Human-readable maps** | CSV format. Engineers must be able to open, audit, and hand-edit maps in Excel/Notepad. |

---

## Architecture — Five Modules, No Framework

No plugin system for v1. Parsers are internal callables registered in a dictionary. Architecture supports future pluggy migration but doesn't require it now.

```
logmask/
├── pyproject.toml          # PEP 621, src layout, pip install -e .
├── src/
│   └── logmask/
│       ├── __init__.py
│       ├── __main__.py      # Entry: python -m logmask
│       ├── cli.py           # argparse CLI (typer migration = future)
│       ├── scanner.py       # Discovery engine — runs parsers against files
│       ├── parsers/         # Internal parser registry
│       │   ├── __init__.py  # PARSER_REGISTRY dict: name → callable
│       │   ├── ipv4.py      # RFC1918 IPv4 addresses
│       │   ├── cidr.py      # Subnet/CIDR notation
│       │   ├── hostname.py  # NetBIOS + FQDN
│       │   ├── identity.py  # UPNs, Entra GUIDs, SIDs
│       │   └── network.py   # MAC addresses, UNC paths
│       ├── map_engine.py    # CSV map CRUD, scope merge, fake value generation
│       ├── replacer.py      # Aho-Corasick automaton build + single-pass replace
│       └── models.py        # Dataclasses: DetectedIdentifier, MapEntry, Config
├── tests/
│   ├── conftest.py          # Synthetic log fixtures (no real client data)
│   ├── test_parsers.py
│   ├── test_map_engine.py
│   ├── test_replacer.py
│   └── test_roundtrip.py    # Anonymize → reveal → hash compare
└── README.md
```

---

## Dependencies

All confirmed pre-built Windows wheels on PyPI:

| Package | Purpose | Wheel status |
|---|---|---|
| `pyahocorasick` >=2.3.0 | Aho-Corasick automaton (C extension) | ✅ Win64 wheels: cp310–cp313 |
| `pandas` | CSV map load/merge/write | ✅ Pre-built wheels |
| `typer` | CLI framework (v1: minimal use) | ✅ Pure Python |
| `rich` | Terminal table output for `map show` | ✅ Pure Python |

**v1 does NOT use:** pluggy, questionary, ahocorasick_rs

**Dev dependencies:** pytest, pytest-cov

---

## Identifier Types — v1 Scope

| Type Enum | Pattern Target | Generation Rule |
|---|---|---|
| `ipv4` | RFC1918 private IPs (10.x, 172.16-31.x, 192.168.x) | Preserve A+B octets, randomize C+D. Stays in same RFC1918 class. |
| `cidr` | Subnet notation (x.x.x.x/N) | Anonymize IP portion per ipv4 rules. Preserve /prefix exactly. |
| `hostname` | NetBIOS (≤15 char) and FQDNs | Preserve structure: flat→flat, dotted→dotted with same label count. |
| `upn` | user@domain.com patterns | Anonymize both local-part and domain independently. |
| `guid` | Entra object IDs, Azure resource GUIDs | Replace with deterministic fake UUID (uuid5 from original as seed). |
| `sid` | Windows SIDs (S-1-5-21-...) | Preserve S-1-5-21 prefix, randomize sub-authority values. |
| `mac` | MAC addresses (XX:XX:XX:XX:XX:XX and XX-XX-XX-XX-XX-XX) | Preserve OUI (first 3 octets), randomize last 3. |
| `unc` | UNC paths (\\\\server\\share) | Anonymize server and share components independently via hostname rules. |

**Not in v1 scope:** Azure resource ID paths, certificate thumbprints, MSSQL/MongoDB-specific parsers (deferred — these require structured format awareness). The v1 parsers work against unstructured/semi-structured text.

---

## Map Format

**File:** CSV with strict schema.

| Column | Type | Description |
|---|---|---|
| `identifier_type` | str (enum) | One of the type enums above |
| `original_value` | str | Exact extracted string |
| `anonymized_value` | str | Generated or user-provided fake |
| `scope` | str | `global` or `project` |
| `preserve_format` | bool | Whether structural rules were applied |

**Scope segregation:**

| Scope | Location | Purpose |
|---|---|---|
| Global | `%USERPROFILE%\.logmask\global_map.csv` | MSP-wide constants (jump servers, monitoring hosts, corporate domain) |
| Project | `./.logmask/project_map.csv` | Client-specific identifiers for this diagnostic bundle |

**Merge rule:** Project map overrides global map on `original_value` key collision. Merge happens at runtime load, never mutates either source file.

---

## CLI Commands — v1

Minimal. Functional. Not pretty.

```
logmask init [--client NAME]
    Create .logmask/ directory in CWD with empty project_map.csv

logmask scan <target_dir> [--ext .log .txt .md .ps1]
    Run all parsers against target files
    Print discovered identifiers to stdout as a table
    Prompt: approve/reject/edit each new identifier
    Approved entries appended to project_map.csv

logmask anonymize <target_dir> --out <output_dir>
    Load merged map (global + project)
    Build Aho-Corasick automaton (LeftmostLongest)
    Single-pass replace on all target files
    Write anonymized copies to output_dir

logmask reveal <target_dir> --out <output_dir>
    Reverse operation: swap map keys↔values
    Build automaton from anonymized_value→original_value
    Write revealed copies to output_dir

logmask map show [--scope global|project|merged]
    Render map contents as terminal table via rich

logmask map add <type> <original> <anonymized>
    Manually inject a mapping into project_map.csv
```

---

## Replacement Engine — Core Algorithm

This is the critical path. Get this right first.

1. Map Engine loads global + project CSVs into pandas DataFrames
2. Merge: project overrides global on `original_value` key
3. Extract `{original_value: anonymized_value}` dictionary
4. Feed all keys into `ahocorasick.Automaton()` with `ahocorasick.MATCH_EXACT_LENGTH` (note: pyahocorasick uses `AHOCORASICK_MATCH_KIND` — verify API; the key behavior needed is longest-match-wins to prevent substring collision)
5. `automaton.iter(text)` returns matches as `(end_index, value)` tuples
6. Build output string by slicing: unmodified text up to match start → replacement value → advance pointer past match end
7. Write output, preserving original encoding

**Bidirectional:** For `reveal`, invert the dictionary (swap k↔v) before building the automaton.

**Substring collision prevention:** The Aho-Corasick automaton with longest-match guarantees `10.0.0.100` is matched before `10.0.0.1` at the same position. This is architectural, not heuristic.

---

## Fake Value Generation Rules

Generation happens once during `scan` approval and is stored permanently in the map. At `anonymize` time, the map is read-only.

| Type | Rule | Example |
|---|---|---|
| `ipv4` | Keep A+B octets from original. Random C+D (1-254). Check for collision in existing map. | `10.0.1.50` → `10.0.187.22` |
| `cidr` | Anonymize IP portion per ipv4. Keep `/prefix` intact. | `192.168.1.0/24` → `192.168.204.0/24` |
| `hostname` | Generate from word list (e.g., `SRV-{WORD}-{NN}`). Match flat vs FQDN structure. | `SQL-PROD-03.contoso.local` → `SRV-ALPHA-42.fabrikam.local` |
| `upn` | Anonymize local-part with random name. Anonymize domain via hostname rules. | `jsmith@contoso.com` → `user047@fabrikam.com` |
| `guid` | `uuid.uuid5(NAMESPACE_URL, original)` — deterministic from input. | `a1b2c3d4-...` → `f7e8d9c0-...` |
| `sid` | Preserve `S-1-5-21-` prefix. Random sub-authorities (same count). | `S-1-5-21-123-456-789-1001` → `S-1-5-21-887-234-551-4022` |
| `mac` | Keep first 3 octets (OUI). Random last 3. Preserve delimiter style. | `AA:BB:CC:11:22:33` → `AA:BB:CC:7F:3A:91` |
| `unc` | Decompose, anonymize server+share via hostname rules, reassemble. | `\\FILESVR\Finance$` → `\\SRV-BETA-07\Share41$` |

---

## Regex Patterns — Implementation Notes

All patterns MUST use word boundary anchors (`\b`) or zero-width lookarounds. Naive patterns without boundaries will cause timestamp/version corruption (see Anti-Pattern 2 in reference GDR doc).

**Parser contract:** Every parser is a function with signature:

```python
def parse(text: str, config: Config) -> list[DetectedIdentifier]
```

Where `DetectedIdentifier` is:

```python
@dataclass
class DetectedIdentifier:
    value: str              # Exact matched string
    identifier_type: str    # Enum: ipv4, cidr, hostname, etc.
    start_pos: int          # Start index in source text
    end_pos: int            # End index in source text
    confidence: float       # 0.0–1.0 (ipv4 = high, hostname = lower)
```

**PARSER_REGISTRY** is just:

```python
PARSER_REGISTRY: dict[str, Callable] = {
    "ipv4": ipv4_parse,
    "cidr": cidr_parse,
    "hostname": hostname_parse,
    "identity": identity_parse,
    "network": network_parse,
}
```

No hookspecs. No plugin manager. Add a file, add a dict entry.

---

## Testing Strategy

| Test Category | What It Proves |
|---|---|
| **Parser unit tests** | Each regex finds exactly the expected identifiers in synthetic fixtures. No false positives on timestamps, versions, paths. |
| **Map merge tests** | Project scope overrides global. No mutation of source files. |
| **Replacer unit tests** | Substring collision cases (10.0.0.1 vs 10.0.0.100). Overlapping patterns. |
| **Round-trip integration** | `anonymize(text, map)` → `reveal(result, map)` → `hash(result) == hash(original)`. Byte-identical. |

**Fixtures:** Synthetic only. No real client data in tests. Generate realistic-looking MSSQL error logs, routing tables, PowerShell transcripts with known "poison" identifiers embedded.

---

## What Is NOT v1

Explicitly deferred. Planned, not forgotten.

| Feature | Why Deferred |
|---|---|
| pluggy plugin architecture | Overkill until 3+ external parser contributors exist |
| questionary interactive prompts | UX polish; stdout table + CSV edit workflow is functional |
| MSSQL-specific log parser | Requires structured format awareness beyond regex |
| MongoDB-specific log parser | Same as above |
| JSON/XML-aware parsing | Structured data needs format-aware approach, not text regex |
| IPv6 support | Low priority for current client environments |
| Azure resource ID paths | Complex hierarchical structure; needs dedicated parser |
| typer rich CLI help | Works fine with argparse for now |
| Pickle/cache automaton | Optimization; rebuild is fast enough for MSP-scale maps |

---

## Build Sequence — Suggested Agent Split

**Phase 1 — Skeleton (KiloCode Architect Mode)**
- Scaffold repo structure per tree above
- pyproject.toml with dependencies
- All module files with docstrings, type hints, empty implementations
- models.py fully implemented (dataclasses are the contract)
- README.md with install + usage

**Phase 2 — Engine Core (Claude Code or KiloCode Code Mode)**
- map_engine.py: CSV load, merge, write, fake value generation
- replacer.py: Aho-Corasick build, single-pass replace, reveal mode
- test_replacer.py + test_map_engine.py passing

**Phase 3 — Parsers (Parallelizable)**
- Each parser file is independent. Can be built/tested in isolation.
- ipv4.py + cidr.py first (most critical, most testable)
- hostname.py next (hardest — false positive management)
- identity.py + network.py (guid/sid/mac/unc — well-defined patterns)

**Phase 4 — CLI Wiring**
- cli.py: Wire commands to engine
- __main__.py: Entry point
- Manual integration test: scan a synthetic log dir, approve, anonymize, reveal, verify

---

## Reference Material

The GDR research document (`Python_Anonymization_Library_Architecture.md`) contains:
- Detailed regex patterns for IPv4/RFC1918, CIDR, hostname, MSSQL, MongoDB
- Anti-Pattern Catalog (6 failure modes with defensive patterns) — **read this before implementing replacer.py**
- Aho-Corasick algorithm explanation and API usage for pyahocorasick
- Map merge semantics and scope segregation rationale

Attach as reference if context window allows. The anti-pattern catalog is the most operationally useful section.

---

## Document Info

| | |
|---|---|
| Author | CrainBramp + Claude (MSP4 KB Writing GPT) |
| Created | 2025-03-01 |
| Version | 0.1 |
| Status | Active — handoff to build agents |
| Lineage | GDR research output → Claude review → scoped v1 spec |
