"""
logmask - Deterministic, offline, map-based anonymization of IT infrastructure data.

This package provides a CLI tool for MSP operational security that scans text files
for infrastructure identifiers, builds a persistent translation map, and performs
single-pass replacement using an Aho-Corasick automaton.

Core modules:
- cli: Command-line interface
- scanner: Discovery engine that runs parsers against files
- map_engine: CSV map CRUD, scope merge, fake value generation
- replacer: Aho-Corasick automaton build and single-pass replace
- models: Dataclasses for DetectedIdentifier, MapEntry, Config
- parsers: Internal parser registry for identifier detection

Usage:
    python -m logmask scan <target_dir>
    logmask anonymize <target_dir> --out <output_dir>
    logmask reveal <target_dir> --out <output_dir>
"""

__version__ = "0.1.0"
__author__ = "logmask contributors"

from logmask.models import DetectedIdentifier, MapEntry, Config

__all__ = [
    "__version__",
    "DetectedIdentifier",
    "MapEntry",
    "Config",
]
