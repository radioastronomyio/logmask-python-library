"""
Command-line interface for logmask.

This module provides the argparse-based CLI with commands for:
- init: Initialize project map
- scan: Discover identifiers in files
- anonymize: Replace identifiers with fake values
- reveal: Reverse anonymization
- map: Manage translation maps

# [Agent context: This module has NO unit test coverage. All handler functions
# (handle_init, handle_scan, handle_anonymize, handle_reveal, handle_map_show,
# handle_map_add) and create_parser() are untested. When adding tests, use
# monkeypatch for input() in handle_scan's per-type approval flow. The main()
# function dispatches via command_handlers dict — test each command path.]
"""

import argparse
import sys
from pathlib import Path
from typing import Any

from logmask.map_engine import MapEngine
from logmask.models import Config, MapEntry
from logmask.replacer import Replacer
from logmask.scanner import Scanner
from rich.console import Console
from rich.table import Table


def create_parser() -> argparse.ArgumentParser:
    """
    Create and configure the argument parser for the logmask CLI.
    
    Returns:
        argparse.ArgumentParser: Configured parser with all subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="logmask",
        description="Deterministic, offline, map-based anonymization of IT infrastructure data.",
        epilog="Run 'logmask <command> --help' for command-specific help.",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # init command
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize .logmask directory with empty project map"
    )
    init_parser.add_argument(
        "--client",
        type=str,
        help="Client name for the project"
    )
    
    # scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan files for infrastructure identifiers"
    )
    scan_parser.add_argument(
        "target_dir",
        type=Path,
        help="Directory to scan for identifiers"
    )
    scan_parser.add_argument(
        "--ext",
        nargs="+",
        default=[".log", ".txt", ".md", ".ps1"],
        help="File extensions to scan (default: .log .txt .md .ps1)"
    )
    
    # anonymize command
    anonymize_parser = subparsers.add_parser(
        "anonymize",
        help="Replace identifiers with fake values"
    )
    anonymize_parser.add_argument(
        "target_dir",
        type=Path,
        help="Directory containing files to anonymize"
    )
    anonymize_parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output directory for anonymized files"
    )
    
    # reveal command
    reveal_parser = subparsers.add_parser(
        "reveal",
        help="Reverse anonymization to reveal original values"
    )
    reveal_parser.add_argument(
        "target_dir",
        type=Path,
        help="Directory containing anonymized files"
    )
    reveal_parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output directory for revealed files"
    )
    
    # map subcommands
    map_parser = subparsers.add_parser(
        "map",
        help="Manage translation maps"
    )
    map_subparsers = map_parser.add_subparsers(dest="map_command", help="Map commands")
    
    # map show
    show_parser = map_subparsers.add_parser("show", help="Display map contents")
    show_parser.add_argument(
        "--scope",
        choices=["global", "project", "merged"],
        default="merged",
        help="Map scope to display (default: merged)"
    )
    
    # map add
    add_parser = map_subparsers.add_parser("add", help="Add a manual mapping")
    add_parser.add_argument("type", type=str, help="Identifier type")
    add_parser.add_argument("original", type=str, help="Original value")
    add_parser.add_argument("anonymized", type=str, help="Anonymized value")
    
    return parser


def handle_init(args: argparse.Namespace) -> int:
    """
    Handle the init command.
    
    Args:
        args: Parsed command-line arguments.
        
    Returns:
        int: Exit code (0 for success, non-zero for failure).
    """
    config = Config.default()
    
    # Create .logmask directory
    try:
        config.ensure_directories()
        print(f"Created .logmask directory at: {config.project_map_path.parent}")
    except Exception as e:
        print(f"Error creating .logmask directory: {e}", file=sys.stderr)
        return 1
    
    # Create empty project_map.csv if it doesn't exist
    if not config.project_map_path.exists():
        try:
            # Write CSV header
            import pandas as pd
            df = pd.DataFrame(columns=["identifier_type", "original_value", "anonymized_value", "scope", "preserve_format"])
            df.to_csv(config.project_map_path, index=False)
            print(f"Created empty project map at: {config.project_map_path}")
        except Exception as e:
            print(f"Error creating project map: {e}", file=sys.stderr)
            return 1
    else:
        print(f"Project map already exists at: {config.project_map_path}")
    
    if args.client:
        print(f"Initialized logmask project for client: {args.client}")
    else:
        print("Initialized logmask project")
    
    return 0


def handle_scan(args: argparse.Namespace) -> int:
    """
    Handle the scan command.
    
    Args:
        args: Parsed command-line arguments.
        
    Returns:
        int: Exit code (0 for success, non-zero for failure).
    """
    # Validate target directory
    if not args.target_dir.exists():
        print(f"Error: Target directory does not exist: {args.target_dir}", file=sys.stderr)
        return 1
    
    # Create config with specified extensions
    config = Config.default()
    config.extensions = args.ext
    
    # Initialize scanner
    scanner = Scanner(config)
    
    # Scan directory
    print(f"Scanning directory: {args.target_dir}")
    print(f"Extensions: {args.ext}")
    print()
    
    try:
        results = scanner.scan_directory(args.target_dir)
    except Exception as e:
        print(f"Error scanning directory: {e}", file=sys.stderr)
        return 1
    
    if not results:
        print("No identifiers found.")
        return 0
    
    # Collect all unique identifiers
    all_identifiers: list = []
    seen = set()
    for file_path, identifiers in results.items():
        for identifier in identifiers:
            key = (identifier.identifier_type, identifier.value)
            if key not in seen:
                seen.add(key)
                all_identifiers.append(identifier)
    
    # Display results in a table
    console = Console()
    table = Table(title=f"Detected Identifiers ({len(all_identifiers)} unique)")
    table.add_column("Type", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Confidence", style="yellow")
    
    for identifier in all_identifiers:
        table.add_row(
            identifier.identifier_type,
            identifier.value,
            f"{identifier.confidence:.2f}"
        )
    
    console.print(table)
    
    # Group identifiers by type for per-type approval
    by_type: dict[str, list] = {}
    for identifier in all_identifiers:
        by_type.setdefault(identifier.identifier_type, []).append(identifier)

    # Prompt for each type separately
    approved_identifiers: list = []
    print()
    for id_type, type_identifiers in sorted(by_type.items()):
        prompt = f"Found {len(type_identifiers)} {id_type} identifiers. Add to project map? (y/n): "
        print(prompt, end="")
        try:
            response = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nOperation cancelled.")
            return 0

        if response == 'y':
            approved_identifiers.extend(type_identifiers)

    if not approved_identifiers:
        print("No identifiers added to project map.")
        return 0

    # Generate fake values and create map entries
    map_engine = MapEngine(config)
    approved_entries = []

    for identifier in approved_identifiers:
        fake_value = map_engine.generate_fake_value(
            identifier.identifier_type,
            identifier.value,
            preserve_format=True,
            scope="project"
        )

        entry = MapEntry(
            identifier_type=identifier.identifier_type,
            original_value=identifier.value,
            anonymized_value=fake_value,
            scope="project",
            preserve_format=True
        )
        approved_entries.append(entry)

    # Write to project map
    try:
        existing_map = map_engine.load_project_map()

        for entry in approved_entries:
            existing_map[entry.original_value] = entry

        map_engine.write_project_map(list(existing_map.values()))

        print(f"\nAdded {len(approved_entries)} entries to project map.")
        return 0
    except Exception as e:
        print(f"Error writing to project map: {e}", file=sys.stderr)
        return 1


def handle_anonymize(args: argparse.Namespace) -> int:
    """
    Handle the anonymize command.
    
    Args:
        args: Parsed command-line arguments.
        
    Returns:
        int: Exit code (0 for success, non-zero for failure).
    """
    # Validate target directory
    if not args.target_dir.exists():
        print(f"Error: Target directory does not exist: {args.target_dir}", file=sys.stderr)
        return 1
    
    # Validate output directory is not inside target directory
    try:
        args.out.resolve().relative_to(args.target_dir.resolve())
        print(f"Error: Output directory cannot be inside target directory.", file=sys.stderr)
        return 1
    except ValueError:
        # This is expected - output is not inside target
        pass
    
    # Create config
    config = Config.default()
    
    # Initialize replacer
    replacer = Replacer(config)
    
    # TODO: Inline import — load_merged_map is imported at function scope here and
    # in handle_reveal(). Move to module-level imports for consistency.
    # Load merged map and build automaton
    print(f"Loading translation maps...")
    from logmask.map_engine import load_merged_map
    mapping = load_merged_map(config)

    if not mapping:
        print("Warning: No mappings found. Files will be copied without changes.")
    else:
        print(f"Loaded {len(mapping)} mappings from global and project maps.")
    
    # Build automaton
    replacer.build_automaton(mapping)
    
    # Anonymize directory
    print(f"Anonymizing files from: {args.target_dir}")
    print(f"Output directory: {args.out}")
    print()
    
    try:
        results = replacer.replace_directory(args.target_dir, args.out)
        
        success_count = sum(1 for success in results.values() if success)
        failure_count = len(results) - success_count
        
        print(f"Processed {len(results)} files:")
        print(f"  Success: {success_count}")
        print(f"  Failed:  {failure_count}")
        
        if failure_count > 0:
            print("\nFailed files:")
            for file_path, success in results.items():
                if not success:
                    print(f"  - {file_path}")
        
        return 0 if failure_count == 0 else 1
    except Exception as e:
        print(f"Error anonymizing files: {e}", file=sys.stderr)
        return 1


def handle_reveal(args: argparse.Namespace) -> int:
    """
    Handle the reveal command.
    
    Args:
        args: Parsed command-line arguments.
        
    Returns:
        int: Exit code (0 for success, non-zero for failure).
    """
    # Validate target directory
    if not args.target_dir.exists():
        print(f"Error: Target directory does not exist: {args.target_dir}", file=sys.stderr)
        return 1
    
    # Validate output directory is not inside target directory
    try:
        args.out.resolve().relative_to(args.target_dir.resolve())
        print(f"Error: Output directory cannot be inside target directory.", file=sys.stderr)
        return 1
    except ValueError:
        # This is expected - output is not inside target
        pass
    
    # Create config
    config = Config.default()
    
    # Initialize replacer
    replacer = Replacer(config)
    
    # Load merged map
    print(f"Loading translation maps...")
    from logmask.map_engine import load_merged_map
    mapping = load_merged_map(config)
    
    if not mapping:
        print("Error: No mappings found. Cannot reveal files.", file=sys.stderr)
        return 1
    
    print(f"Loaded {len(mapping)} mappings from global and project maps.")
    
    # Reveal directory
    print(f"Revealing files from: {args.target_dir}")
    print(f"Output directory: {args.out}")
    print()
    
    try:
        results = replacer.reveal_directory(args.target_dir, args.out)
        
        success_count = sum(1 for success in results.values() if success)
        failure_count = len(results) - success_count
        
        print(f"Processed {len(results)} files:")
        print(f"  Success: {success_count}")
        print(f"  Failed:  {failure_count}")
        
        if failure_count > 0:
            print("\nFailed files:")
            for file_path, success in results.items():
                if not success:
                    print(f"  - {file_path}")
        
        return 0 if failure_count == 0 else 1
    except Exception as e:
        print(f"Error revealing files: {e}", file=sys.stderr)
        return 1


def handle_map_show(args: argparse.Namespace) -> int:
    """
    Handle the map show command.
    
    Args:
        args: Parsed command-line arguments.
        
    Returns:
        int: Exit code (0 for success, non-zero for failure).
    """
    # Create config
    config = Config.default()
    
    # Initialize map engine
    map_engine = MapEngine(config)
    
    # Get map entries for specified scope
    try:
        entries = map_engine.show_map(args.scope)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    if not entries:
        print(f"No entries found in {args.scope} map.")
        return 0
    
    # Display entries in a table
    console = Console()
    table = Table(title=f"Translation Map ({args.scope}) - {len(entries)} entries")
    table.add_column("Type", style="cyan")
    table.add_column("Original", style="green")
    table.add_column("Anonymized", style="yellow")
    table.add_column("Scope", style="magenta")
    
    for entry in entries:
        table.add_row(
            entry.identifier_type,
            entry.original_value,
            entry.anonymized_value,
            entry.scope
        )
    
    console.print(table)
    
    return 0


def handle_map_add(args: argparse.Namespace) -> int:
    """
    Handle the map add command.
    
    Args:
        args: Parsed command-line arguments.
        
    Returns:
        int: Exit code (0 for success, non-zero for failure).
    """
    # Validate identifier type
    valid_types = ["ipv4", "cidr", "hostname", "upn", "guid", "sid", "mac", "unc"]
    if args.type not in valid_types:
        print(f"Error: Invalid identifier type '{args.type}'. Valid types: {', '.join(valid_types)}", file=sys.stderr)
        return 1
    
    # Create config
    config = Config.default()
    
    # Ensure .logmask directory exists
    try:
        config.ensure_directories()
    except Exception as e:
        print(f"Error creating .logmask directory: {e}", file=sys.stderr)
        return 1
    
    # Create MapEntry
    try:
        entry = MapEntry(
            identifier_type=args.type,  # type: ignore
            original_value=args.original,
            anonymized_value=args.anonymized,
            scope="project",
            preserve_format=True
        )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    # Add to project map
    try:
        map_engine = MapEngine(config)
        map_engine.add_entry(entry)
        print(f"Added mapping: {args.type} | {args.original} -> {args.anonymized}")
        return 0
    except Exception as e:
        print(f"Error adding mapping: {e}", file=sys.stderr)
        return 1


def main() -> int:
    """
    Main entry point for the logmask CLI.
    
    Returns:
        int: Exit code (0 for success, non-zero for failure).
    """
    parser = create_parser()
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return 0
    
    command_handlers: dict[str, Any] = {
        "init": handle_init,
        "scan": handle_scan,
        "anonymize": handle_anonymize,
        "reveal": handle_reveal,
    }
    
    if args.command == "map":
        map_handlers: dict[str, Any] = {
            "show": handle_map_show,
            "add": handle_map_add,
        }
        if args.map_command is None:
            parser.parse_args(["map", "--help"])
            return 0
        return map_handlers.get(args.map_command, lambda _: 1)(args)
    
    handler = command_handlers.get(args.command, lambda _: 1)
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
