"""
Entry point for running logmask as a module.

Usage:
    python -m logmask <command> [options]

# TODO: Entry point mismatch — pyproject.toml [project.scripts] points to
# logmask.cli:main, which skips the KeyboardInterrupt/exception handling
# defined in cli_entry() below. Users who `pip install logmask` and run the
# `logmask` command will get raw tracebacks on Ctrl+C.
# Fix: Either change pyproject.toml to point to logmask.__main__:cli_entry,
# or move the exception handling into cli.main().
"""

import sys
from typing import NoReturn

from logmask.cli import main


def cli_entry() -> NoReturn:
    """
    Main entry point when running python -m logmask.
    
    Delegates to the CLI main function and exits with the appropriate code.
    """
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    cli_entry()
