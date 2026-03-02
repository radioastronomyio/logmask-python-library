"""
Discovery engine for scanning files and detecting infrastructure identifiers.

This module orchestrates the scanning process by running registered parsers
against target files and collecting detected identifiers.

# [Agent context: This module has NO unit test coverage. The Scanner class,
# _filter_contained_hostnames(), and scan_files() are all untested. When
# adding tests, cover: (1) scan_file with mixed identifier types, (2)
# hostname/UPN collision filtering, (3) deduplication behavior, (4)
# extension filtering in scan_directory, (5) error handling for unreadable
# files. See PARSER_REGISTRY in parsers/__init__.py for available parsers.]
"""

from pathlib import Path
from typing import Callable

from logmask.models import Config, DetectedIdentifier
from logmask.parsers import PARSER_REGISTRY


class Scanner:
    """
    Discovery engine that runs parsers against files to detect identifiers.
    """
    
    def __init__(self, config: Config) -> None:
        """
        Initialize the scanner with configuration.
        
        Args:
            config: Runtime configuration including paths and extensions.
        """
        self.config = config
        self._parsers: dict[str, Callable] = PARSER_REGISTRY.copy()
    
    def scan_file(self, file_path: Path) -> list[DetectedIdentifier]:
        """
        Scan a single file for infrastructure identifiers.
        
        Args:
            file_path: Path to the file to scan.
            
        Returns:
            List of detected identifiers from all parsers.
        """
        # Read file content
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"Warning: Could not read file {file_path}: {e}")
            return []
        
        # Run all parsers against content
        all_identifiers: list[DetectedIdentifier] = []
        for parser_name, parser_func in self._parsers.items():
            try:
                identifiers = parser_func(content, self.config)
                all_identifiers.extend(identifiers)
            except Exception as e:
                print(f"Warning: Parser {parser_name} failed on {file_path}: {e}")
        
        # Filter out hostname detections contained within UPN detections
        all_identifiers = _filter_contained_hostnames(all_identifiers)

        # Deduplicate by (identifier_type, value)
        seen = set()
        deduplicated: list[DetectedIdentifier] = []
        for identifier in all_identifiers:
            key = (identifier.identifier_type, identifier.value)
            if key not in seen:
                seen.add(key)
                deduplicated.append(identifier)

        return deduplicated
    
    def scan_directory(self, target_dir: Path) -> dict[Path, list[DetectedIdentifier]]:
        """
        Scan all files in a directory for infrastructure identifiers.
        
        Args:
            target_dir: Directory to scan.
            
        Returns:
            Dictionary mapping file paths to their detected identifiers.
        """
        if not target_dir.exists():
            raise FileNotFoundError(f"Target directory does not exist: {target_dir}")
        
        if not target_dir.is_dir():
            raise NotADirectoryError(f"Target path is not a directory: {target_dir}")
        
        results: dict[Path, list[DetectedIdentifier]] = {}
        
        # Find all files matching configured extensions
        for file_path in target_dir.rglob("*"):
            if file_path.is_file():
                # Check if file extension matches configured extensions
                if file_path.suffix.lower() in self.config.extensions:
                    # Scan the file
                    identifiers = self.scan_file(file_path)
                    if identifiers:
                        results[file_path] = identifiers
        
        return results
    
    def get_parser_names(self) -> list[str]:
        """
        Get list of registered parser names.
        
        Returns:
            List of parser identifiers.
        """
        return list(self._parsers.keys())


def _filter_contained_hostnames(identifiers: list[DetectedIdentifier]) -> list[DetectedIdentifier]:
    """
    Remove hostname detections whose position range is fully contained within a UPN detection.

    This resolves the collision where the FQDN regex matches the domain portion of a UPN
    (e.g., 'contoso.com' inside 'jsmith@contoso.com'), producing a spurious hostname entry.

    Args:
        identifiers: List of detected identifiers from all parsers.

    Returns:
        Filtered list with contained hostname detections removed.

    # [Agent context: This function uses position-based overlap detection. It
    # compares (start_pos, end_pos) from DetectedIdentifier (frozen dataclass in
    # models.py). The positions are character offsets set by each parser's regex
    # match. Only filters hostnames inside UPNs — other collisions (e.g., IP
    # inside CIDR) are not handled here. No test coverage exists for this
    # function — add tests when working on scanner tests.]
    """
    # Collect UPN ranges
    upn_ranges = [
        (ident.start_pos, ident.end_pos)
        for ident in identifiers
        if ident.identifier_type == "upn"
    ]

    if not upn_ranges:
        return identifiers

    result = []
    for ident in identifiers:
        if ident.identifier_type == "hostname":
            # Check if this hostname is fully contained within any UPN range
            contained = any(
                us <= ident.start_pos and ident.end_pos <= ue
                for us, ue in upn_ranges
            )
            if contained:
                continue
        result.append(ident)

    return result


def scan_files(target_dir: Path, config: Config) -> dict[Path, list[DetectedIdentifier]]:
    """
    Convenience function to scan a directory with default configuration.
    
    Args:
        target_dir: Directory to scan.
        config: Runtime configuration.
        
    Returns:
        Dictionary mapping file paths to their detected identifiers.
    """
    scanner = Scanner(config)
    return scanner.scan_directory(target_dir)
