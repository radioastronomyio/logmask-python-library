"""
Data models for the logmask package.

This module defines the core dataclasses used throughout the application:
- DetectedIdentifier: Represents a found identifier in text
- MapEntry: Represents a row in the CSV translation map
- Config: Runtime configuration
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class DetectedIdentifier:
    """
    Represents an identifier detected in source text.
    
    This dataclass captures the exact match location and metadata
    for infrastructure identifiers found during scanning.
    
    Attributes:
        value: The exact matched string from the source text.
        identifier_type: The type of identifier (one of: ipv4, cidr, hostname,
            upn, guid, sid, mac, unc).
        start_pos: The start index (0-based) of the match in the source text.
        end_pos: The end index (0-based, exclusive) of the match in the source text.
        confidence: Confidence score from 0.0 to 1.0 indicating how certain the
            parser is that this is a valid identifier.
    """
    value: str
    identifier_type: Literal["ipv4", "cidr", "hostname", "upn", "guid", "sid", "mac", "unc"]
    start_pos: int
    end_pos: int
    confidence: float
    
    def __post_init__(self) -> None:
        """Validate the dataclass fields after initialization."""
        if not 0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {self.confidence}")
        if self.start_pos < 0:
            raise ValueError(f"start_pos must be non-negative, got {self.start_pos}")
        if self.end_pos < self.start_pos:
            raise ValueError(f"end_pos ({self.end_pos}) must be >= start_pos ({self.start_pos})")
        if not self.value:
            raise ValueError("value cannot be empty")
        if len(self.value) != (self.end_pos - self.start_pos):
            raise ValueError(
                f"value length ({len(self.value)}) does not match "
                f"position range ({self.end_pos} - {self.start_pos} = {self.end_pos - self.start_pos})"
            )


@dataclass
class MapEntry:
    """
    Represents a single entry in the CSV translation map.
    
    Each entry maps an original infrastructure identifier to its anonymized
    replacement value, along with metadata about scope and formatting.
    
    Attributes:
        identifier_type: The type of identifier (one of: ipv4, cidr, hostname,
            upn, guid, sid, mac, unc).
        original_value: The exact original identifier string.
        anonymized_value: The generated or user-provided fake value.
        scope: Either "global" for MSP-wide constants or "project" for
            client-specific identifiers.
        preserve_format: Whether structural rules were applied during generation
            (e.g., preserving IP class, hostname structure).
    """
    identifier_type: Literal["ipv4", "cidr", "hostname", "upn", "guid", "sid", "mac", "unc"]
    original_value: str
    anonymized_value: str
    scope: Literal["global", "project"]
    preserve_format: bool
    
    def __post_init__(self) -> None:
        """Validate the dataclass fields after initialization."""
        if not self.original_value:
            raise ValueError("original_value cannot be empty")
        if not self.anonymized_value:
            raise ValueError("anonymized_value cannot be empty")
        if self.scope not in ("global", "project"):
            raise ValueError(f"scope must be 'global' or 'project', got {self.scope}")
        if self.original_value == self.anonymized_value:
            raise ValueError("original_value and anonymized_value cannot be identical")
    
    def to_csv_row(self) -> dict[str, str]:
        """
        Convert to a dictionary suitable for CSV writing.
        
        Returns:
            Dictionary with string values for CSV serialization.
        """
        return {
            "identifier_type": self.identifier_type,
            "original_value": self.original_value,
            "anonymized_value": self.anonymized_value,
            "scope": self.scope,
            "preserve_format": str(self.preserve_format).lower(),
        }
    
    @classmethod
    def from_csv_row(cls, row: dict[str, str]) -> "MapEntry":
        """
        Create a MapEntry from a CSV row dictionary.
        
        Args:
            row: Dictionary with keys matching the CSV schema.
            
        Returns:
            A new MapEntry instance.
        """
        return cls(
            identifier_type=row["identifier_type"],  # type: ignore
            original_value=row["original_value"],
            anonymized_value=row["anonymized_value"],
            scope=row["scope"],  # type: ignore
            preserve_format=row["preserve_format"].lower() == "true",
        )


@dataclass
class Config:
    """
    Runtime configuration for the logmask application.
    
    This dataclass holds paths and settings that control the behavior
    of scanning, anonymization, and map management.
    
    Attributes:
        global_map_path: Path to the global map CSV file located in
            %USERPROFILE%\\.logmask\\global_map.csv.
        project_map_path: Path to the project-specific map CSV file located
            at ./.logmask/project_map.csv relative to the working directory.
        extensions: List of file extensions to include in scanning operations.
    """
    global_map_path: Path
    project_map_path: Path
    extensions: list[str]
    
    def __post_init__(self) -> None:
        """Validate the dataclass fields after initialization."""
        if not self.extensions:
            raise ValueError("extensions cannot be empty")
        for ext in self.extensions:
            if not ext.startswith("."):
                raise ValueError(f"extensions must start with '.', got '{ext}'")
    
    @classmethod
    def default(cls) -> "Config":
        """
        Create a Config instance with default values.
        
        Returns:
            A new Config instance with standard paths and extensions.
        """
        import os
        
        user_profile = Path(os.path.expanduser("~"))
        return cls(
            global_map_path=user_profile / ".logmask" / "global_map.csv",
            project_map_path=Path.cwd() / ".logmask" / "project_map.csv",
            extensions=[".log", ".txt", ".md", ".ps1"],
        )
    
    def ensure_directories(self) -> None:
        """
        Ensure that the directories for map files exist.
        
        Creates parent directories for global_map_path and project_map_path
        if they do not already exist.
        """
        self.global_map_path.parent.mkdir(parents=True, exist_ok=True)
        self.project_map_path.parent.mkdir(parents=True, exist_ok=True)
