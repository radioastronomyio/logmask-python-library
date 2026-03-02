"""
Network parser for MAC addresses and UNC paths.

This module detects network-related identifiers:
- MAC addresses: Hardware addresses (e.g., "AA:BB:CC:11:22:33" or "AA-BB-CC-11-22-33")
- UNC paths: Universal Naming Convention paths (e.g., "\\\\server\\share")
"""

import re

from logmask.models import Config, DetectedIdentifier


# MAC address pattern: 6 groups of 2 hex digits separated by colons or hyphens
# Must use word boundaries to avoid false matches
MAC_PATTERN = re.compile(
    r'\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b'
)

# UNC path pattern: \\server\share format
# Must use lookbehind to avoid matching in other contexts
UNC_PATTERN = re.compile(
    r'\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9._$-]+(?:\\[A-Za-z0-9._$-]+)*'
)


def parse(text: str, config: Config) -> list[DetectedIdentifier]:
    """
    Parse text for MAC addresses and UNC paths.
    
    Args:
        text: The text to parse.
        config: Runtime configuration (unused in this parser).
        
    Returns:
        List of DetectedIdentifier objects for each network identifier found.
    """
    identifiers: list[DetectedIdentifier] = []
    
    # Parse MAC addresses
    identifiers.extend(parse_mac(text))
    
    # Parse UNC paths
    identifiers.extend(parse_unc(text))
    
    return identifiers


def parse_mac(text: str) -> list[DetectedIdentifier]:
    """
    Parse text for MAC addresses.
    
    Args:
        text: The text to parse.
        
    Returns:
        List of DetectedIdentifier objects for each MAC address found.
    """
    identifiers: list[DetectedIdentifier] = []
    
    for match in MAC_PATTERN.finditer(text):
        mac = match.group(0)
        
        identifiers.append(
            DetectedIdentifier(
                value=mac,
                identifier_type="mac",
                start_pos=match.start(),
                end_pos=match.end(),
                confidence=1.0,  # High confidence for MAC addresses
            )
        )
    
    return identifiers


def parse_unc(text: str) -> list[DetectedIdentifier]:
    """
    Parse text for UNC paths.
    
    Args:
        text: The text to parse.
        
    Returns:
        List of DetectedIdentifier objects for each UNC path found.
    """
    identifiers: list[DetectedIdentifier] = []
    
    for match in UNC_PATTERN.finditer(text):
        unc = match.group(0)
        
        identifiers.append(
            DetectedIdentifier(
                value=unc,
                identifier_type="unc",
                start_pos=match.start(),
                end_pos=match.end(),
                confidence=0.85,  # Medium-high confidence for UNC paths
            )
        )
    
    return identifiers
