"""
CIDR notation parser for subnet specifications.

This module detects CIDR notation in the format x.x.x.x/N where the IP
portion is an RFC1918 private address and N is the prefix length (0-32).
"""

import re

from logmask.models import Config, DetectedIdentifier


# CIDR pattern matching RFC1918 IP addresses with prefix notation
# Must use \b to avoid matching in other contexts
CIDR_PATTERN = re.compile(
    r'\b('
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # 10.0.0.0/8
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'  # 172.16.0.0/12
    r'192\.168\.\d{1,3}\.\d{1,3}'  # 192.168.0.0/16
    r')/(?:[0-9]|[1-2][0-9]|3[0-2])\b'
)


def parse(text: str, config: Config) -> list[DetectedIdentifier]:
    """
    Parse text for CIDR subnet notation.
    
    Args:
        text: The text to parse.
        config: Runtime configuration (unused in this parser).
        
    Returns:
        List of DetectedIdentifier objects for each CIDR notation found.
    """
    identifiers: list[DetectedIdentifier] = []
    
    for match in CIDR_PATTERN.finditer(text):
        cidr_notation = match.group(0)
        
        # Validate that the IP portion is RFC1918
        ip_address, _ = parse_cidr(cidr_notation)
        
        # Import validate_rfc1918 from ipv4 module
        from logmask.parsers.ipv4 import validate_rfc1918
        
        if validate_rfc1918(ip_address):
            identifiers.append(
                DetectedIdentifier(
                    value=cidr_notation,
                    identifier_type="cidr",
                    start_pos=match.start(),
                    end_pos=match.end(),
                    confidence=1.0,  # High confidence for CIDR notation
                )
            )
    
    return identifiers


def parse_cidr(cidr: str) -> tuple[str, int]:
    """
    Parse a CIDR string into IP and prefix length.
    
    Args:
        cidr: The CIDR notation string (e.g., "192.168.1.0/24").
        
    Returns:
        A tuple of (ip_address, prefix_length).
    """
    if "/" not in cidr:
        raise ValueError(f"Invalid CIDR notation: {cidr}")
    
    ip_address, prefix_str = cidr.split("/")
    
    try:
        prefix_length = int(prefix_str)
        if not 0 <= prefix_length <= 32:
            raise ValueError(f"Invalid prefix length: {prefix_length}")
    except ValueError:
        raise ValueError(f"Invalid prefix length in CIDR: {cidr}")
    
    return ip_address, prefix_length
