"""
IPv4 address parser for RFC1918 private IP addresses.

This module detects IPv4 addresses in the RFC1918 private ranges:
- 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
- 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
- 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
"""

import re

from logmask.models import Config, DetectedIdentifier


# RFC1918 IPv4 pattern with word boundaries
# Must use \b to avoid matching in timestamps, version numbers, etc.
RFC1918_PATTERN = re.compile(
    r'\b('
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # 10.0.0.0/8
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'  # 172.16.0.0/12
    r'192\.168\.\d{1,3}\.\d{1,3}'  # 192.168.0.0/16
    r')\b'
)


def parse(text: str, config: Config) -> list[DetectedIdentifier]:
    """
    Parse text for RFC1918 IPv4 addresses.
    
    Args:
        text: The text to parse.
        config: Runtime configuration (unused in this parser).
        
    Returns:
        List of DetectedIdentifier objects for each RFC1918 IPv4 address found.
    """
    identifiers: list[DetectedIdentifier] = []
    
    for match in RFC1918_PATTERN.finditer(text):
        ip_address = match.group(0)
        
        # Validate that the IP is actually in RFC1918 range
        # (the regex catches the pattern, but we need to validate octet ranges)
        if validate_rfc1918(ip_address):
            identifiers.append(
                DetectedIdentifier(
                    value=ip_address,
                    identifier_type="ipv4",
                    start_pos=match.start(),
                    end_pos=match.end(),
                    confidence=1.0,  # High confidence for RFC1918
                )
            )
    
    return identifiers


def validate_rfc1918(ip: str) -> bool:
    """
    Validate that an IP address is in RFC1918 private range.

    Args:
        ip: The IP address string to validate.

    Returns:
        True if the IP is in RFC1918 range, False otherwise.
    """
    try:
        octets = ip.split(".")
        if len(octets) != 4:
            return False

        first = int(octets[0])
        second = int(octets[1])

        # Validate all octets are in valid range (0-255)
        if not all(0 <= int(o) <= 255 for o in octets):
            return False

        # 10.0.0.0/8
        if first == 10:
            return True

        # 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
        if first == 172 and 16 <= second <= 31:
            return True

        # 192.168.0.0/16
        if first == 192 and second == 168:
            return True

        return False
    except (ValueError, IndexError):
        return False
