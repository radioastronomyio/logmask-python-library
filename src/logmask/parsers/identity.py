"""
Identity parser for UPNs, Entra GUIDs, and Windows SIDs.

This module detects identity-related identifiers:
- UPNs: User Principal Names (e.g., "user@domain.com")
- GUIDs: Globally Unique Identifiers (e.g., "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
- SIDs: Windows Security Identifiers (e.g., "S-1-5-21-123-456-789-1001")
"""

import re

from logmask.models import Config, DetectedIdentifier


# UPN pattern: local-part@domain format
# Must use word boundaries to avoid matching in email-like contexts
UPN_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
)

# GUID pattern: 8-4-4-4-12 hex digits with dashes
# Must use word boundaries to avoid false matches
GUID_PATTERN = re.compile(
    r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
)

# SID pattern: S-1-5-21-... format for Windows SIDs
# Must use word boundaries to avoid false matches
SID_PATTERN = re.compile(
    r'\bS-1-5-21-\d+(?:-\d+)+\b'
)


def parse(text: str, config: Config) -> list[DetectedIdentifier]:
    """
    Parse text for UPNs, GUIDs, and SIDs.
    
    Args:
        text: The text to parse.
        config: Runtime configuration (unused in this parser).
        
    Returns:
        List of DetectedIdentifier objects for each identity found.
    """
    identifiers: list[DetectedIdentifier] = []
    
    # Parse UPNs
    identifiers.extend(parse_upn(text))
    
    # Parse GUIDs
    identifiers.extend(parse_guid(text))
    
    # Parse SIDs
    identifiers.extend(parse_sid(text))
    
    return identifiers


def parse_upn(text: str) -> list[DetectedIdentifier]:
    """
    Parse text for User Principal Names (UPNs).
    
    Args:
        text: The text to parse.
        
    Returns:
        List of DetectedIdentifier objects for each UPN found.
    """
    identifiers: list[DetectedIdentifier] = []
    
    # Public email domains to exclude (not corporate UPNs)
    public_domains = {
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
        "icloud.com", "protonmail.com", "mail.com", "gmx.com", "zoho.com"
    }
    
    # Generic local parts to exclude ONLY when combined with public domains
    generic_local_parts = {
        "info", "support", "contact", "sales", "help",
        "webmaster", "postmaster", "abuse", "noreply", "no-reply"
    }
    
    for match in UPN_PATTERN.finditer(text):
        upn = match.group(0)
        
        # Extract domain part
        if "@" in upn:
            domain = upn.split("@")[1].lower()
            local_part = upn.split("@")[0].lower()
            
            # Skip public email domains
            if domain in public_domains:
                continue

        identifiers.append(
            DetectedIdentifier(
                value=upn,
                identifier_type="upn",
                start_pos=match.start(),
                end_pos=match.end(),
                confidence=0.9,  # Medium-high confidence for UPNs
            )
        )
    
    return identifiers


def parse_guid(text: str) -> list[DetectedIdentifier]:
    """
    Parse text for GUIDs.
    
    Args:
        text: The text to parse.
        
    Returns:
        List of DetectedIdentifier objects for each GUID found.
    """
    identifiers: list[DetectedIdentifier] = []
    
    for match in GUID_PATTERN.finditer(text):
        guid = match.group(0)
        
        identifiers.append(
            DetectedIdentifier(
                value=guid,
                identifier_type="guid",
                start_pos=match.start(),
                end_pos=match.end(),
                confidence=1.0,  # High confidence for GUIDs
            )
        )
    
    return identifiers


def parse_sid(text: str) -> list[DetectedIdentifier]:
    """
    Parse text for Windows SIDs.
    
    Args:
        text: The text to parse.
        
    Returns:
        List of DetectedIdentifier objects for each SID found.
    """
    identifiers: list[DetectedIdentifier] = []
    
    for match in SID_PATTERN.finditer(text):
        sid = match.group(0)
        
        identifiers.append(
            DetectedIdentifier(
                value=sid,
                identifier_type="sid",
                start_pos=match.start(),
                end_pos=match.end(),
                confidence=1.0,  # High confidence for SIDs
            )
        )
    
    return identifiers
