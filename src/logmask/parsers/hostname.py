"""
Hostname parser for NetBIOS and FQDN hostnames.

This module detects hostnames in two forms:
- NetBIOS names: Flat names up to 15 characters (e.g., "SQL-PROD-03")
- FQDNs: Fully Qualified Domain Names with dots (e.g., "server.contoso.local")

NetBIOS detection uses structural heuristics to minimize false positives:
- Contains a hyphen (e.g., SQL-PROD-03, DC-PRIMARY)
- Starts with a known server prefix (SRV-, SQL-, DC-, etc.)
- Is all-uppercase, >= 4 chars, and contains at least one digit (e.g., FILESVR01)
"""

import re

from logmask.models import Config, DetectedIdentifier


# NetBIOS pattern: 1-15 alphanumeric characters with hyphens
# Must use word boundaries to avoid matching in paths, URLs, etc.
NETBIOS_PATTERN = re.compile(
    r'\b[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?\b'
)

# FQDN pattern: labels separated by dots, ending with a TLD-like suffix
# Must use word boundaries to avoid matching in paths, URLs, etc.
FQDN_PATTERN = re.compile(
    r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b'
)

# Known server prefix patterns (case-insensitive)
_SERVER_PREFIXES = (
    "SRV-", "SQL-", "DB-", "DC-", "WEB-", "APP-", "FILE-", "MAIL-",
    "EXCH-", "BACKUP-", "FS-", "RDS-", "VPN-", "FW-", "GW-", "PRINT-",
    "WSUS-", "SCCM-", "SCOM-", "PKI-", "CA-", "NPS-", "ADFS-", "AAD-",
    "HV-", "VMW-", "ESX-",
)


def _is_structural_netbios(name: str) -> bool:
    """
    Check if a NetBIOS match has structural signals indicating a real hostname.

    A match qualifies if any of:
    - Contains a hyphen (e.g., SQL-PROD-03, DC-PRIMARY)
    - Starts with a known server prefix (case-insensitive)
    - Is all-uppercase, >= 4 characters, and contains at least one digit

    Args:
        name: The matched string to evaluate.

    Returns:
        True if the name has structural hostname signals.
    """
    # Contains a hyphen
    if "-" in name:
        return True

    # Starts with a known server prefix
    name_upper = name.upper()
    for prefix in _SERVER_PREFIXES:
        if name_upper.startswith(prefix):
            return True

    # All-uppercase, >= 4 chars, contains at least one digit
    if name.isupper() and len(name) >= 4 and any(c.isdigit() for c in name):
        return True

    return False


def parse(text: str, config: Config) -> list[DetectedIdentifier]:
    """
    Parse text for NetBIOS names and FQDNs.

    Args:
        text: The text to parse.
        config: Runtime configuration (unused in this parser).

    Returns:
        List of DetectedIdentifier objects for each hostname found.
    """
    identifiers: list[DetectedIdentifier] = []

    # Find FQDN matches first
    fqdn_matches = list(FQDN_PATTERN.finditer(text))
    for match in fqdn_matches:
        hostname_val = match.group(0)
        hostname_val = filter_false_positives_single(hostname_val)
        if hostname_val is not None:
            confidence = _calculate_confidence(hostname_val, "fqdn", text, match.start())
            identifiers.append(
                DetectedIdentifier(
                    value=hostname_val,
                    identifier_type="hostname",
                    start_pos=match.start(),
                    end_pos=match.end(),
                    confidence=confidence,
                )
            )

    # Collect FQDN ranges to avoid double-matching NetBIOS within FQDNs
    fqdn_ranges = [(m.start(), m.end()) for m in fqdn_matches]

    # Find NetBIOS matches with structural heuristic gate
    for match in NETBIOS_PATTERN.finditer(text):
        name = match.group(0)
        start, end = match.start(), match.end()

        # Skip if this match is inside an FQDN match
        if any(fs <= start and end <= fe for fs, fe in fqdn_ranges):
            continue

        # Apply structural heuristic gate
        if not _is_structural_netbios(name):
            continue

        # Apply secondary false-positive filter
        if filter_false_positives_single(name) is None:
            continue

        confidence = _calculate_confidence(name, "netbios", text, start)
        identifiers.append(
            DetectedIdentifier(
                value=name,
                identifier_type="hostname",
                start_pos=start,
                end_pos=end,
                confidence=confidence,
            )
        )

    return identifiers


def _calculate_confidence(hostname: str, match_type: str, text: str, pos: int) -> float:
    """
    Calculate confidence score for a hostname based on context.

    Args:
        hostname: The matched hostname.
        match_type: Either "netbios" or "fqdn".
        text: The full text being parsed.
        pos: The position of the match in the text.

    Returns:
        Confidence score between 0.0 and 1.0.
    """
    # Base confidence
    confidence = 0.7 if match_type == "netbios" else 0.8

    # Infrastructure keywords that suggest higher confidence
    infrastructure_keywords = [
        "server", "host", "node", "machine", "computer", "desktop",
        "laptop", "sql", "db", "database", "exchange", "mail", "file",
        "backup", "dc", "domain", "controller", "gateway", "router",
        "switch", "firewall", "proxy", "web", "app", "service"
    ]

    # Check for infrastructure keywords in hostname
    hostname_lower = hostname.lower()
    for keyword in infrastructure_keywords:
        if keyword in hostname_lower:
            confidence += 0.1
            break

    # Check for context clues (surrounding text)
    context_window = 100  # characters before and after
    start = max(0, pos - context_window)
    end = min(len(text), pos + len(hostname) + context_window)
    context = text[start:end].lower()

    context_boosters = [
        "connecting to", "connected to", "connection from", "server",
        "hostname", "host:", "target:", "destination:", "source:",
        "forwarding to", "gateway at", "database at", "backup server"
    ]

    for booster in context_boosters:
        if booster in context:
            confidence += 0.1
            break

    # Cap confidence at 0.95 for hostnames (never 1.0 due to false positive risk)
    return min(confidence, 0.95)


_FILE_EXTENSIONS = {
    "txt", "log", "md", "ps1", "py", "js", "html", "css", "json", "xml",
    "csv", "sql", "db", "bak", "tmp", "old", "new", "cfg", "conf", "ini",
    "yml", "yaml", "toml", "properties", "env", "dockerfile", "exe", "dll",
    "zip", "gz", "tar", "rar", "pdf", "doc", "docx", "xls", "xlsx", "png",
    "jpg", "jpeg", "gif", "svg", "ico",
}


def filter_false_positives_single(hostname: str) -> str | None:
    """
    Check a single hostname candidate for obvious false positives.

    Args:
        hostname: The hostname candidate.

    Returns:
        The hostname if it passes, or None if it's a false positive.
    """
    if not hostname or len(hostname) == 1:
        return None

    # Skip pure digits
    if hostname.isdigit():
        return None

    # Skip if it has invalid characters for hostnames
    invalid_chars = set(" /\\:;|<>\"'`~!@#$%^&*()+=[]{}?,")
    if any(char in hostname for char in invalid_chars):
        return None

    # Skip FQDNs that look like filenames (end with a file extension)
    if "." in hostname:
        last_part = hostname.rsplit(".", 1)[-1].lower()
        if last_part in _FILE_EXTENSIONS:
            return None

    # Skip date-like patterns (e.g., 2025-03-01)
    if re.match(r'^\d{4}-\d{2}-\d{2}$', hostname):
        return None

    return hostname


def filter_false_positives(hostnames: list[str]) -> list[str]:
    """
    Filter out obvious false positives from hostname detection.

    Args:
        hostnames: List of potential hostnames.

    Returns:
        Filtered list with likely false positives removed.
    """
    filtered = []
    for hostname in hostnames:
        result = filter_false_positives_single(hostname)
        if result is not None:
            filtered.append(result)
    return filtered
