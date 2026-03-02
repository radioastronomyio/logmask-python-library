"""
Pytest configuration and synthetic log fixtures.

This module provides pytest fixtures for testing logmask functionality.
All fixtures use synthetic data - no real client data is included.
"""

import pytest
from pathlib import Path
from typing import Literal

from logmask.models import Config, DetectedIdentifier, MapEntry


# Synthetic log fixtures - NO real client data


@pytest.fixture
def sample_log_with_ipv4() -> str:
    """
    Synthetic log containing RFC1918 IPv4 addresses.
    
    Returns:
        A log string with embedded IPv4 addresses.
    """
    return """2025-03-01 10:15:23 INFO Connection established from 10.0.1.50
2025-03-01 10:15:24 INFO Forwarding to 192.168.100.10
2025-03-01 10:15:25 INFO Gateway at 172.16.0.1 responding
2025-03-01 10:15:26 INFO Database at 10.255.255.254 connected
2025-03-01 10:15:27 INFO Backup server 192.168.1.200 online
"""


@pytest.fixture
def sample_log_with_cidr() -> str:
    """
    Synthetic log containing CIDR subnet notation.
    
    Returns:
        A log string with embedded CIDR notation.
    """
    return """Network configuration:
- Subnet: 192.168.1.0/24
- Gateway: 10.0.0.1/16
- VLAN: 172.16.10.0/24
- DMZ: 10.10.10.0/24
"""


@pytest.fixture
def sample_log_with_hostnames() -> str:
    """
    Synthetic log containing NetBIOS names and FQDNs.
    
    Returns:
        A log string with embedded hostnames.
    """
    return """2025-03-01 10:00:00 INFO SQL-PROD-03 starting up
2025-03-01 10:00:01 INFO Connecting to DC-PRIMARY.contoso.local
2025-03-01 10:00:02 INFO File server FILESVR-01 responding
2025-03-01 10:00:03 INFO Exchange at MAIL.contoso.local ready
2025-03-01 10:00:04 INFO Backup target BACKUP-02.fabrikam.local
"""


@pytest.fixture
def sample_log_with_identity() -> str:
    """
    Synthetic log containing UPNs, GUIDs, and SIDs.
    
    Returns:
        A log string with embedded identity identifiers.
    """
    return """User authentication:
- UPN: jsmith@contoso.com
- UPN: admin@fabrikam.local
- Object GUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
- User SID: S-1-5-21-1234567890-1234567890-1234567890-1001
- Group SID: S-1-5-21-9876543210-9876543210-9876543210-512
"""


@pytest.fixture
def sample_log_with_network() -> str:
    """
    Synthetic log containing MAC addresses and UNC paths.
    
    Returns:
        A log string with embedded network identifiers.
    """
    return """Network devices:
- Switch: AA:BB:CC:11:22:33
- Router: 11-22-33-44-55-66
- Server MAC: DD:EE:FF:AA:BB:CC
- UNC path: \\\\FILESVR\\Finance$
- Backup: \\\\BACKUP-02\\Data\\Archive
"""


@pytest.fixture
def sample_log_mixed() -> str:
    """
    Synthetic log containing mixed identifier types.
    
    Returns:
        A log string with embedded identifiers of all types.
    """
    return """=== System Log Entry ===
Timestamp: 2025-03-01T10:15:23.456Z
Source: SQL-PROD-03.contoso.local
User: jsmith@contoso.com (S-1-5-21-123-456-789-1001)

Connection established from 10.0.1.50:54321
Forwarding to 192.168.100.10:443
Gateway: 172.16.0.1
Subnet: 192.168.1.0/24

MAC address: AA:BB:CC:11:22:33
UNC path: \\\\FILESVR\\Finance$

Object ID: f7e8d9c0-1234-5678-90ab-cdef12345678
"""


@pytest.fixture
def sample_config() -> Config:
    """
    Create a sample Config for testing.
    
    Returns:
        A Config instance with test paths.
    """
    return Config(
        global_map_path=Path.home() / ".logmask" / "global_map.csv",
        project_map_path=Path.cwd() / ".logmask" / "project_map.csv",
        extensions=[".log", ".txt", ".md", ".ps1"],
    )


@pytest.fixture
def sample_map_entries() -> list[MapEntry]:
    """
    Create sample MapEntry objects for testing.
    
    Returns:
        A list of MapEntry objects.
    """
    return [
        MapEntry(
            identifier_type="ipv4",
            original_value="10.0.1.50",
            anonymized_value="10.0.187.22",
            scope="project",
            preserve_format=True,
        ),
        MapEntry(
            identifier_type="hostname",
            original_value="SQL-PROD-03",
            anonymized_value="SRV-ALPHA-42",
            scope="project",
            preserve_format=True,
        ),
        MapEntry(
            identifier_type="upn",
            original_value="jsmith@contoso.com",
            anonymized_value="user047@fabrikam.com",
            scope="project",
            preserve_format=True,
        ),
        MapEntry(
            identifier_type="guid",
            original_value="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            anonymized_value="f7e8d9c0-1234-5678-90ab-cdef12345678",
            scope="global",
            preserve_format=False,
        ),
    ]


@pytest.fixture
def sample_detected_identifiers() -> list[DetectedIdentifier]:
    """
    Create sample DetectedIdentifier objects for testing.
    
    Returns:
        A list of DetectedIdentifier objects.
    """
    return [
        DetectedIdentifier(
            value="10.0.1.50",
            identifier_type="ipv4",
            start_pos=50,
            end_pos=59,
            confidence=1.0,
        ),
        DetectedIdentifier(
            value="SQL-PROD-03",
            identifier_type="hostname",
            start_pos=100,
            end_pos=111,
            confidence=0.85,
        ),
        DetectedIdentifier(
            value="jsmith@contoso.com",
            identifier_type="upn",
            start_pos=150,
            end_pos=167,
            confidence=0.9,
        ),
    ]


@pytest.fixture
def temp_directory(tmp_path: Path) -> Path:
    """
    Create a temporary directory for file operations.
    
    Args:
        tmp_path: Pytest's built-in temporary path fixture.
        
    Returns:
        Path to a temporary directory.
    """
    return tmp_path


@pytest.fixture
def sample_log_file(temp_directory: Path) -> Path:
    """
    Create a sample log file in a temporary directory.
    
    Args:
        temp_directory: Temporary directory fixture.
        
    Returns:
        Path to the created sample log file.
    """
    # BUG: sample_log_mixed is a pytest fixture function, not a decorated function.
    # Accessing .__wrapped__() will raise AttributeError at runtime. This fixture
    # is currently unused so the bug is latent.
    # Fix: Call sample_log_mixed directly (it's a fixture, inject it as a parameter)
    # or use the fixture's return value instead of __wrapped__().
    log_file = temp_directory / "sample.log"
    log_file.write_text(sample_log_mixed.__wrapped__())
    return log_file
