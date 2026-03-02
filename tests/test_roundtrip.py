"""
Integration tests for round-trip anonymization and revelation.

This module tests the complete workflow: anonymize → reveal → hash compare.
The critical requirement is that round-trip produces byte-identical output.
"""

import hashlib
import pytest
from pathlib import Path

from logmask.models import Config
from logmask.map_engine import MapEngine
from logmask.replacer import Replacer, anonymize_text, reveal_text


class TestRoundTripWorkflow:
    """Tests for the complete anonymize → reveal workflow."""
    
    def test_roundtrip_text(self, sample_config: Config) -> None:
        """
        Test that anonymize → reveal produces byte-identical original text.
        
        This is the critical integration test for the entire system.
        """
        # Create sample text with identifiers
        text = "Connection from 10.0.1.50 to SQL-PROD-03 by jsmith@contoso.com"
        
        # Create translation map
        mapping = {
            "10.0.1.50": "10.0.187.22",
            "SQL-PROD-03": "SRV-ALPHA-42",
            "jsmith@contoso.com": "user047@fabrikam.com",
        }
        
        # Anonymize text
        anonymized = anonymize_text(text, mapping)
        
        # Reveal anonymized text
        revealed = reveal_text(anonymized, mapping)
        
        # Assert revealed text equals original
        assert revealed == text
    
    def test_roundtrip_file(self, sample_config: Config, temp_directory: Path) -> None:
        """
        Test that anonymize → reveal produces byte-identical original file.

        This tests the complete file workflow including encoding preservation.
        """
        # TODO: Fragile path dependency — reveal_file() calls reveal_text() which
        # loads from sample_config paths (pointing to ~/.logmask/). If those CSV
        # files don't exist on the test machine, reveal silently returns unchanged
        # text and the test still passes by coincidence. Fix: use a config with
        # temp_directory paths and write a CSV map file, like test_reveal_file does.
        # Create input file with identifiers
        input_file = temp_directory / "input.log"
        original_text = "Connection from 10.0.1.50 to SQL-PROD-03"
        input_file.write_text(original_text)
        
        # Create translation map
        mapping = {
            "10.0.1.50": "10.0.187.22",
            "SQL-PROD-03": "SRV-ALPHA-42",
        }
        
        # Anonymize file to output directory
        output_dir = temp_directory / "anonymized"
        output_dir.mkdir()
        output_file = output_dir / "input.log"
        
        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)
        replacer.replace_file(input_file, output_file)
        
        # Reveal anonymized file back
        reveal_dir = temp_directory / "revealed"
        reveal_dir.mkdir()
        revealed_file = reveal_dir / "input.log"
        
        replacer.reveal_file(output_file, revealed_file)
        
        # Read revealed file and compare with original
        revealed_text = revealed_file.read_text()
        assert revealed_text == original_text
    
    def test_roundtrip_directory(self, sample_config: Config, temp_directory: Path) -> None:
        """
        Test that anonymize → reveal produces byte-identical directory contents.
        
        This tests the complete directory workflow.
        """
        # Create input directory with files
        input_dir = temp_directory / "input"
        input_dir.mkdir()
        
        file1_text = "Connection from 10.0.1.50"
        file2_text = "Server SQL-PROD-03"
        file3_text = "User jsmith@contoso.com"
        
        (input_dir / "file1.log").write_text(file1_text)
        (input_dir / "file2.txt").write_text(file2_text)
        (input_dir / "file3.md").write_text(file3_text)
        
        # Create translation map
        mapping = {
            "10.0.1.50": "10.0.187.22",
            "SQL-PROD-03": "SRV-ALPHA-42",
            "jsmith@contoso.com": "user047@fabrikam.com",
        }
        
        # Anonymize directory
        output_dir = temp_directory / "anonymized"
        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)
        replacer.replace_directory(input_dir, output_dir)

        # Reveal directory (build inverted automaton)
        reveal_dir = temp_directory / "revealed"
        inverted_mapping = {v: k for k, v in mapping.items()}
        replacer.build_automaton(inverted_mapping)
        replacer.replace_directory(output_dir, reveal_dir)
        
        # Verify all files are byte-identical to originals
        assert (reveal_dir / "file1.log").read_text() == file1_text
        assert (reveal_dir / "file2.txt").read_text() == file2_text
        assert (reveal_dir / "file3.md").read_text() == file3_text
    
    def test_roundtrip_with_mixed_identifiers(self, sample_config: Config) -> None:
        """
        Test round-trip with all identifier types.
        
        This ensures the workflow works for ipv4, cidr, hostname, upn, guid, sid, mac, unc.
        """
        # Create text with all identifier types
        text = """=== System Log Entry ===
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
        
        # Create mapping covering all types
        mapping = {
            "SQL-PROD-03": "SRV-ALPHA-42",
            "SQL-PROD-03.contoso.local": "SRV-ALPHA-42.fabrikam.local",
            "jsmith@contoso.com": "user047@fabrikam.com",
            "S-1-5-21-123-456-789-1001": "S-1-5-21-999-888-777-2002",
            "10.0.1.50": "10.0.187.22",
            "192.168.100.10": "172.16.50.100",
            "172.16.0.1": "10.10.10.1",
            "192.168.1.0/24": "10.20.30.0/24",
            "AA:BB:CC:11:22:33": "11:22:33:44:55:66",
            "\\\\FILESVR\\Finance$": "\\\\SRV-ALPHA-42\\Data$",
            "f7e8d9c0-1234-5678-90ab-cdef12345678": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        }
        
        # Anonymize text
        anonymized = anonymize_text(text, mapping)
        
        # Reveal anonymized text
        revealed = reveal_text(anonymized, mapping)
        
        # Assert revealed text equals original
        assert revealed == text


class TestHashComparison:
    """Tests for hash-based comparison of round-trip results."""
    
    def test_sha256_hash_comparison(self, sample_config: Config, temp_directory: Path) -> None:
        """Test using SHA256 for hash comparison."""
        # Create input file
        input_file = temp_directory / "input.log"
        original_text = "Connection from 10.0.1.50 to SQL-PROD-03"
        input_file.write_text(original_text)
        
        # Create mapping
        mapping = {
            "10.0.1.50": "10.0.187.22",
            "SQL-PROD-03": "SRV-ALPHA-42",
        }
        
        # Anonymize file
        output_dir = temp_directory / "anonymized"
        output_dir.mkdir()
        output_file = output_dir / "input.log"
        
        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)
        replacer.replace_file(input_file, output_file)
        
        # Reveal file
        reveal_dir = temp_directory / "revealed"
        reveal_dir.mkdir()
        revealed_file = reveal_dir / "input.log"
        replacer.reveal_file(output_file, revealed_file)
        
        # Compute hashes
        original_hash = compute_file_hash(input_file, "sha256")
        revealed_hash = compute_file_hash(revealed_file, "sha256")
        
        # Assert hashes are identical
        assert original_hash == revealed_hash
    
    def test_md5_hash_comparison(self, sample_config: Config, temp_directory: Path) -> None:
        """Test using MD5 for hash comparison."""
        # Create input file
        input_file = temp_directory / "input.log"
        original_text = "Connection from 10.0.1.50 to SQL-PROD-03"
        input_file.write_text(original_text)
        
        # Create mapping
        mapping = {
            "10.0.1.50": "10.0.187.22",
            "SQL-PROD-03": "SRV-ALPHA-42",
        }
        
        # Anonymize file
        output_dir = temp_directory / "anonymized"
        output_dir.mkdir()
        output_file = output_dir / "input.log"
        
        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)
        replacer.replace_file(input_file, output_file)
        
        # Reveal file
        reveal_dir = temp_directory / "revealed"
        reveal_dir.mkdir()
        revealed_file = reveal_dir / "input.log"
        replacer.reveal_file(output_file, revealed_file)
        
        # Compute hashes
        original_hash = compute_file_hash(input_file, "md5")
        revealed_hash = compute_file_hash(revealed_file, "md5")
        
        # Assert hashes are identical
        assert original_hash == revealed_hash
    
    def test_byte_level_comparison(self, sample_config: Config, temp_directory: Path) -> None:
        """Test byte-level comparison without hashing."""
        # Create input file
        input_file = temp_directory / "input.log"
        original_text = "Connection from 10.0.1.50 to SQL-PROD-03"
        input_file.write_text(original_text)
        
        # Create mapping
        mapping = {
            "10.0.1.50": "10.0.187.22",
            "SQL-PROD-03": "SRV-ALPHA-42",
        }
        
        # Anonymize file
        output_dir = temp_directory / "anonymized"
        output_dir.mkdir()
        output_file = output_dir / "input.log"
        
        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)
        replacer.replace_file(input_file, output_file)
        
        # Reveal file
        reveal_dir = temp_directory / "revealed"
        reveal_dir.mkdir()
        revealed_file = reveal_dir / "input.log"
        replacer.reveal_file(output_file, revealed_file)
        
        # Read bytes and compare directly
        original_bytes = input_file.read_bytes()
        revealed_bytes = revealed_file.read_bytes()
        
        # Assert bytes are identical
        assert original_bytes == revealed_bytes


class TestRoundTripEdgeCases:
    """Tests for edge cases in round-trip workflow."""
    
    def test_roundtrip_empty_text(self, sample_config: Config) -> None:
        """Test round-trip with empty text."""
        # Empty text
        text = ""
        
        # Empty mapping
        mapping = {}
        
        # Anonymize and reveal
        anonymized = anonymize_text(text, mapping)
        revealed = reveal_text(anonymized, mapping)
        
        # Assert empty string round-trips to empty string
        assert revealed == ""
    
    def test_roundtrip_no_identifiers(self, sample_config: Config) -> None:
        """Test round-trip with text containing no identifiers."""
        # Text with no identifiers
        text = "This is plain text with no infrastructure identifiers"
        
        # Empty mapping
        mapping = {}
        
        # Anonymize and reveal
        anonymized = anonymize_text(text, mapping)
        revealed = reveal_text(anonymized, mapping)
        
        # Assert text comes back identical
        assert revealed == text
    
    def test_roundtrip_single_identifier(self, sample_config: Config) -> None:
        """Test round-trip with a single identifier."""
        # Text with single identifier
        text = "Connection from 10.0.1.50"
        
        # Mapping with single entry
        mapping = {
            "10.0.1.50": "10.0.187.22",
        }
        
        # Anonymize and reveal
        anonymized = anonymize_text(text, mapping)
        revealed = reveal_text(anonymized, mapping)
        
        # Assert text comes back identical
        assert revealed == text
    
    def test_roundtrip_repeated_identifier(self, sample_config: Config) -> None:
        """Test round-trip with the same identifier repeated multiple times."""
        # Text with repeated identifier
        text = "Server 10.0.1.50 is at 10.0.1.50 and 10.0.1.50 again"
        
        # Mapping
        mapping = {
            "10.0.1.50": "10.0.187.22",
        }
        
        # Anonymize and reveal
        anonymized = anonymize_text(text, mapping)
        revealed = reveal_text(anonymized, mapping)
        
        # Assert text comes back identical
        assert revealed == text
    
    def test_roundtrip_overlapping_identifiers(self, sample_config: Config) -> None:
        """
        Test round-trip with overlapping identifiers.
        
        Example: 10.0.0.100 and 10.0.0.1 at the same position.
        """
        # Text with longer identifier
        text = "Server at 10.0.0.100 is responding"
        
        # Mapping with overlapping identifiers
        mapping = {
            "10.0.0.1": "192.168.1.1",
            "10.0.0.100": "192.168.1.100",
        }
        
        # Anonymize and reveal
        anonymized = anonymize_text(text, mapping)
        revealed = reveal_text(anonymized, mapping)
        
        # Assert text comes back identical (longest match wins)
        assert revealed == text


class TestRoundTripWithMapScopes:
    """Tests for round-trip with different map scopes."""
    
    def test_roundtrip_global_map_only(self, sample_config: Config, temp_directory: Path) -> None:
        """Test round-trip using only global map."""
        # Create global map
        global_map_path = temp_directory / "global_map.csv"
        global_map_path.parent.mkdir(parents=True, exist_ok=True)
        
        csv_content = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,10.0.1.50,10.0.187.22,global,true
hostname,SQL-PROD-03,SRV-ALPHA-42,global,true
"""
        global_map_path.write_text(csv_content)
        
        # Create empty project map
        project_map_path = temp_directory / "project_map.csv"
        project_map_path.parent.mkdir(parents=True, exist_ok=True)
        project_map_path.write_text("identifier_type,original_value,anonymized_value,scope,preserve_format\n")
        
        # Create config with custom paths
        config = Config(
            global_map_path=global_map_path,
            project_map_path=project_map_path,
            extensions=sample_config.extensions,
        )
        
        # Create input file
        input_file = temp_directory / "input.log"
        original_text = "Connection from 10.0.1.50 to SQL-PROD-03"
        input_file.write_text(original_text)
        
        # Anonymize and reveal using Replacer with config
        output_dir = temp_directory / "anonymized"
        output_dir.mkdir()
        output_file = output_dir / "input.log"
        
        replacer = Replacer(config)
        replacer.replace_file(input_file, output_file)
        
        reveal_dir = temp_directory / "revealed"
        reveal_dir.mkdir()
        revealed_file = reveal_dir / "input.log"
        replacer.reveal_file(output_file, revealed_file)
        
        # Assert revealed text equals original
        revealed_text = revealed_file.read_text()
        assert revealed_text == original_text
    
    def test_roundtrip_project_map_only(self, sample_config: Config, temp_directory: Path) -> None:
        """Test round-trip using only project map."""
        # Create empty global map
        global_map_path = temp_directory / "global_map.csv"
        global_map_path.parent.mkdir(parents=True, exist_ok=True)
        global_map_path.write_text("identifier_type,original_value,anonymized_value,scope,preserve_format\n")
        
        # Create project map
        project_map_path = temp_directory / "project_map.csv"
        project_map_path.parent.mkdir(parents=True, exist_ok=True)
        
        csv_content = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,10.0.1.50,10.0.187.22,project,true
hostname,SQL-PROD-03,SRV-ALPHA-42,project,true
"""
        project_map_path.write_text(csv_content)
        
        # Create config with custom paths
        config = Config(
            global_map_path=global_map_path,
            project_map_path=project_map_path,
            extensions=sample_config.extensions,
        )
        
        # Create input file
        input_file = temp_directory / "input.log"
        original_text = "Connection from 10.0.1.50 to SQL-PROD-03"
        input_file.write_text(original_text)
        
        # Anonymize and reveal using Replacer with config
        output_dir = temp_directory / "anonymized"
        output_dir.mkdir()
        output_file = output_dir / "input.log"
        
        replacer = Replacer(config)
        replacer.replace_file(input_file, output_file)
        
        reveal_dir = temp_directory / "revealed"
        reveal_dir.mkdir()
        revealed_file = reveal_dir / "input.log"
        replacer.reveal_file(output_file, revealed_file)
        
        # Assert revealed text equals original
        revealed_text = revealed_file.read_text()
        assert revealed_text == original_text
    
    def test_roundtrip_merged_maps(self, sample_config: Config, temp_directory: Path) -> None:
        """Test round-trip using merged global and project maps."""
        # Create global map
        global_map_path = temp_directory / "global_map.csv"
        global_map_path.parent.mkdir(parents=True, exist_ok=True)
        
        global_csv = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,10.0.1.50,10.0.187.22,global,true
hostname,SQL-PROD-03,SRV-ALPHA-42,global,true
"""
        global_map_path.write_text(global_csv)
        
        # Create project map (project overrides global on collision)
        project_map_path = temp_directory / "project_map.csv"
        project_map_path.parent.mkdir(parents=True, exist_ok=True)
        
        project_csv = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,192.168.1.100,172.16.50.100,project,true
"""
        project_map_path.write_text(project_csv)
        
        # Create config with custom paths
        config = Config(
            global_map_path=global_map_path,
            project_map_path=project_map_path,
            extensions=sample_config.extensions,
        )
        
        # Create input file with identifiers from both maps
        input_file = temp_directory / "input.log"
        original_text = "Connection from 10.0.1.50 to 192.168.1.100 via SQL-PROD-03"
        input_file.write_text(original_text)
        
        # Anonymize and reveal using Replacer with config
        output_dir = temp_directory / "anonymized"
        output_dir.mkdir()
        output_file = output_dir / "input.log"
        
        replacer = Replacer(config)
        replacer.replace_file(input_file, output_file)
        
        reveal_dir = temp_directory / "revealed"
        reveal_dir.mkdir()
        revealed_file = reveal_dir / "input.log"
        replacer.reveal_file(output_file, revealed_file)
        
        # Assert revealed text equals original
        revealed_text = revealed_file.read_text()
        assert revealed_text == original_text


def compute_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """
    Compute hash of a file.
    
    Args:
        file_path: Path to the file.
        algorithm: Hash algorithm to use (sha256, md5, etc.).
        
    Returns:
        Hexadecimal hash string.
    """
    hash_func = hashlib.new(algorithm)
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()
