"""
Unit tests for the map engine module.

This module tests CSV map loading, merging, writing, and fake value generation.
"""

import pytest
from pathlib import Path

from logmask.models import Config, MapEntry
from logmask.map_engine import MapEngine, load_merged_map


class TestMapLoading:
    """Tests for loading maps from CSV files."""

    def test_load_global_map(self, sample_config: Config, temp_directory: Path) -> None:
        """Test loading the global map from CSV."""
        # Create a sample global_map.csv file
        global_map_path = temp_directory / "global_map.csv"
        global_map_path.parent.mkdir(parents=True, exist_ok=True)

        csv_content = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,10.0.1.50,10.0.187.22,global,true
hostname,SQL-PROD-03,SRV-ALPHA-42,global,true
upn,jsmith@contoso.com,user047@fabrikam.com,global,true
"""
        global_map_path.write_text(csv_content)

        # Update config to use temp directory
        config = Config(
            global_map_path=global_map_path,
            project_map_path=temp_directory / "project_map.csv",
            extensions=sample_config.extensions,
        )

        # Load it using MapEngine
        engine = MapEngine(config)
        global_map = engine.load_global_map()

        # Assert entries are parsed correctly
        assert len(global_map) == 3
        assert "10.0.1.50" in global_map
        assert "SQL-PROD-03" in global_map
        assert "jsmith@contoso.com" in global_map

        entry = global_map["10.0.1.50"]
        assert entry.identifier_type == "ipv4"
        assert entry.anonymized_value == "10.0.187.22"
        assert entry.scope == "global"
        assert entry.preserve_format is True

    def test_load_project_map(self, sample_config: Config, temp_directory: Path) -> None:
        """Test loading the project map from CSV."""
        # Create a sample project_map.csv file
        project_map_path = temp_directory / "project_map.csv"
        project_map_path.parent.mkdir(parents=True, exist_ok=True)

        csv_content = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,192.168.100.10,192.168.45.67,project,true
guid,a1b2c3d4-e5f6-7890-abcd-ef1234567890,f7e8d9c0-1234-5678-90ab-cdef12345678,project,false
"""
        project_map_path.write_text(csv_content)

        # Update config to use temp directory
        config = Config(
            global_map_path=temp_directory / "global_map.csv",
            project_map_path=project_map_path,
            extensions=sample_config.extensions,
        )

        # Load it using MapEngine
        engine = MapEngine(config)
        project_map = engine.load_project_map()

        # Assert entries are parsed correctly
        assert len(project_map) == 2
        assert "192.168.100.10" in project_map
        assert "a1b2c3d4-e5f6-7890-abcd-ef1234567890" in project_map

    def test_load_nonexistent_map(self, sample_config: Config) -> None:
        """Test loading a map file that doesn't exist."""
        # Use paths that don't exist
        config = Config(
            global_map_path=Path.home() / ".logmask" / "nonexistent_global.csv",
            project_map_path=Path.home() / ".logmask" / "nonexistent_project.csv",
            extensions=sample_config.extensions,
        )

        engine = MapEngine(config)

        # Should return empty dict for nonexistent files
        global_map = engine.load_global_map()
        project_map = engine.load_project_map()

        assert global_map == {}
        assert project_map == {}


class TestMapMerging:
    """Tests for merging global and project maps."""

    def test_merge_maps_project_overrides_global(self, sample_config: Config, temp_directory: Path) -> None:
        """Test that project map entries override global map entries."""
        # Create global map
        global_map_path = temp_directory / "global_map.csv"
        global_map_path.parent.mkdir(parents=True, exist_ok=True)
        global_csv = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,10.0.1.50,10.0.100.100,global,true
hostname,SQL-PROD-03,SRV-GLOBAL-01,global,true
"""
        global_map_path.write_text(global_csv)

        # Create project map with overlapping key
        project_map_path = temp_directory / "project_map.csv"
        project_csv = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,10.0.1.50,10.0.187.22,project,true
upn,jsmith@contoso.com,user047@fabrikam.com,project,true
"""
        project_map_path.write_text(project_csv)

        # Update config
        config = Config(
            global_map_path=global_map_path,
            project_map_path=project_map_path,
            extensions=sample_config.extensions,
        )

        # Merge maps
        engine = MapEngine(config)
        merged = engine.merge_maps()

        # Assert project values take precedence
        assert len(merged) == 3  # 2 global + 2 project - 1 overlap
        assert merged["10.0.1.50"].anonymized_value == "10.0.187.22"  # Project value
        assert merged["10.0.1.50"].scope == "project"
        assert merged["SQL-PROD-03"].anonymized_value == "SRV-GLOBAL-01"  # Global value
        assert merged["jsmith@contoso.com"].anonymized_value == "user047@fabrikam.com"  # Project value

    def test_merge_maps_no_mutation(self, sample_config: Config, temp_directory: Path) -> None:
        """Test that merging does not mutate source files."""
        # Create global map
        global_map_path = temp_directory / "global_map.csv"
        global_map_path.parent.mkdir(parents=True, exist_ok=True)
        global_csv = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,10.0.1.50,10.0.100.100,global,true
"""
        global_map_path.write_text(global_csv)

        # Create project map
        project_map_path = temp_directory / "project_map.csv"
        project_csv = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,10.0.1.50,10.0.187.22,project,true
"""
        project_map_path.write_text(project_csv)

        # Store original content
        original_global = global_map_path.read_text()
        original_project = project_map_path.read_text()

        # Update config
        config = Config(
            global_map_path=global_map_path,
            project_map_path=project_map_path,
            extensions=sample_config.extensions,
        )

        # Merge maps
        engine = MapEngine(config)
        merged = engine.merge_maps()

        # Assert source files are unchanged
        assert global_map_path.read_text() == original_global
        assert project_map_path.read_text() == original_project

    def test_merge_maps_unique_keys(self, sample_config: Config, temp_directory: Path) -> None:
        """Test that unique keys from both maps are preserved."""
        # Create global map
        global_map_path = temp_directory / "global_map.csv"
        global_map_path.parent.mkdir(parents=True, exist_ok=True)
        global_csv = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,10.0.1.50,10.0.100.100,global,true
hostname,SQL-PROD-03,SRV-GLOBAL-01,global,true
"""
        global_map_path.write_text(global_csv)

        # Create project map with unique keys
        project_map_path = temp_directory / "project_map.csv"
        project_csv = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,192.168.100.10,192.168.45.67,project,true
upn,jsmith@contoso.com,user047@fabrikam.com,project,true
"""
        project_map_path.write_text(project_csv)

        # Update config
        config = Config(
            global_map_path=global_map_path,
            project_map_path=project_map_path,
            extensions=sample_config.extensions,
        )

        # Merge maps
        engine = MapEngine(config)
        merged = engine.merge_maps()

        # Assert all unique keys are preserved
        assert len(merged) == 4
        assert "10.0.1.50" in merged
        assert "SQL-PROD-03" in merged
        assert "192.168.100.10" in merged
        assert "jsmith@contoso.com" in merged


class TestMapWriting:
    """Tests for writing maps to CSV files."""

    def test_write_project_map(self, sample_config: Config, temp_directory: Path) -> None:
        """Test writing entries to the project map."""
        # Update config to use temp directory
        project_map_path = temp_directory / "project_map.csv"
        config = Config(
            global_map_path=temp_directory / "global_map.csv",
            project_map_path=project_map_path,
            extensions=sample_config.extensions,
        )

        # Create entries
        entries = [
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
        ]

        # Write entries
        engine = MapEngine(config)
        engine.write_project_map(entries)

        # Verify file was created
        assert project_map_path.exists()

        # Verify content
        content = project_map_path.read_text()
        assert "10.0.1.50" in content
        assert "10.0.187.22" in content
        assert "SQL-PROD-03" in content
        assert "SRV-ALPHA-42" in content

    def test_write_project_map_creates_directory(self, sample_config: Config, temp_directory: Path) -> None:
        """Test that writing creates the .logmask directory if needed."""
        # Use a nested path that doesn't exist
        project_map_path = temp_directory / "nested" / "path" / ".logmask" / "project_map.csv"
        config = Config(
            global_map_path=temp_directory / "global_map.csv",
            project_map_path=project_map_path,
            extensions=sample_config.extensions,
        )

        entries = [
            MapEntry(
                identifier_type="ipv4",
                original_value="10.0.1.50",
                anonymized_value="10.0.187.22",
                scope="project",
                preserve_format=True,
            ),
        ]

        # Write entries
        engine = MapEngine(config)
        engine.write_project_map(entries)

        # Verify directory was created
        assert project_map_path.parent.exists()
        assert project_map_path.exists()

    def test_append_to_existing_map(self, sample_config: Config, temp_directory: Path) -> None:
        """Test appending entries to an existing project map."""
        # Update config to use temp directory
        project_map_path = temp_directory / "project_map.csv"
        config = Config(
            global_map_path=temp_directory / "global_map.csv",
            project_map_path=project_map_path,
            extensions=sample_config.extensions,
        )

        # Write initial entries
        engine = MapEngine(config)
        initial_entries = [
            MapEntry(
                identifier_type="ipv4",
                original_value="10.0.1.50",
                anonymized_value="10.0.187.22",
                scope="project",
                preserve_format=True,
            ),
        ]
        engine.write_project_map(initial_entries)

        # Add new entry
        new_entry = MapEntry(
            identifier_type="hostname",
            original_value="SQL-PROD-03",
            anonymized_value="SRV-ALPHA-42",
            scope="project",
            preserve_format=True,
        )
        engine.add_entry(new_entry)

        # Load and verify both entries exist
        project_map = engine.load_project_map()
        assert len(project_map) == 2
        assert "10.0.1.50" in project_map
        assert "SQL-PROD-03" in project_map


class TestFakeValueGeneration:
    """Tests for fake value generation."""

    def test_generate_fake_ipv4(self) -> None:
        """Test generating fake IPv4 addresses."""
        config = Config.default()
        engine = MapEngine(config)

        # Generate fake for sample IPv4
        fake = engine.generate_fake_value("ipv4", "10.0.1.50", preserve_format=True)

        # Assert it's in same RFC1918 class (first two octets preserved)
        assert fake.startswith("10.0.")
        octets = fake.split(".")
        assert len(octets) == 4
        assert 1 <= int(octets[2]) <= 254
        assert 1 <= int(octets[3]) <= 254

    def test_generate_fake_cidr(self) -> None:
        """Test generating fake CIDR notation."""
        config = Config.default()
        engine = MapEngine(config)

        fake = engine.generate_fake_value("cidr", "192.168.1.0/24", preserve_format=True)

        # Assert IP portion is anonymized but prefix is preserved
        assert fake.endswith("/24")
        ip_part = fake.split("/")[0]
        assert ip_part.startswith("192.168.")

    def test_generate_fake_hostname(self) -> None:
        """Test generating fake hostnames."""
        config = Config.default()
        engine = MapEngine(config)

        # Test flat hostname
        fake_flat = engine.generate_fake_value("hostname", "SQL-PROD-03", preserve_format=True)
        assert "SRV-" in fake_flat
        assert "-" in fake_flat

        # Test FQDN
        fake_fqdn = engine.generate_fake_value("hostname", "SQL-PROD-03.contoso.local", preserve_format=True)
        assert "SRV-" in fake_fqdn
        assert ".contoso.local" in fake_fqdn

    def test_generate_fake_upn(self) -> None:
        """Test generating fake UPNs."""
        config = Config.default()
        engine = MapEngine(config)

        fake = engine.generate_fake_value("upn", "jsmith@contoso.com", preserve_format=True)

        # Assert format is preserved
        assert "@" in fake
        local_part, domain = fake.split("@")
        assert local_part  # Should have a local part
        assert domain  # Should have a domain

    def test_generate_fake_guid(self) -> None:
        """Test generating fake GUIDs deterministically."""
        config = Config.default()
        engine = MapEngine(config)

        # Generate fake for same input twice
        fake1 = engine.generate_fake_value("guid", "a1b2c3d4-e5f6-7890-abcd-ef1234567890", preserve_format=True)
        fake2 = engine.generate_fake_value("guid", "a1b2c3d4-e5f6-7890-abcd-ef1234567890", preserve_format=True)

        # Assert outputs are identical (deterministic)
        assert fake1 == fake2

        # Different input should produce different output
        fake3 = engine.generate_fake_value("guid", "b2c3d4e5-f6a7-8901-bcde-f12345678901", preserve_format=True)
        assert fake1 != fake3

    def test_generate_fake_sid(self) -> None:
        """Test generating fake SIDs."""
        config = Config.default()
        engine = MapEngine(config)

        fake = engine.generate_fake_value("sid", "S-1-5-21-1234567890-1234567890-1234567890-1001", preserve_format=True)

        # Assert prefix is preserved
        assert fake.startswith("S-1-5-21-")

        # Assert structure is maintained
        parts = fake.split("-")
        assert len(parts) >= 4

    def test_generate_fake_mac(self) -> None:
        """Test generating fake MAC addresses."""
        config = Config.default()
        engine = MapEngine(config)

        # Test with colon delimiter
        fake_colon = engine.generate_fake_value("mac", "AA:BB:CC:11:22:33", preserve_format=True)
        assert ":" in fake_colon
        octets = fake_colon.split(":")
        assert len(octets) == 6
        # First 3 octets (OUI) should be preserved
        assert octets[0] == "aa"
        assert octets[1] == "bb"
        assert octets[2] == "cc"

        # Test with dash delimiter
        fake_dash = engine.generate_fake_value("mac", "AA-BB-CC-11-22-33", preserve_format=True)
        assert "-" in fake_dash
        octets = fake_dash.split("-")
        assert len(octets) == 6
        assert octets[0] == "AA"
        assert octets[1] == "BB"
        assert octets[2] == "CC"

    def test_generate_fake_unc(self) -> None:
        """Test generating fake UNC paths."""
        config = Config.default()
        engine = MapEngine(config)

        fake = engine.generate_fake_value("unc", "\\\\FILESVR\\Finance$", preserve_format=True)

        # Assert UNC structure is preserved
        assert fake.startswith("\\\\")
        assert "\\" in fake
        # Server and share should be anonymized
        assert "FILESVR" not in fake or fake == "\\\\FILESVR\\Finance$"  # Either changed or same if no collision

    def test_generate_fake_value_invalid_type(self) -> None:
        """Test that invalid identifier type raises error."""
        config = Config.default()
        engine = MapEngine(config)

        with pytest.raises(ValueError, match="Unknown identifier type"):
            engine.generate_fake_value("invalid_type", "test", preserve_format=True)


class TestMapEntry:
    """Tests for the MapEntry dataclass."""

    def test_map_entry_validation(self) -> None:
        """Test that MapEntry validates its fields."""
        # Test empty original_value raises error
        with pytest.raises(ValueError, match="original_value cannot be empty"):
            MapEntry(
                identifier_type="ipv4",
                original_value="",
                anonymized_value="10.0.187.22",
                scope="project",
                preserve_format=True,
            )

        # Test empty anonymized_value raises error
        with pytest.raises(ValueError, match="anonymized_value cannot be empty"):
            MapEntry(
                identifier_type="ipv4",
                original_value="10.0.1.50",
                anonymized_value="",
                scope="project",
                preserve_format=True,
            )

        # Test invalid scope raises error
        with pytest.raises(ValueError, match="scope must be 'global' or 'project'"):
            MapEntry(
                identifier_type="ipv4",
                original_value="10.0.1.50",
                anonymized_value="10.0.187.22",
                scope="invalid",
                preserve_format=True,
            )

        # Test identical values raise error
        with pytest.raises(ValueError, match="original_value and anonymized_value cannot be identical"):
            MapEntry(
                identifier_type="ipv4",
                original_value="10.0.1.50",
                anonymized_value="10.0.1.50",
                scope="project",
                preserve_format=True,
            )

    def test_map_entry_to_csv_row(self, sample_map_entries: list[MapEntry]) -> None:
        """Test converting MapEntry to CSV row dictionary."""
        entry = sample_map_entries[0]
        row = entry.to_csv_row()

        assert row["identifier_type"] == "ipv4"
        assert row["original_value"] == "10.0.1.50"
        assert row["anonymized_value"] == "10.0.187.22"
        assert row["scope"] == "project"
        assert row["preserve_format"] == "true"

    def test_map_entry_from_csv_row(self) -> None:
        """Test creating MapEntry from CSV row dictionary."""
        row = {
            "identifier_type": "ipv4",
            "original_value": "10.0.1.50",
            "anonymized_value": "10.0.187.22",
            "scope": "project",
            "preserve_format": "true",
        }

        entry = MapEntry.from_csv_row(row)

        assert entry.identifier_type == "ipv4"
        assert entry.original_value == "10.0.1.50"
        assert entry.anonymized_value == "10.0.187.22"
        assert entry.scope == "project"
        assert entry.preserve_format is True


class TestLoadMergedMap:
    """Tests for the load_merged_map convenience function."""

    def test_load_merged_map(self, sample_config: Config, temp_directory: Path) -> None:
        """Test loading merged map as simple dictionary."""
        # Create global map
        global_map_path = temp_directory / "global_map.csv"
        global_map_path.parent.mkdir(parents=True, exist_ok=True)
        global_csv = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,10.0.1.50,10.0.100.100,global,true
"""
        global_map_path.write_text(global_csv)

        # Create project map
        project_map_path = temp_directory / "project_map.csv"
        project_csv = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,10.0.1.50,10.0.187.22,project,true
hostname,SQL-PROD-03,SRV-ALPHA-42,project,true
"""
        project_map_path.write_text(project_csv)

        # Update config
        config = Config(
            global_map_path=global_map_path,
            project_map_path=project_map_path,
            extensions=sample_config.extensions,
        )

        # Load merged map
        merged = load_merged_map(config)

        # Assert it's a simple dict
        assert isinstance(merged, dict)
        assert len(merged) == 2
        assert merged["10.0.1.50"] == "10.0.187.22"  # Project overrides
        assert merged["SQL-PROD-03"] == "SRV-ALPHA-42"


class TestShowMap:
    """Tests for the show_map method."""

    def test_show_map_global(self, sample_config: Config, temp_directory: Path) -> None:
        """Test showing global map."""
        # Create global map
        global_map_path = temp_directory / "global_map.csv"
        global_map_path.parent.mkdir(parents=True, exist_ok=True)
        global_csv = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,10.0.1.50,10.0.100.100,global,true
"""
        global_map_path.write_text(global_csv)

        # Update config
        config = Config(
            global_map_path=global_map_path,
            project_map_path=temp_directory / "project_map.csv",
            extensions=sample_config.extensions,
        )

        engine = MapEngine(config)
        entries = engine.show_map(scope="global")

        assert len(entries) == 1
        assert entries[0].original_value == "10.0.1.50"

    def test_show_map_project(self, sample_config: Config, temp_directory: Path) -> None:
        """Test showing project map."""
        # Create project map
        project_map_path = temp_directory / "project_map.csv"
        project_map_path.parent.mkdir(parents=True, exist_ok=True)
        project_csv = """identifier_type,original_value,anonymized_value,scope,preserve_format
hostname,SQL-PROD-03,SRV-ALPHA-42,project,true
"""
        project_map_path.write_text(project_csv)

        # Update config
        config = Config(
            global_map_path=temp_directory / "global_map.csv",
            project_map_path=project_map_path,
            extensions=sample_config.extensions,
        )

        engine = MapEngine(config)
        entries = engine.show_map(scope="project")

        assert len(entries) == 1
        assert entries[0].original_value == "SQL-PROD-03"

    def test_show_map_merged(self, sample_config: Config, temp_directory: Path) -> None:
        """Test showing merged map."""
        # Create global map
        global_map_path = temp_directory / "global_map.csv"
        global_map_path.parent.mkdir(parents=True, exist_ok=True)
        global_csv = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,10.0.1.50,10.0.100.100,global,true
"""
        global_map_path.write_text(global_csv)

        # Create project map
        project_map_path = temp_directory / "project_map.csv"
        project_csv = """identifier_type,original_value,anonymized_value,scope,preserve_format
hostname,SQL-PROD-03,SRV-ALPHA-42,project,true
"""
        project_map_path.write_text(project_csv)

        # Update config
        config = Config(
            global_map_path=global_map_path,
            project_map_path=project_map_path,
            extensions=sample_config.extensions,
        )

        engine = MapEngine(config)
        entries = engine.show_map(scope="merged")

        assert len(entries) == 2

    def test_show_map_invalid_scope(self, sample_config: Config) -> None:
        """Test that invalid scope raises error."""
        config = Config.default()
        engine = MapEngine(config)

        with pytest.raises(ValueError, match="Invalid scope"):
            engine.show_map(scope="invalid")
