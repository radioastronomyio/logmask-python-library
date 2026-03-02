"""
Unit tests for the replacer module.

This module tests the Aho-Corasick automaton and single-pass replacement,
including substring collision prevention.
"""

import pytest
from pathlib import Path

from logmask.models import Config, MapEntry
from logmask.replacer import Replacer, anonymize_text, reveal_text


class TestAutomatonBuilding:
    """Tests for building the Aho-Corasick automaton."""

    def test_build_automaton_from_mapping(self, sample_config: Config) -> None:
        """Test building an automaton from a translation map."""
        # Create a sample mapping dictionary
        mapping = {
            "10.0.1.50": "10.0.187.22",
            "SQL-PROD-03": "SRV-ALPHA-42",
            "jsmith@contoso.com": "user047@fabrikam.com",
        }

        # Build automaton using Replacer
        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)

        # Assert automaton is built successfully
        assert replacer._automaton is not None

    def test_build_automaton_empty_mapping(self, sample_config: Config) -> None:
        """Test building an automaton with an empty mapping."""
        replacer = Replacer(sample_config)
        replacer.build_automaton({})

        # Assert automaton is built even with empty mapping
        assert replacer._automaton is not None


class TestTextReplacement:
    """Tests for single-pass text replacement."""

    def test_replace_single_identifier(self, sample_config: Config) -> None:
        """Test replacing a single identifier in text."""
        # Create mapping with single entry
        mapping = {
            "10.0.1.50": "10.0.187.22",
        }

        # Build automaton
        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)

        # Replace text
        text = "Connection from 10.0.1.50 established"
        result = replacer.replace_text(text)

        # Assert replacement occurred correctly
        assert "10.0.187.22" in result
        assert "10.0.1.50" not in result
        assert result == "Connection from 10.0.187.22 established"

    def test_replace_multiple_identifiers(self, sample_config: Config) -> None:
        """Test replacing multiple identifiers in text."""
        mapping = {
            "10.0.1.50": "10.0.187.22",
            "SQL-PROD-03": "SRV-ALPHA-42",
            "jsmith@contoso.com": "user047@fabrikam.com",
        }

        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)

        text = "User jsmith@contoso.com connected to SQL-PROD-03 from 10.0.1.50"
        result = replacer.replace_text(text)

        assert "user047@fabrikam.com" in result
        assert "SRV-ALPHA-42" in result
        assert "10.0.187.22" in result
        assert "jsmith@contoso.com" not in result
        assert "SQL-PROD-03" not in result
        assert "10.0.1.50" not in result

    def test_replace_no_matches(self, sample_config: Config) -> None:
        """Test replacing text with no matching identifiers."""
        mapping = {
            "10.0.1.50": "10.0.187.22",
        }

        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)

        text = "No identifiers in this text"
        result = replacer.replace_text(text)

        # Assert text is unchanged
        assert result == text

    def test_replace_preserves_encoding(self, sample_config: Config) -> None:
        """Test that replacement preserves original text encoding."""
        mapping = {
            "10.0.1.50": "10.0.187.22",
        }

        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)

        # Text with UTF-8 characters
        text = "Connection from 10.0.1.50 with café and résumé"
        result = replacer.replace_text(text)

        assert "10.0.187.22" in result
        assert "café" in result
        assert "résumé" in result


class TestSubstringCollisionPrevention:
    """Tests for longest-match substring collision prevention."""

    def test_longest_match_wins(self, sample_config: Config) -> None:
        """Test that longer matches take precedence over shorter ones."""
        # Critical test: 10.0.0.100 should match before 10.0.0.1
        # at the same position
        mapping = {
            "10.0.0.1": "192.168.1.1",
            "10.0.0.100": "192.168.1.100",
        }

        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)

        # Text contains 10.0.0.100, which contains 10.0.0.1 as prefix
        text = "Server at 10.0.0.100 is responding"
        result = replacer.replace_text(text)

        # Assert longest match (10.0.0.100) was used
        assert "192.168.1.100" in result
        assert "10.0.0.1" not in result  # Original shorter value should not appear
        assert result == "Server at 192.168.1.100 is responding"

    def test_overlapping_patterns(self, sample_config: Config) -> None:
        """Test handling of overlapping patterns."""
        mapping = {
            "abc": "XYZ",
            "bcd": "123",
        }

        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)

        # Text "abcd" contains both "abc" and "bcd" overlapping
        text = "test abcd test"
        result = replacer.replace_text(text)

        # TODO: Weak assertion — `or` means this passes even if only one pattern
        # matched. The expected behavior for overlapping "abc"/"bcd" in "abcd" is
        # that "abc" wins (first match), producing "XYZd". Assert the exact output.
        assert "XYZ" in result or "123" in result

    def test_duplicate_prevention(self, sample_config: Config) -> None:
        """Test that the same position is not matched multiple times."""
        mapping = {
            "10.0.0.100": "192.168.1.100",
        }

        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)

        text = "Server at 10.0.0.100 is at 10.0.0.100"
        result = replacer.replace_text(text)

        # Both occurrences should be replaced
        assert result.count("192.168.1.100") == 2
        assert "10.0.0.100" not in result


class TestFileReplacement:
    """Tests for file-level replacement operations."""

    def test_replace_file(self, sample_config: Config, temp_directory: Path) -> None:
        """Test replacing identifiers in a single file."""
        # Create input file with identifiers
        input_file = temp_directory / "input.log"
        input_file.write_text("Connection from 10.0.1.50 to SQL-PROD-03")

        # Create mapping
        mapping = {
            "10.0.1.50": "10.0.187.22",
            "SQL-PROD-03": "SRV-ALPHA-42",
        }

        # Replace file
        output_file = temp_directory / "output.log"
        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)
        replacer.replace_file(input_file, output_file)

        # Read output file
        output_content = output_file.read_text()

        # Assert replacements occurred
        assert "10.0.187.22" in output_content
        assert "SRV-ALPHA-42" in output_content
        assert "10.0.1.50" not in output_content
        assert "SQL-PROD-03" not in output_content

    def test_replace_directory(self, sample_config: Config, temp_directory: Path) -> None:
        """Test replacing identifiers in all files in a directory."""
        # Create input directory with files
        input_dir = temp_directory / "input"
        input_dir.mkdir()

        (input_dir / "file1.log").write_text("Connection from 10.0.1.50")
        (input_dir / "file2.txt").write_text("Server SQL-PROD-03")
        (input_dir / "file3.md").write_text("User jsmith@contoso.com")

        # Create mapping
        mapping = {
            "10.0.1.50": "10.0.187.22",
            "SQL-PROD-03": "SRV-ALPHA-42",
            "jsmith@contoso.com": "user047@fabrikam.com",
        }

        # Replace directory
        output_dir = temp_directory / "output"
        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)
        results = replacer.replace_directory(input_dir, output_dir)

        # Assert all files were processed
        assert len(results) == 3
        assert all(results.values())

        # Verify output files
        assert (output_dir / "file1.log").exists()
        assert (output_dir / "file2.txt").exists()
        assert (output_dir / "file3.md").exists()

        output1 = (output_dir / "file1.log").read_text()
        assert "10.0.187.22" in output1

        output2 = (output_dir / "file2.txt").read_text()
        assert "SRV-ALPHA-42" in output2

        output3 = (output_dir / "file3.md").read_text()
        assert "user047@fabrikam.com" in output3

    def test_replace_creates_output_directory(self, sample_config: Config, temp_directory: Path) -> None:
        """Test that replacement creates output directory if needed."""
        # Create input file
        input_file = temp_directory / "input.log"
        input_file.write_text("Connection from 10.0.1.50")

        # Use nested output path that doesn't exist
        output_file = temp_directory / "nested" / "path" / "output.log"

        mapping = {"10.0.1.50": "10.0.187.22"}

        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)
        replacer.replace_file(input_file, output_file)

        # Assert directory was created and file exists
        assert output_file.parent.exists()
        assert output_file.exists()

    def test_replace_respects_extensions(self, sample_config: Config, temp_directory: Path) -> None:
        """Test that replacement only processes configured extensions."""
        # Create input directory with different file types
        input_dir = temp_directory / "input"
        input_dir.mkdir()

        (input_dir / "file1.log").write_text("Connection from 10.0.1.50")
        (input_dir / "file2.txt").write_text("Server SQL-PROD-03")
        (input_dir / "file3.py").write_text("print('10.0.1.50')")  # Not in extensions
        (input_dir / "file4.md").write_text("User jsmith@contoso.com")

        # Create mapping
        mapping = {
            "10.0.1.50": "10.0.187.22",
            "SQL-PROD-03": "SRV-ALPHA-42",
            "jsmith@contoso.com": "user047@fabrikam.com",
        }

        # Replace directory
        output_dir = temp_directory / "output"
        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)
        results = replacer.replace_directory(input_dir, output_dir)

        # Assert only configured extensions were processed
        assert len(results) == 3  # log, txt, md (not py)
        assert (output_dir / "file1.log").exists()
        assert (output_dir / "file2.txt").exists()
        assert (output_dir / "file4.md").exists()
        assert not (output_dir / "file3.py").exists()


class TestRevealMode:
    """Tests for reverse replacement (reveal mode)."""

    def test_reveal_text(self, sample_config: Config) -> None:
        """Test revealing original values from anonymized text."""
        # Create mapping
        mapping = {
            "10.0.1.50": "10.0.187.22",
            "SQL-PROD-03": "SRV-ALPHA-42",
        }

        # Create project map for reveal
        project_map_path = sample_config.project_map_path
        project_map_path.parent.mkdir(parents=True, exist_ok=True)

        csv_content = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,10.0.1.50,10.0.187.22,project,true
hostname,SQL-PROD-03,SRV-ALPHA-42,project,true
"""
        project_map_path.write_text(csv_content)

        replacer = Replacer(sample_config)

        # Anonymize text
        text = "Connection from 10.0.1.50 to SQL-PROD-03"
        anonymized = anonymize_text(text, mapping)

        # Reveal text
        revealed = replacer.reveal_text(anonymized)

        # Assert original values are restored
        assert "10.0.1.50" in revealed
        assert "SQL-PROD-03" in revealed
        assert "10.0.187.22" not in revealed
        assert "SRV-ALPHA-42" not in revealed

    def test_reveal_file(self, sample_config: Config, temp_directory: Path) -> None:
        """Test revealing original values in a file."""
        # Create project map
        project_map_path = temp_directory / "project_map.csv"
        project_map_path.parent.mkdir(parents=True, exist_ok=True)

        csv_content = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,10.0.1.50,10.0.187.22,project,true
"""
        project_map_path.write_text(csv_content)

        # Create anonymized input file
        input_file = temp_directory / "anonymized.log"
        input_file.write_text("Connection from 10.0.187.22")

        # Update config
        config = Config(
            global_map_path=temp_directory / "global_map.csv",
            project_map_path=project_map_path,
            extensions=sample_config.extensions,
        )

        # Reveal file
        output_file = temp_directory / "revealed.log"
        replacer = Replacer(config)
        replacer.reveal_file(input_file, output_file)

        # Read output file
        output_content = output_file.read_text()

        # Assert original values are restored
        assert "10.0.1.50" in output_content
        assert "10.0.187.22" not in output_content

    def test_reveal_directory(self, sample_config: Config, temp_directory: Path) -> None:
        """Test revealing original values in a directory."""
        # Create project map
        project_map_path = temp_directory / "project_map.csv"
        project_map_path.parent.mkdir(parents=True, exist_ok=True)

        csv_content = """identifier_type,original_value,anonymized_value,scope,preserve_format
ipv4,10.0.1.50,10.0.187.22,project,true
hostname,SQL-PROD-03,SRV-ALPHA-42,project,true
"""
        project_map_path.write_text(csv_content)

        # Create anonymized input directory
        input_dir = temp_directory / "anonymized"
        input_dir.mkdir()

        (input_dir / "file1.log").write_text("Connection from 10.0.187.22")
        (input_dir / "file2.txt").write_text("Server SRV-ALPHA-42")

        # Update config
        config = Config(
            global_map_path=temp_directory / "global_map.csv",
            project_map_path=project_map_path,
            extensions=sample_config.extensions,
        )

        # Reveal directory
        output_dir = temp_directory / "revealed"
        replacer = Replacer(config)
        results = replacer.reveal_directory(input_dir, output_dir)

        # Assert all files were processed
        assert len(results) == 2
        assert all(results.values())

        # Verify output files
        output1 = (output_dir / "file1.log").read_text()
        assert "10.0.1.50" in output1

        output2 = (output_dir / "file2.txt").read_text()
        assert "SQL-PROD-03" in output2


class TestDeterministicReplacement:
    """Tests for deterministic replacement behavior."""

    def test_same_input_same_output(self, sample_config: Config) -> None:
        """Test that same input with same map produces identical output."""
        # Critical requirement for MSP operational security
        mapping = {
            "10.0.1.50": "10.0.187.22",
            "SQL-PROD-03": "SRV-ALPHA-42",
            "jsmith@contoso.com": "user047@fabrikam.com",
        }

        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)

        text = "User jsmith@contoso.com connected to SQL-PROD-03 from 10.0.1.50"

        # Replace twice
        result1 = replacer.replace_text(text)
        result2 = replacer.replace_text(text)

        # Assert outputs are identical
        assert result1 == result2

    def test_byte_identical_output(self, sample_config: Config) -> None:
        """Test that output is byte-identical across multiple runs."""
        mapping = {
            "10.0.1.50": "10.0.187.22",
        }

        replacer = Replacer(sample_config)
        replacer.build_automaton(mapping)

        text = "Connection from 10.0.1.50"

        # Replace multiple times
        results = [replacer.replace_text(text) for _ in range(5)]

        # Assert all results are identical
        assert all(r == results[0] for r in results)


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_anonymize_text(self) -> None:
        """Test the anonymize_text convenience function."""
        mapping = {
            "10.0.1.50": "10.0.187.22",
            "SQL-PROD-03": "SRV-ALPHA-42",
        }

        text = "Connection from 10.0.1.50 to SQL-PROD-03"
        result = anonymize_text(text, mapping)

        assert "10.0.187.22" in result
        assert "SRV-ALPHA-42" in result
        assert "10.0.1.50" not in result
        assert "SQL-PROD-03" not in result

    def test_reveal_text_function(self) -> None:
        """Test the reveal_text convenience function."""
        mapping = {
            "10.0.1.50": "10.0.187.22",
            "SQL-PROD-03": "SRV-ALPHA-42",
        }

        text = "Connection from 10.0.1.50 to SQL-PROD-03"
        anonymized = anonymize_text(text, mapping)
        revealed = reveal_text(anonymized, mapping)

        # Assert original text is restored
        assert revealed == text
