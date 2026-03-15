"""
Unit tests for the scanner module.

Covers Scanner class, _filter_contained_hostnames(), scan_files(),
deduplication, extension filtering, and error handling.
"""

import pytest
from pathlib import Path

from logmask.models import Config, DetectedIdentifier
from logmask.scanner import Scanner, _filter_contained_hostnames, scan_files


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_config(tmp_path: Path, extensions: list[str] | None = None) -> Config:
    """Return a Config that points entirely into tmp_path."""
    return Config(
        global_map_path=tmp_path / "global_map.csv",
        project_map_path=tmp_path / ".logmask" / "project_map.csv",
        extensions=extensions or [".log", ".txt", ".md", ".ps1"],
    )


def make_ident(
    value: str,
    identifier_type: str,
    start_pos: int,
    confidence: float = 1.0,
) -> DetectedIdentifier:
    """Convenience constructor for DetectedIdentifier."""
    return DetectedIdentifier(
        value=value,
        identifier_type=identifier_type,  # type: ignore[arg-type]
        start_pos=start_pos,
        end_pos=start_pos + len(value),
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# TestFilterContainedHostnames
# ---------------------------------------------------------------------------


class TestFilterContainedHostnames:
    """Tests for _filter_contained_hostnames()."""

    def test_empty_list_returns_empty(self) -> None:
        assert _filter_contained_hostnames([]) == []

    def test_no_upns_returns_unchanged(self) -> None:
        """When no UPNs exist the function is a no-op."""
        idents = [
            make_ident("10.0.1.50", "ipv4", 0),
            make_ident("SQL-PROD-03", "hostname", 20),
        ]
        result = _filter_contained_hostnames(idents)
        assert result == idents

    def test_hostname_inside_upn_is_removed(self) -> None:
        """A hostname whose character range falls entirely within a UPN is filtered out."""
        # UPN: "jsmith@contoso.com" at positions 0-18
        upn = make_ident("jsmith@contoso.com", "upn", 0)
        # "contoso.com" is a substring of the UPN, positions 7-18
        hostname_inside = make_ident("contoso.com", "hostname", 7)
        result = _filter_contained_hostnames([upn, hostname_inside])
        assert upn in result
        assert hostname_inside not in result

    def test_hostname_outside_upn_is_preserved(self) -> None:
        """A hostname that does not overlap any UPN is kept."""
        upn = make_ident("jsmith@contoso.com", "upn", 0)
        hostname_outside = make_ident("SQL-PROD-03", "hostname", 50)
        result = _filter_contained_hostnames([upn, hostname_outside])
        assert upn in result
        assert hostname_outside in result

    def test_partially_overlapping_hostname_preserved(self) -> None:
        """A hostname that partially overlaps a UPN (but is not fully contained) is kept."""
        # UPN at 5-23 (18 chars), hostname starts at 4 — not fully inside
        upn = make_ident("jsmith@contoso.com", "upn", 5)
        # hostname starts before the UPN → start_pos 4 < upn start_pos 5
        hostname = make_ident("xcontoso.co", "hostname", 4)
        result = _filter_contained_hostnames([upn, hostname])
        assert hostname in result

    def test_multiple_upns_multiple_hostnames(self) -> None:
        """Correct filtering when multiple UPNs and multiple hostnames are present."""
        upn1 = make_ident("jsmith@contoso.com", "upn", 0)    # 0-18
        upn2 = make_ident("admin@fabrikam.local", "upn", 50)  # 50-70
        hostname_in_upn1 = make_ident("contoso.com", "hostname", 7)    # 7-18 inside upn1
        hostname_in_upn2 = make_ident("fabrikam.local", "hostname", 56) # 56-70 inside upn2
        hostname_free = make_ident("SQL-PROD-03", "hostname", 100)       # 100-111 free

        result = _filter_contained_hostnames(
            [upn1, upn2, hostname_in_upn1, hostname_in_upn2, hostname_free]
        )
        assert upn1 in result
        assert upn2 in result
        assert hostname_in_upn1 not in result
        assert hostname_in_upn2 not in result
        assert hostname_free in result

    def test_non_hostname_types_are_never_filtered(self) -> None:
        """Only hostname-type identifiers are subject to filtering; others pass through."""
        upn = make_ident("jsmith@contoso.com", "upn", 0)
        ip_inside = make_ident("10.0.1.100", "ipv4", 2)  # ipv4 inside UPN range — kept
        result = _filter_contained_hostnames([upn, ip_inside])
        assert ip_inside in result

    def test_hostname_exactly_at_upn_boundaries_filtered(self) -> None:
        """A hostname whose range is exactly equal to the UPN range is filtered."""
        upn = make_ident("jsmith@contoso.com", "upn", 0)   # 0-18
        hostname = make_ident("jsmith@contoso.com", "hostname", 0)  # same span
        result = _filter_contained_hostnames([upn, hostname])
        assert hostname not in result


# ---------------------------------------------------------------------------
# TestScannerInit
# ---------------------------------------------------------------------------


class TestScannerInit:
    """Tests for Scanner initialisation."""

    def test_get_parser_names(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        scanner = Scanner(config)
        names = scanner.get_parser_names()
        assert isinstance(names, list)
        assert len(names) > 0
        assert "ipv4" in names
        assert "hostname" in names

    def test_parsers_are_independent_copy(self, tmp_path: Path) -> None:
        """Each Scanner instance gets its own copy of the registry."""
        config = make_config(tmp_path)
        s1 = Scanner(config)
        s2 = Scanner(config)
        s1._parsers["_test_key"] = lambda t, c: []  # type: ignore[assignment]
        assert "_test_key" not in s2._parsers


# ---------------------------------------------------------------------------
# TestScanFile
# ---------------------------------------------------------------------------


class TestScanFile:
    """Tests for Scanner.scan_file()."""

    def test_scan_file_detects_ipv4(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        log_file = tmp_path / "sample.log"
        log_file.write_text("Connection from 10.0.1.50 to 192.168.100.10\n")
        scanner = Scanner(config)
        identifiers = scanner.scan_file(log_file)
        values = [i.value for i in identifiers]
        assert "10.0.1.50" in values
        assert "192.168.100.10" in values

    def test_scan_file_detects_hostname(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        log_file = tmp_path / "sample.log"
        log_file.write_text("Server SQL-PROD-03 started\n")
        scanner = Scanner(config)
        identifiers = scanner.scan_file(log_file)
        values = [i.value for i in identifiers]
        assert "SQL-PROD-03" in values

    def test_scan_file_detects_upn(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        log_file = tmp_path / "sample.log"
        log_file.write_text("User: jsmith@contoso.com logged in\n")
        scanner = Scanner(config)
        identifiers = scanner.scan_file(log_file)
        values = [i.value for i in identifiers]
        assert "jsmith@contoso.com" in values

    def test_scan_file_deduplicates(self, tmp_path: Path) -> None:
        """The same identifier appearing multiple times should only appear once."""
        config = make_config(tmp_path)
        log_file = tmp_path / "sample.log"
        log_file.write_text(
            "10.0.1.50 connected. Retry from 10.0.1.50. Final: 10.0.1.50\n"
        )
        scanner = Scanner(config)
        identifiers = scanner.scan_file(log_file)
        ip_hits = [i for i in identifiers if i.value == "10.0.1.50"]
        assert len(ip_hits) == 1

    def test_scan_file_upn_domain_hostname_filtered(self, tmp_path: Path) -> None:
        """The domain portion of a UPN must not appear as a separate hostname entry."""
        config = make_config(tmp_path)
        log_file = tmp_path / "sample.log"
        log_file.write_text("User: jsmith@contoso.com\n")
        scanner = Scanner(config)
        identifiers = scanner.scan_file(log_file)
        hostname_values = [i.value for i in identifiers if i.identifier_type == "hostname"]
        # contoso.com (or contoso) should not appear as a separate hostname
        assert "contoso.com" not in hostname_values

    def test_scan_file_unreadable_returns_empty(self, tmp_path: Path) -> None:
        """An unreadable file should return an empty list, not raise."""
        config = make_config(tmp_path)
        nonexistent = tmp_path / "does_not_exist.log"
        scanner = Scanner(config)
        result = scanner.scan_file(nonexistent)
        assert result == []

    def test_scan_file_empty_file(self, tmp_path: Path) -> None:
        """An empty file returns an empty list without error."""
        config = make_config(tmp_path)
        empty_file = tmp_path / "empty.log"
        empty_file.write_text("")
        scanner = Scanner(config)
        result = scanner.scan_file(empty_file)
        assert result == []

    def test_scan_file_no_identifiers(self, tmp_path: Path) -> None:
        """Text with no recognised identifiers returns an empty list."""
        config = make_config(tmp_path)
        clean_file = tmp_path / "clean.txt"
        clean_file.write_text("Hello world. Nothing to see here.\n")
        scanner = Scanner(config)
        result = scanner.scan_file(clean_file)
        assert result == []

    def test_scan_file_mixed_identifiers(self, tmp_path: Path) -> None:
        """A file with multiple identifier types produces results for each type."""
        config = make_config(tmp_path)
        log_file = tmp_path / "mixed.log"
        log_file.write_text(
            "IP: 10.0.1.50\n"
            "Host: SQL-PROD-03\n"
            "User: jsmith@contoso.com\n"
        )
        scanner = Scanner(config)
        identifiers = scanner.scan_file(log_file)
        types_found = {i.identifier_type for i in identifiers}
        assert "ipv4" in types_found
        assert "hostname" in types_found
        assert "upn" in types_found

    def test_scan_file_returns_detected_identifier_objects(self, tmp_path: Path) -> None:
        """All returned items are DetectedIdentifier instances."""
        config = make_config(tmp_path)
        log_file = tmp_path / "sample.log"
        log_file.write_text("10.0.1.50\n")
        scanner = Scanner(config)
        identifiers = scanner.scan_file(log_file)
        for ident in identifiers:
            assert isinstance(ident, DetectedIdentifier)


# ---------------------------------------------------------------------------
# TestScanDirectory
# ---------------------------------------------------------------------------


class TestScanDirectory:
    """Tests for Scanner.scan_directory()."""

    def test_scan_directory_nonexistent_raises(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        scanner = Scanner(config)
        with pytest.raises(FileNotFoundError):
            scanner.scan_directory(tmp_path / "no_such_dir")

    def test_scan_directory_file_path_raises(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        a_file = tmp_path / "file.txt"
        a_file.write_text("data")
        scanner = Scanner(config)
        with pytest.raises(NotADirectoryError):
            scanner.scan_directory(a_file)

    def test_scan_directory_extension_filtering(self, tmp_path: Path) -> None:
        """Only files matching configured extensions are scanned."""
        config = make_config(tmp_path, extensions=[".log"])
        (tmp_path / "log_file.log").write_text("10.0.1.50\n")
        (tmp_path / "python_file.py").write_text("10.0.2.50\n")  # should be skipped
        scanner = Scanner(config)
        results = scanner.scan_directory(tmp_path)
        # .py file should not appear in results
        result_paths = [p.name for p in results.keys()]
        assert "log_file.log" in result_paths
        assert "python_file.py" not in result_paths

    def test_scan_directory_returns_only_files_with_identifiers(self, tmp_path: Path) -> None:
        """Files with no identifiers are omitted from the result dict."""
        config = make_config(tmp_path, extensions=[".txt"])
        (tmp_path / "clean.txt").write_text("No identifiers here.\n")
        (tmp_path / "dirty.txt").write_text("IP: 10.0.1.50\n")
        scanner = Scanner(config)
        results = scanner.scan_directory(tmp_path)
        result_names = [p.name for p in results.keys()]
        assert "dirty.txt" in result_names
        assert "clean.txt" not in result_names

    def test_scan_directory_empty_dir(self, tmp_path: Path) -> None:
        """An empty directory returns an empty dict."""
        config = make_config(tmp_path)
        empty_dir = tmp_path / "empty_subdir"
        empty_dir.mkdir()
        scanner = Scanner(config)
        results = scanner.scan_directory(empty_dir)
        assert results == {}

    def test_scan_directory_recurses_into_subdirs(self, tmp_path: Path) -> None:
        """scan_directory finds files in nested subdirectories."""
        config = make_config(tmp_path, extensions=[".txt"])
        sub = tmp_path / "sub" / "sub2"
        sub.mkdir(parents=True)
        (sub / "deep.txt").write_text("10.0.1.50\n")
        scanner = Scanner(config)
        results = scanner.scan_directory(tmp_path)
        result_names = [p.name for p in results.keys()]
        assert "deep.txt" in result_names

    def test_scan_directory_multiple_files(self, tmp_path: Path) -> None:
        """Multiple files with identifiers all appear in results."""
        config = make_config(tmp_path, extensions=[".txt"])
        (tmp_path / "a.txt").write_text("10.0.1.50\n")
        (tmp_path / "b.txt").write_text("192.168.100.10\n")
        scanner = Scanner(config)
        results = scanner.scan_directory(tmp_path)
        assert len(results) == 2

    def test_scan_directory_values_are_lists_of_detected_identifiers(self, tmp_path: Path) -> None:
        """Result dict values are lists of DetectedIdentifier."""
        config = make_config(tmp_path, extensions=[".txt"])
        (tmp_path / "sample.txt").write_text("10.0.1.50\n")
        scanner = Scanner(config)
        results = scanner.scan_directory(tmp_path)
        for path, idents in results.items():
            assert isinstance(idents, list)
            for ident in idents:
                assert isinstance(ident, DetectedIdentifier)


# ---------------------------------------------------------------------------
# TestScanFiles (convenience function)
# ---------------------------------------------------------------------------


class TestScanFiles:
    """Tests for the scan_files() module-level convenience function."""

    def test_scan_files_returns_dict(self, tmp_path: Path) -> None:
        config = make_config(tmp_path, extensions=[".txt"])
        (tmp_path / "sample.txt").write_text("10.0.1.50\n")
        results = scan_files(tmp_path, config)
        assert isinstance(results, dict)

    def test_scan_files_delegates_to_scanner(self, tmp_path: Path) -> None:
        """scan_files() should produce the same results as Scanner.scan_directory()."""
        config = make_config(tmp_path, extensions=[".txt"])
        (tmp_path / "sample.txt").write_text("10.0.1.50\n")
        direct = Scanner(config).scan_directory(tmp_path)
        via_convenience = scan_files(tmp_path, config)
        # Same keys (file paths) and same identifier values
        assert set(direct.keys()) == set(via_convenience.keys())
        for path in direct:
            direct_values = {i.value for i in direct[path]}
            conv_values = {i.value for i in via_convenience[path]}
            assert direct_values == conv_values
