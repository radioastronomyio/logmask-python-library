"""
Unit tests for the cli module.

Covers create_parser(), handle_init(), handle_scan(), handle_anonymize(),
handle_reveal(), handle_map_show(), handle_map_add(), and main().

Strategy:
- All file-system operations use pytest's tmp_path fixture so nothing touches
  the real user profile or working directory.
- Rich console output is captured via capsys / monkeypatch of sys.stdout.
- handle_scan()'s interactive input() is patched with monkeypatch.
"""

import argparse
import sys
from pathlib import Path

import pytest

from logmask.cli import (
    create_parser,
    handle_anonymize,
    handle_init,
    handle_map_add,
    handle_map_show,
    handle_reveal,
    handle_scan,
    main,
)
from logmask.models import Config, MapEntry
from logmask.map_engine import MapEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def isolated_config(tmp_path: Path) -> Config:
    """Return a Config whose paths are all inside tmp_path."""
    return Config(
        global_map_path=tmp_path / "global_map.csv",
        project_map_path=tmp_path / ".logmask" / "project_map.csv",
        extensions=[".log", ".txt", ".md", ".ps1"],
    )


def write_project_map(config: Config, entries: list[MapEntry]) -> None:
    engine = MapEngine(config)
    engine.write_project_map(entries)


def _make_args(**kwargs) -> argparse.Namespace:
    """Build an argparse.Namespace with arbitrary attributes."""
    return argparse.Namespace(**kwargs)


# ---------------------------------------------------------------------------
# TestCreateParser
# ---------------------------------------------------------------------------


class TestCreateParser:
    """Tests for create_parser()."""

    def test_returns_argument_parser(self) -> None:
        parser = create_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_prog_is_logmask(self) -> None:
        parser = create_parser()
        assert parser.prog == "logmask"

    def test_init_subcommand_registered(self) -> None:
        parser = create_parser()
        args = parser.parse_args(["init"])
        assert args.command == "init"

    def test_init_client_option(self) -> None:
        parser = create_parser()
        args = parser.parse_args(["init", "--client", "Acme"])
        assert args.client == "Acme"

    def test_scan_subcommand_registered(self) -> None:
        parser = create_parser()
        args = parser.parse_args(["scan", "/tmp"])
        assert args.command == "scan"
        assert args.target_dir == Path("/tmp")

    def test_scan_ext_default(self) -> None:
        parser = create_parser()
        args = parser.parse_args(["scan", "/tmp"])
        assert ".log" in args.ext

    def test_scan_ext_override(self) -> None:
        parser = create_parser()
        args = parser.parse_args(["scan", "/tmp", "--ext", ".csv", ".json"])
        assert args.ext == [".csv", ".json"]

    def test_anonymize_subcommand_registered(self) -> None:
        parser = create_parser()
        args = parser.parse_args(["anonymize", "/tmp", "--out", "/out"])
        assert args.command == "anonymize"
        assert args.out == Path("/out")

    def test_reveal_subcommand_registered(self) -> None:
        parser = create_parser()
        args = parser.parse_args(["reveal", "/tmp", "--out", "/out"])
        assert args.command == "reveal"

    def test_map_show_subcommand_registered(self) -> None:
        parser = create_parser()
        args = parser.parse_args(["map", "show"])
        assert args.command == "map"
        assert args.map_command == "show"
        assert args.scope == "merged"  # default

    def test_map_show_scope_option(self) -> None:
        parser = create_parser()
        args = parser.parse_args(["map", "show", "--scope", "global"])
        assert args.scope == "global"

    def test_map_add_subcommand_registered(self) -> None:
        parser = create_parser()
        args = parser.parse_args(["map", "add", "ipv4", "10.0.1.50", "10.0.99.1"])
        assert args.command == "map"
        assert args.map_command == "add"
        assert args.type == "ipv4"
        assert args.original == "10.0.1.50"
        assert args.anonymized == "10.0.99.1"


# ---------------------------------------------------------------------------
# TestHandleInit
# ---------------------------------------------------------------------------


class TestHandleInit:
    """Tests for handle_init()."""

    def test_creates_logmask_directory(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        args = _make_args(client=None)
        result = handle_init(args)
        assert result == 0
        assert config.project_map_path.parent.exists()

    def test_creates_empty_project_map_csv(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        args = _make_args(client=None)
        handle_init(args)
        assert config.project_map_path.exists()
        content = config.project_map_path.read_text()
        assert "identifier_type" in content

    def test_does_not_overwrite_existing_map(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        # Pre-create map with custom content
        config.project_map_path.parent.mkdir(parents=True, exist_ok=True)
        config.project_map_path.write_text("custom content sentinel\n")
        args = _make_args(client=None)
        handle_init(args)
        assert "custom content sentinel" in config.project_map_path.read_text()

    def test_with_client_name_returns_zero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        args = _make_args(client="Acme Corp")
        result = handle_init(args)
        assert result == 0

    def test_prints_client_name(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        args = _make_args(client="Acme Corp")
        handle_init(args)
        captured = capsys.readouterr()
        assert "Acme Corp" in captured.out


# ---------------------------------------------------------------------------
# TestHandleScan
# ---------------------------------------------------------------------------


class TestHandleScan:
    """Tests for handle_scan()."""

    def test_nonexistent_dir_returns_one(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        args = _make_args(target_dir=tmp_path / "no_such_dir", ext=[".txt"])
        result = handle_scan(args)
        assert result == 1

    def test_no_identifiers_found_returns_zero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        scan_dir = tmp_path / "logs"
        scan_dir.mkdir()
        (scan_dir / "clean.txt").write_text("Nothing suspicious here.\n")
        args = _make_args(target_dir=scan_dir, ext=[".txt"])
        result = handle_scan(args)
        assert result == 0

    def test_eof_on_prompt_returns_zero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """EOFError during the per-type approval prompt exits gracefully."""
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        scan_dir = tmp_path / "logs"
        scan_dir.mkdir()
        (scan_dir / "sample.txt").write_text("Connection from 10.0.1.50\n")
        # Simulate EOF when input() is called
        monkeypatch.setattr("builtins.input", lambda: (_ for _ in ()).throw(EOFError()))
        args = _make_args(target_dir=scan_dir, ext=[".txt"])
        result = handle_scan(args)
        assert result == 0

    def test_user_declines_all_returns_zero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        scan_dir = tmp_path / "logs"
        scan_dir.mkdir()
        (scan_dir / "sample.txt").write_text("Connection from 10.0.1.50\n")
        monkeypatch.setattr("builtins.input", lambda: "n")
        args = _make_args(target_dir=scan_dir, ext=[".txt"])
        result = handle_scan(args)
        assert result == 0

    def test_user_approves_writes_to_map(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        scan_dir = tmp_path / "logs"
        scan_dir.mkdir()
        (scan_dir / "sample.txt").write_text("Connection from 10.0.1.50\n")
        monkeypatch.setattr("builtins.input", lambda: "y")
        args = _make_args(target_dir=scan_dir, ext=[".txt"])
        result = handle_scan(args)
        assert result == 0
        # The project map should now contain the discovered IP
        assert config.project_map_path.exists()
        content = config.project_map_path.read_text()
        assert "10.0.1.50" in content


# ---------------------------------------------------------------------------
# TestHandleAnonymize
# ---------------------------------------------------------------------------


class TestHandleAnonymize:
    """Tests for handle_anonymize()."""

    def test_nonexistent_dir_returns_one(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        args = _make_args(target_dir=tmp_path / "no_such_dir", out=tmp_path / "out")
        result = handle_anonymize(args)
        assert result == 1

    def test_output_inside_target_returns_one(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        target = tmp_path / "target"
        target.mkdir()
        out = target / "subdir"  # inside target
        args = _make_args(target_dir=target, out=out)
        result = handle_anonymize(args)
        assert result == 1

    def test_anonymize_with_empty_map_returns_zero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With no map entries, files are copied unchanged and exit code is 0."""
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        target = tmp_path / "target"
        target.mkdir()
        (target / "file.txt").write_text("hello world\n")
        out = tmp_path / "out"
        args = _make_args(target_dir=target, out=out)
        result = handle_anonymize(args)
        assert result == 0

    def test_anonymize_replaces_mapped_values(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Mapped values in the input files are replaced in the output."""
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        # Seed the project map
        write_project_map(config, [
            MapEntry(
                identifier_type="ipv4",
                original_value="10.0.1.50",
                anonymized_value="10.0.99.99",
                scope="project",
                preserve_format=True,
            )
        ])
        target = tmp_path / "target"
        target.mkdir()
        (target / "file.txt").write_text("IP is 10.0.1.50\n")
        out = tmp_path / "out"
        args = _make_args(target_dir=target, out=out)
        result = handle_anonymize(args)
        assert result == 0
        output_file = out / "file.txt"
        assert output_file.exists()
        content = output_file.read_text()
        assert "10.0.99.99" in content
        assert "10.0.1.50" not in content


# ---------------------------------------------------------------------------
# TestHandleReveal
# ---------------------------------------------------------------------------


class TestHandleReveal:
    """Tests for handle_reveal()."""

    def test_nonexistent_dir_returns_one(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        args = _make_args(target_dir=tmp_path / "no_such_dir", out=tmp_path / "out")
        result = handle_reveal(args)
        assert result == 1

    def test_output_inside_target_returns_one(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        target = tmp_path / "target"
        target.mkdir()
        out = target / "subdir"  # inside target
        args = _make_args(target_dir=target, out=out)
        result = handle_reveal(args)
        assert result == 1

    def test_reveal_no_map_returns_one(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """When no map entries exist, reveal cannot work and returns 1."""
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        target = tmp_path / "target"
        target.mkdir()
        (target / "file.txt").write_text("IP is 10.0.99.99\n")
        out = tmp_path / "out"
        args = _make_args(target_dir=target, out=out)
        result = handle_reveal(args)
        assert result == 1

    def test_reveal_restores_original_values(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Reveal should invert the map and restore original values."""
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        write_project_map(config, [
            MapEntry(
                identifier_type="ipv4",
                original_value="10.0.1.50",
                anonymized_value="10.0.99.99",
                scope="project",
                preserve_format=True,
            )
        ])
        target = tmp_path / "target"
        target.mkdir()
        (target / "file.txt").write_text("IP is 10.0.99.99\n")
        out = tmp_path / "out"
        args = _make_args(target_dir=target, out=out)
        result = handle_reveal(args)
        assert result == 0
        output_file = out / "file.txt"
        assert output_file.exists()
        content = output_file.read_text()
        assert "10.0.1.50" in content
        assert "10.0.99.99" not in content


# ---------------------------------------------------------------------------
# TestHandleMapShow
# ---------------------------------------------------------------------------


class TestHandleMapShow:
    """Tests for handle_map_show()."""

    def test_empty_map_returns_zero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        args = _make_args(scope="project")
        result = handle_map_show(args)
        assert result == 0

    def test_shows_entries_from_project_map(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        write_project_map(config, [
            MapEntry(
                identifier_type="ipv4",
                original_value="10.0.1.50",
                anonymized_value="10.0.99.99",
                scope="project",
                preserve_format=True,
            )
        ])
        args = _make_args(scope="project")
        result = handle_map_show(args)
        assert result == 0

    def test_merged_scope_combines_maps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        # Write a global map entry
        config.global_map_path.parent.mkdir(parents=True, exist_ok=True)
        config.global_map_path.write_text(
            "identifier_type,original_value,anonymized_value,scope,preserve_format\n"
            "hostname,DC-PRIMARY,SRV-ALPHA-01,global,true\n"
        )
        write_project_map(config, [
            MapEntry(
                identifier_type="ipv4",
                original_value="10.0.1.50",
                anonymized_value="10.0.99.99",
                scope="project",
                preserve_format=True,
            )
        ])
        args = _make_args(scope="merged")
        result = handle_map_show(args)
        assert result == 0


# ---------------------------------------------------------------------------
# TestHandleMapAdd
# ---------------------------------------------------------------------------


class TestHandleMapAdd:
    """Tests for handle_map_add()."""

    def test_invalid_type_returns_one(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        args = _make_args(type="foobar", original="10.0.1.50", anonymized="10.0.99.99")
        result = handle_map_add(args)
        assert result == 1

    def test_identical_values_returns_one(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        args = _make_args(type="ipv4", original="10.0.1.50", anonymized="10.0.1.50")
        result = handle_map_add(args)
        assert result == 1

    def test_adds_entry_to_project_map(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        args = _make_args(type="ipv4", original="10.0.1.50", anonymized="10.0.99.99")
        result = handle_map_add(args)
        assert result == 0
        assert config.project_map_path.exists()
        content = config.project_map_path.read_text()
        assert "10.0.1.50" in content
        assert "10.0.99.99" in content

    def test_all_valid_identifier_types_accepted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Each supported type should be accepted without error."""
        valid_cases = [
            ("ipv4", "10.0.1.50", "10.0.99.99"),
            ("hostname", "SQL-PROD-03", "SRV-ALPHA-01"),
            ("upn", "jsmith@contoso.com", "user001@fabrikam.com"),
            ("guid", "a1b2c3d4-0000-0000-0000-000000000001", "b2c3d4e5-0000-0000-0000-000000000002"),
            ("mac", "AA:BB:CC:11:22:33", "AA:BB:CC:44:55:66"),
        ]
        for id_type, orig, anon in valid_cases:
            config = isolated_config(tmp_path / id_type)
            monkeypatch.setattr("logmask.cli.Config.default", lambda c=config: c)
            args = _make_args(type=id_type, original=orig, anonymized=anon)
            result = handle_map_add(args)
            assert result == 0, f"Expected 0 for type={id_type}"

    def test_prints_confirmation_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        args = _make_args(type="ipv4", original="10.0.1.50", anonymized="10.0.99.99")
        handle_map_add(args)
        captured = capsys.readouterr()
        assert "10.0.1.50" in captured.out
        assert "10.0.99.99" in captured.out


# ---------------------------------------------------------------------------
# TestMain
# ---------------------------------------------------------------------------


class TestMain:
    """Tests for main() dispatch and edge cases."""

    def test_no_command_returns_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "argv", ["logmask"])
        result = main()
        assert result == 0

    def test_init_command_dispatched(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        monkeypatch.setattr(sys, "argv", ["logmask", "init"])
        result = main()
        assert result == 0

    def test_map_no_subcommand_returns_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """'logmask map' with no sub-command should print help and return 0."""
        monkeypatch.setattr(sys, "argv", ["logmask", "map"])
        # parse_args(["map", "--help"]) calls sys.exit(0); catch it
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    def test_map_add_dispatched(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        monkeypatch.setattr(
            sys, "argv",
            ["logmask", "map", "add", "ipv4", "10.0.1.50", "10.0.99.99"],
        )
        result = main()
        assert result == 0

    def test_map_show_dispatched(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = isolated_config(tmp_path)
        monkeypatch.setattr("logmask.cli.Config.default", lambda: config)
        monkeypatch.setattr(sys, "argv", ["logmask", "map", "show"])
        result = main()
        assert result == 0
