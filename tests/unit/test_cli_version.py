"""Tests for the kua CLI version command."""

from typer.testing import CliRunner

from kua.cli.main import app

runner = CliRunner()


def test_cli_version() -> None:
    """Assert kua version exits 0 and prints version information."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "kua" in result.stdout


def test_cli_scan_placeholder() -> None:
    """Assert kua scan exits 2 and prints not implemented."""
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 2
    assert "not implemented" in result.stdout
