"""Tests for sofapy.cli module functions and commands."""

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

import pytest
from asyncclick.testing import CliRunner

from sofapy.cli import format_err, infer_os_family, output_json
from sofapy.main import parse_sofa_feed

if TYPE_CHECKING:
    from _pytest.capture import CaptureFixture


def test_format_err_outputs_error_message(capsys: "CaptureFixture[str]") -> None:
    """Test format_err outputs formatted error message to stderr."""
    exc = Exception("Test error message")
    format_err(exc)

    captured = capsys.readouterr()
    assert "Test error message" in captured.err
    assert "Error" in captured.err


def test_format_err_handles_empty_message(capsys: "CaptureFixture[str]") -> None:
    """Test format_err handles exception with empty message."""
    exc = Exception("")
    format_err(exc)

    captured = capsys.readouterr()
    assert "Error" in captured.err


def test_output_json_dict(capsys: "CaptureFixture[str]") -> None:
    """Test output_json correctly formats dictionary."""
    data = {"key": "value", "number": 42}
    output_json(data)

    captured = capsys.readouterr()
    assert '"key": "value"' in captured.out
    assert '"number": 42' in captured.out


def test_output_json_list(capsys: "CaptureFixture[str]") -> None:
    """Test output_json correctly formats list."""
    data = [1, 2, 3]
    output_json(data)

    captured = capsys.readouterr()
    assert "1" in captured.out
    assert "2" in captured.out
    assert "3" in captured.out


def test_output_json_nested(capsys: "CaptureFixture[str]") -> None:
    """Test output_json correctly formats nested structures."""
    data = {"outer": {"inner": "value"}}
    output_json(data)

    captured = capsys.readouterr()
    assert '"outer"' in captured.out
    assert '"inner"' in captured.out


def test_infer_os_family_finds_match(sofa_feed_response: dict[str, Any]) -> None:
    """Test infer_os_family finds matching OS family."""
    sofa_feed = parse_sofa_feed(sofa_feed_response)
    result = infer_os_family(sofa_feed, "14.2.1")

    assert result is not None
    assert "14" in result


def test_infer_os_family_no_match(sofa_feed_response: dict[str, Any]) -> None:
    """Test infer_os_family returns None when no match found."""
    sofa_feed = parse_sofa_feed(sofa_feed_response)
    result = infer_os_family(sofa_feed, "99.0.0")

    assert result is None


def test_infer_os_family_uses_major_version(sofa_feed_response: dict[str, Any]) -> None:
    """Test infer_os_family matches based on major version."""
    sofa_feed = parse_sofa_feed(sofa_feed_response)
    # Should match any 14.x version
    result = infer_os_family(sofa_feed, "14.9.9")

    assert result is not None


def test_infer_os_family_different_major_versions(sofa_feed_response: dict[str, Any]) -> None:
    """Test infer_os_family correctly distinguishes major versions."""
    sofa_feed = parse_sofa_feed(sofa_feed_response)

    result_14 = infer_os_family(sofa_feed, "14.0.0")
    result_13 = infer_os_family(sofa_feed, "13.0.0")
    result_12 = infer_os_family(sofa_feed, "12.0.0")

    # Each should find their respective OS family
    assert result_14 is not None
    assert result_13 is not None
    assert result_12 is not None


@pytest.fixture
def cli_runner() -> CliRunner:
    """Provide a CLI runner for testing commands."""
    return CliRunner()


@pytest.mark.asyncio
async def test_cli_help(cli_runner: CliRunner) -> None:
    """Test CLI shows help when invoked without subcommand."""
    from sofapy.cli import cli

    result = await cli_runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "sofapy" in result.output


@pytest.mark.asyncio
async def test_cli_version(cli_runner: CliRunner) -> None:
    """Test CLI version option."""
    from sofapy.cli import cli

    result = await cli_runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output or "version" in result.output.lower()


@pytest.mark.asyncio
async def test_feed_command_raw(
    cli_runner: CliRunner,
    sofa_feed_response: dict[str, Any],
) -> None:
    """Test feed command with raw output."""
    from sofapy.cli import cli

    with patch("sofapy.cli.get_sofa_feed", new_callable=AsyncMock) as mock_feed:
        mock_feed.return_value = sofa_feed_response

        result = await cli_runner.invoke(cli, ["feed", "--raw"])

    assert result.exit_code == 0
    assert "UpdateHash" in result.output


@pytest.mark.asyncio
async def test_feed_command_parsed(
    cli_runner: CliRunner,
    sofa_feed_response: dict[str, Any],
) -> None:
    """Test feed command with parsed output."""
    from sofapy.cli import cli

    with patch("sofapy.cli.get_sofa_feed", new_callable=AsyncMock) as mock_feed:
        mock_feed.return_value = sofa_feed_response

        result = await cli_runner.invoke(cli, ["feed"])

    assert result.exit_code == 0
    assert "update_hash" in result.output or "os_versions" in result.output


@pytest.mark.asyncio
async def test_latest_command(
    cli_runner: CliRunner,
    sofa_feed_response: dict[str, Any],
) -> None:
    """Test latest command displays version info."""
    from sofapy.cli import cli

    with patch("sofapy.cli.get_sofa_feed", new_callable=AsyncMock) as mock_feed:
        mock_feed.return_value = sofa_feed_response

        result = await cli_runner.invoke(cli, ["latest"])

    assert result.exit_code == 0
    assert "Latest" in result.output or "14.2.1" in result.output


@pytest.mark.asyncio
async def test_latest_command_json_output(
    cli_runner: CliRunner,
    sofa_feed_response: dict[str, Any],
) -> None:
    """Test latest command with JSON output."""
    from sofapy.cli import cli

    with patch("sofapy.cli.get_sofa_feed", new_callable=AsyncMock) as mock_feed:
        mock_feed.return_value = sofa_feed_response

        result = await cli_runner.invoke(cli, ["latest", "--json"])

    assert result.exit_code == 0
    assert "latest_version" in result.output


@pytest.mark.asyncio
async def test_latest_command_with_filter(
    cli_runner: CliRunner,
    sofa_feed_response: dict[str, Any],
) -> None:
    """Test latest command with OS filter."""
    from sofapy.cli import cli

    with patch("sofapy.cli.get_sofa_feed", new_callable=AsyncMock) as mock_feed:
        mock_feed.return_value = sofa_feed_response

        result = await cli_runner.invoke(cli, ["latest", "--os", "14"])

    assert result.exit_code == 0


@pytest.mark.asyncio
async def test_cves_command(
    cli_runner: CliRunner,
    sofa_feed_response: dict[str, Any],
) -> None:
    """Test cves command displays CVE information."""
    from sofapy.cli import cli

    with patch("sofapy.cli.get_sofa_feed", new_callable=AsyncMock) as mock_feed:
        mock_feed.return_value = sofa_feed_response

        result = await cli_runner.invoke(cli, ["cves", "14.1.0"])

    assert result.exit_code == 0
    assert "CVE" in result.output or "Total" in result.output


@pytest.mark.asyncio
async def test_cves_command_json_output(
    cli_runner: CliRunner,
    sofa_feed_response: dict[str, Any],
) -> None:
    """Test cves command with JSON output."""
    from sofapy.cli import cli

    with patch("sofapy.cli.get_sofa_feed", new_callable=AsyncMock) as mock_feed:
        mock_feed.return_value = sofa_feed_response

        result = await cli_runner.invoke(cli, ["cves", "14.1.0", "--json"])

    assert result.exit_code == 0
    assert "version" in result.output
    assert "os_family" in result.output


@pytest.mark.asyncio
async def test_cves_command_exploited_only(
    cli_runner: CliRunner,
    feed_with_critical_cves: dict[str, Any],
) -> None:
    """Test cves command with exploited-only filter."""
    from sofapy.cli import cli

    with patch("sofapy.cli.get_sofa_feed", new_callable=AsyncMock) as mock_feed:
        mock_feed.return_value = feed_with_critical_cves

        result = await cli_runner.invoke(cli, ["cves", "14.0", "--exploited-only"])

    assert result.exit_code == 0


@pytest.mark.asyncio
async def test_cves_command_unknown_version(
    cli_runner: CliRunner,
    sofa_feed_response: dict[str, Any],
) -> None:
    """Test cves command with unknown version shows error."""
    from sofapy.cli import cli

    with patch("sofapy.cli.get_sofa_feed", new_callable=AsyncMock) as mock_feed:
        mock_feed.return_value = sofa_feed_response

        result = await cli_runner.invoke(cli, ["cves", "99.0.0"])

    # Should fail because version 99.x doesn't exist
    assert result.exit_code != 0


@pytest.mark.asyncio
async def test_cli_debug_mode(
    cli_runner: CliRunner,
    sofa_feed_response: dict[str, Any],
) -> None:
    """Test CLI debug mode flag is accepted."""
    from sofapy.cli import cli

    with patch("sofapy.cli.get_sofa_feed", new_callable=AsyncMock) as mock_feed:
        mock_feed.return_value = sofa_feed_response

        result = await cli_runner.invoke(cli, ["--debug", "latest"])

    # Should not error due to debug flag
    assert result.exit_code == 0
