"""Tests for sofapy.cli module functions and commands."""

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

import pytest
from asyncclick.testing import CliRunner

from sofapy.cli import format_err, output_json
from sofapy.models import CurrencyInfo, CVEResult, LatestInfo, SOFAFeed

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


@pytest.fixture
def cli_runner() -> CliRunner:
    """Provide a CLI runner for testing commands."""
    return CliRunner()


@pytest.fixture
def mock_sofa_feed(sofa_feed_response: dict[str, Any]) -> SOFAFeed:
    """Create a mock SOFAFeed from response fixture."""
    from sofapy.client import _SofaClientBase

    base = _SofaClientBase()
    return base._parse_feed(sofa_feed_response)


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

    mock_client = AsyncMock()
    mock_client.get_feed.return_value = sofa_feed_response

    with patch("sofapy.cli.AsyncSofaClient", return_value=mock_client):
        result = await cli_runner.invoke(cli, ["feed", "--raw"])

    assert result.exit_code == 0
    assert "UpdateHash" in result.output


@pytest.mark.asyncio
async def test_feed_command_parsed(
    cli_runner: CliRunner,
    mock_sofa_feed: SOFAFeed,
) -> None:
    """Test feed command with parsed output."""
    from sofapy.cli import cli

    mock_client = AsyncMock()
    mock_client.get_feed.return_value = mock_sofa_feed

    with patch("sofapy.cli.AsyncSofaClient", return_value=mock_client):
        result = await cli_runner.invoke(cli, ["feed"])

    assert result.exit_code == 0
    assert "update_hash" in result.output or "os_versions" in result.output


@pytest.mark.asyncio
async def test_latest_command(
    cli_runner: CliRunner,
) -> None:
    """Test latest command displays version info."""
    from sofapy.cli import cli

    mock_client = AsyncMock()
    mock_client.get_latest.return_value = {
        "Sequoia 15": LatestInfo(
            os_family="Sequoia 15",
            latest_version="15.1.0",
            latest_build="24A100",
            release_date="2024-01-01",
            total_cves=5,
            actively_exploited_count=1,
        )
    }

    with patch("sofapy.cli.AsyncSofaClient", return_value=mock_client):
        result = await cli_runner.invoke(cli, ["latest"])

    assert result.exit_code == 0
    assert "Latest" in result.output or "15.1.0" in result.output


@pytest.mark.asyncio
async def test_latest_command_json_output(
    cli_runner: CliRunner,
) -> None:
    """Test latest command with JSON output."""
    from sofapy.cli import cli

    mock_client = AsyncMock()
    mock_client.get_latest.return_value = {
        "Sequoia 15": LatestInfo(
            os_family="Sequoia 15",
            latest_version="15.1.0",
            latest_build="24A100",
            release_date="2024-01-01",
            total_cves=5,
            actively_exploited_count=0,
        )
    }

    with patch("sofapy.cli.AsyncSofaClient", return_value=mock_client):
        result = await cli_runner.invoke(cli, ["latest", "--json"])

    assert result.exit_code == 0
    assert "latest_version" in result.output


@pytest.mark.asyncio
async def test_latest_command_with_filter(
    cli_runner: CliRunner,
) -> None:
    """Test latest command with OS filter."""
    from sofapy.cli import cli

    mock_client = AsyncMock()
    mock_client.get_latest.return_value = {
        "Sonoma 14": LatestInfo(
            os_family="Sonoma 14",
            latest_version="14.2.1",
            latest_build="23C71",
            release_date="2023-12-11",
            total_cves=3,
            actively_exploited_count=0,
        )
    }

    with patch("sofapy.cli.AsyncSofaClient", return_value=mock_client):
        result = await cli_runner.invoke(cli, ["latest", "--os", "14"])

    assert result.exit_code == 0


@pytest.mark.asyncio
async def test_cves_command(
    cli_runner: CliRunner,
) -> None:
    """Test cves command displays CVE information."""
    from sofapy.cli import cli

    mock_client = AsyncMock()
    mock_client.get_cves.return_value = CVEResult(
        version="14.1.0",
        os_family="Sonoma 14",
        all_cves={"CVE-2023-0001", "CVE-2023-0002"},
        actively_exploited_cves={"CVE-2023-0001"},
        total_count=2,
        exploited_count=1,
    )

    with patch("sofapy.cli.AsyncSofaClient", return_value=mock_client):
        result = await cli_runner.invoke(cli, ["cves", "14.1.0"])

    assert result.exit_code == 0
    assert "CVE" in result.output or "Total" in result.output


@pytest.mark.asyncio
async def test_cves_command_json_output(
    cli_runner: CliRunner,
) -> None:
    """Test cves command with JSON output."""
    from sofapy.cli import cli

    mock_client = AsyncMock()
    mock_client.get_cves.return_value = CVEResult(
        version="14.1.0",
        os_family="Sonoma 14",
        all_cves={"CVE-2023-0001"},
        actively_exploited_cves=set(),
        total_count=1,
        exploited_count=0,
    )

    with patch("sofapy.cli.AsyncSofaClient", return_value=mock_client):
        result = await cli_runner.invoke(cli, ["cves", "14.1.0", "--json"])

    assert result.exit_code == 0
    assert "version" in result.output
    assert "os_family" in result.output


@pytest.mark.asyncio
async def test_cves_command_exploited_only(
    cli_runner: CliRunner,
) -> None:
    """Test cves command with exploited-only filter."""
    from sofapy.cli import cli

    mock_client = AsyncMock()
    mock_client.get_cves.return_value = CVEResult(
        version="14.0",
        os_family="Sonoma 14",
        all_cves={"CVE-2023-0001"},
        actively_exploited_cves={"CVE-2023-0001"},
        total_count=1,
        exploited_count=1,
    )

    with patch("sofapy.cli.AsyncSofaClient", return_value=mock_client):
        result = await cli_runner.invoke(cli, ["cves", "14.0", "--exploited-only"])

    assert result.exit_code == 0


@pytest.mark.asyncio
async def test_cves_command_unknown_version(
    cli_runner: CliRunner,
) -> None:
    """Test cves command with unknown version shows error."""
    from sofapy.cli import cli

    mock_client = AsyncMock()
    mock_client.get_cves.side_effect = ValueError(
        "Could not determine OS family for version 99.0.0"
    )

    with patch("sofapy.cli.AsyncSofaClient", return_value=mock_client):
        result = await cli_runner.invoke(cli, ["cves", "99.0.0"])

    # Should fail because version 99.x doesn't exist
    assert result.exit_code != 0


@pytest.mark.asyncio
async def test_cves_command_no_cves(
    cli_runner: CliRunner,
) -> None:
    """Test cves command when no CVEs are found."""
    from sofapy.cli import cli

    mock_client = AsyncMock()
    mock_client.get_cves.return_value = CVEResult(
        version="15.1.0",
        os_family="Sequoia 15",
        all_cves=set(),
        actively_exploited_cves=set(),
        total_count=0,
        exploited_count=0,
    )

    with patch("sofapy.cli.AsyncSofaClient", return_value=mock_client):
        result = await cli_runner.invoke(cli, ["cves", "15.1.0"])

    assert result.exit_code == 0
    assert "No known CVEs" in result.output


@pytest.mark.asyncio
async def test_currency_command(
    cli_runner: CliRunner,
) -> None:
    """Test currency command displays currency info."""
    from sofapy.cli import cli

    mock_client = AsyncMock()
    mock_client.get_currency_info.return_value = CurrencyInfo(
        is_current=False,
        current_version="15.0.0",
        latest_version="15.1.0",
        os_family="Sequoia 15",
        versions_behind=2,
        security_updates_missed=1,
        days_behind=30,
        currency_score=75,
        recommendation="MEDIUM: Security updates available - update when convenient",
    )

    with patch("sofapy.cli.AsyncSofaClient", return_value=mock_client):
        result = await cli_runner.invoke(cli, ["currency", "15.0.0"])

    assert result.exit_code == 0
    assert "Currency" in result.output
    assert "Score" in result.output or "75" in result.output


@pytest.mark.asyncio
async def test_currency_command_json_output(
    cli_runner: CliRunner,
) -> None:
    """Test currency command with JSON output."""
    from sofapy.cli import cli

    mock_client = AsyncMock()
    mock_client.get_currency_info.return_value = CurrencyInfo(
        is_current=True,
        current_version="15.1.0",
        latest_version="15.1.0",
        os_family="Sequoia 15",
        currency_score=100,
        recommendation="OS is current - no action needed",
    )

    with patch("sofapy.cli.AsyncSofaClient", return_value=mock_client):
        result = await cli_runner.invoke(cli, ["currency", "15.1.0", "--json"])

    assert result.exit_code == 0
    assert "is_current" in result.output
    assert "currency_score" in result.output


@pytest.mark.asyncio
async def test_currency_command_current_version(
    cli_runner: CliRunner,
) -> None:
    """Test currency command when version is current."""
    from sofapy.cli import cli

    mock_client = AsyncMock()
    mock_client.get_currency_info.return_value = CurrencyInfo(
        is_current=True,
        current_version="15.1.0",
        latest_version="15.1.0",
        os_family="Sequoia 15",
        currency_score=100,
        recommendation="OS is current - no action needed",
    )

    with patch("sofapy.cli.AsyncSofaClient", return_value=mock_client):
        result = await cli_runner.invoke(cli, ["currency", "15.1.0"])

    assert result.exit_code == 0
    assert "up to date" in result.output


@pytest.mark.asyncio
async def test_cli_debug_mode(
    cli_runner: CliRunner,
) -> None:
    """Test CLI debug mode flag is accepted."""
    from sofapy.cli import cli

    mock_client = AsyncMock()
    mock_client.get_latest.return_value = {}

    with patch("sofapy.cli.AsyncSofaClient", return_value=mock_client):
        result = await cli_runner.invoke(cli, ["--debug", "latest"])

    # Should not error due to debug flag
    assert result.exit_code == 0
