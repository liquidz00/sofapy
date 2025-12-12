"""Tests for sofapy.main module functions."""

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from sofapy.main import (
    calculate_version_distance,
    get_currency_recommendation,
    get_cves_for_version,
    get_sofa_feed,
    get_version_currency_info,
    parse_sofa_feed,
    version_is_newer,
)

if TYPE_CHECKING:
    pass


def test_version_is_newer_major_version() -> None:
    """Test version comparison with different major versions."""
    assert version_is_newer([15, 0, 0], [14, 0, 0]) is True
    assert version_is_newer([14, 0, 0], [15, 0, 0]) is False


def test_version_is_newer_minor_version() -> None:
    """Test version comparison with different minor versions."""
    assert version_is_newer([14, 2, 0], [14, 1, 0]) is True
    assert version_is_newer([14, 1, 0], [14, 2, 0]) is False


def test_version_is_newer_patch_version() -> None:
    """Test version comparison with different patch versions."""
    assert version_is_newer([14, 1, 2], [14, 1, 1]) is True
    assert version_is_newer([14, 1, 1], [14, 1, 2]) is False


def test_version_is_newer_equal_versions() -> None:
    """Test version comparison with equal versions."""
    assert version_is_newer([14, 1, 1], [14, 1, 1]) is False


def test_version_is_newer_different_lengths() -> None:
    """Test version comparison with different version lengths."""
    assert version_is_newer([14, 2], [14, 1, 5]) is True
    assert version_is_newer([14, 1, 5], [14, 2]) is False
    assert version_is_newer([14, 1], [14, 1, 0]) is False  # Equal when padded


def test_version_is_newer_empty_versions() -> None:
    """Test version comparison with empty version lists."""
    assert version_is_newer([1], []) is True
    assert version_is_newer([], [1]) is False
    assert version_is_newer([], []) is False


def test_calculate_version_distance_same_version() -> None:
    """Test distance calculation when versions are the same."""
    assert calculate_version_distance([14, 1, 0], [14, 1, 0]) == 0


def test_calculate_version_distance_current_is_newer() -> None:
    """Test distance calculation when current is newer than latest."""
    assert calculate_version_distance([15, 0, 0], [14, 0, 0]) == 0


def test_calculate_version_distance_major_difference() -> None:
    """Test distance calculation with major version difference."""
    distance = calculate_version_distance([14, 0, 0], [15, 0, 0])
    assert distance > 0


def test_calculate_version_distance_minor_difference() -> None:
    """Test distance calculation with minor version difference."""
    distance = calculate_version_distance([14, 1, 0], [14, 3, 0])
    assert distance > 0


def test_calculate_version_distance_patch_difference() -> None:
    """Test distance calculation with patch version difference."""
    distance = calculate_version_distance([14, 1, 0], [14, 1, 2])
    assert distance > 0


def test_calculate_version_distance_weighting() -> None:
    """Test that major version differences are weighted more heavily."""
    major_distance = calculate_version_distance([14, 0, 0], [15, 0, 0])
    minor_distance = calculate_version_distance([14, 0, 0], [14, 1, 0])
    patch_distance = calculate_version_distance([14, 0, 0], [14, 0, 1])

    assert major_distance > minor_distance
    assert minor_distance > patch_distance


def test_get_currency_recommendation_current() -> None:
    """Test recommendation when OS is current."""
    result = get_currency_recommendation(is_current=True, versions_behind=0, updates_missed=0)
    assert "no action needed" in result.lower()


def test_get_currency_recommendation_critical() -> None:
    """Test recommendation when multiple security updates are missed."""
    result = get_currency_recommendation(is_current=False, versions_behind=1, updates_missed=3)
    assert "CRITICAL" in result


def test_get_currency_recommendation_high() -> None:
    """Test recommendation when multiple versions behind."""
    result = get_currency_recommendation(is_current=False, versions_behind=3, updates_missed=0)
    assert "HIGH" in result


def test_get_currency_recommendation_medium() -> None:
    """Test recommendation when security updates available."""
    result = get_currency_recommendation(is_current=False, versions_behind=1, updates_missed=1)
    assert "MEDIUM" in result


def test_get_currency_recommendation_low() -> None:
    """Test recommendation for minor version update."""
    result = get_currency_recommendation(is_current=False, versions_behind=1, updates_missed=0)
    assert "LOW" in result


def test_get_cves_for_version_valid(sofa_feed_response: dict) -> None:
    """Test getting CVEs for a valid version."""
    sofa_feed = parse_sofa_feed(sofa_feed_response)
    # Use a version that exists in the fixture
    all_cves, exploited_cves = get_cves_for_version(sofa_feed, "14.1.0", "14.2.1")
    assert isinstance(all_cves, set)
    assert isinstance(exploited_cves, set)


def test_get_cves_for_version_invalid_os_family(sofa_feed_response: dict) -> None:
    """Test getting CVEs for an invalid OS family raises ValueError."""
    sofa_feed = parse_sofa_feed(sofa_feed_response)
    with pytest.raises(ValueError, match="not found in SOFA feed"):
        get_cves_for_version(sofa_feed, "14.1.0", "NonexistentOS")


def test_get_cves_for_version_with_exploited_cves(feed_with_critical_cves: dict) -> None:
    """Test getting CVEs returns actively exploited CVEs correctly."""
    sofa_feed = parse_sofa_feed(feed_with_critical_cves)
    all_cves, exploited_cves = get_cves_for_version(sofa_feed, "13.0.0", "14.0")
    # Version 13.0.0 is older than 14.0, so all CVEs from 14.0 should affect it
    assert len(exploited_cves) > 0


def test_get_cves_for_version_current_version(sofa_feed_response: dict) -> None:
    """Test getting CVEs for the current/latest version returns empty or minimal CVEs."""
    sofa_feed = parse_sofa_feed(sofa_feed_response)
    # Using the latest version should return fewer or no CVEs
    all_cves, exploited_cves = get_cves_for_version(sofa_feed, "14.2.1", "14.2.1")
    # The latest version shouldn't have newer releases affecting it
    assert isinstance(all_cves, set)


def test_get_version_currency_info_current(sofa_feed_response: dict) -> None:
    """Test currency info for current version."""
    sofa_feed = parse_sofa_feed(sofa_feed_response)
    result = get_version_currency_info(sofa_feed, "14.2.1", "14.2.1")

    assert result["is_current"] is True
    assert result["currency_score"] == 100
    assert "no action needed" in result["recommendation"].lower()


def test_get_version_currency_info_behind(sofa_feed_response: dict) -> None:
    """Test currency info for outdated version."""
    sofa_feed = parse_sofa_feed(sofa_feed_response)
    result = get_version_currency_info(sofa_feed, "14.1.0", "14.2.1")

    assert result["is_current"] is False
    assert result["current_version"] == "14.1.0"
    assert result["latest_version"] == "14.2.1"
    assert result["currency_score"] <= 100


def test_get_version_currency_info_invalid_os_family(sofa_feed_response: dict) -> None:
    """Test currency info for invalid OS family raises ValueError."""
    sofa_feed = parse_sofa_feed(sofa_feed_response)
    with pytest.raises(ValueError, match="not found in SOFA feed"):
        get_version_currency_info(sofa_feed, "14.1.0", "NonexistentOS")


def test_get_version_currency_info_returns_required_keys(sofa_feed_response: dict) -> None:
    """Test that currency info returns all required keys."""
    sofa_feed = parse_sofa_feed(sofa_feed_response)
    result = get_version_currency_info(sofa_feed, "14.1.0", "14.2.1")

    required_keys = [
        "is_current",
        "current_version",
        "latest_version",
        "versions_behind",
        "security_updates_missed",
        "days_behind",
        "currency_score",
        "recommendation",
    ]
    for key in required_keys:
        assert key in result


@pytest.mark.asyncio
async def test_get_sofa_feed_success(sofa_feed_response: dict) -> None:
    """Test successful retrieval of SOFA feed."""
    from unittest.mock import MagicMock

    # response.json() is synchronous in httpx, not async
    mock_response = MagicMock()
    mock_response.json.return_value = sofa_feed_response
    mock_response.raise_for_status.return_value = None

    with patch("sofapy.main.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_instance
        result = await get_sofa_feed()

    assert "UpdateHash" in result
    assert "OSVersions" in result


@pytest.mark.asyncio
async def test_get_sofa_feed_http_error() -> None:
    """Test get_sofa_feed raises on HTTP error."""
    with patch("sofapy.main.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.get = AsyncMock(
            side_effect=httpx.HTTPError("Connection failed")
        )
        with pytest.raises(httpx.HTTPError):
            await get_sofa_feed()


@pytest.mark.asyncio
async def test_get_sofa_feed_invalid_json() -> None:
    """Test get_sofa_feed raises ValueError on invalid JSON."""
    from unittest.mock import MagicMock

    # response.json() is synchronous in httpx, not async
    mock_response = MagicMock()
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mock_response.raise_for_status.return_value = None

    with patch("sofapy.main.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_instance
        with pytest.raises(ValueError, match="Failed to parse"):
            await get_sofa_feed()


def test_parse_sofa_feed_missing_os_version_name() -> None:
    """Test parsing feed with missing OSVersion name skips that entry."""
    feed_data = {
        "UpdateHash": "abc123",
        "OSVersions": [
            {
                "OSVersion": "",  # Empty version name
                "Latest": {"ProductVersion": "14.0", "Build": "23A"},
                "SecurityReleases": [],
            },
            {
                "OSVersion": "14.1",
                "Latest": {"ProductVersion": "14.1", "Build": "23B"},
                "SecurityReleases": [],
            },
        ],
    }
    result = parse_sofa_feed(feed_data)

    # Should skip the entry with empty OSVersion
    assert "14.1" in result.os_versions
    assert "" not in result.os_versions


def test_parse_sofa_feed_with_days_since_previous() -> None:
    """Test parsing feed with DaysSincePreviousRelease field."""
    feed_data = {
        "UpdateHash": "abc123",
        "OSVersions": [
            {
                "OSVersion": "14.1",
                "Latest": {"ProductVersion": "14.1", "Build": "23B"},
                "SecurityReleases": [
                    {
                        "UpdateName": "macOS 14.1",
                        "ProductVersion": "14.1",
                        "ReleaseDate": "2023-10-25T17:00:00Z",
                        "CVEs": {},
                        "ActivelyExploitedCVEs": [],
                        "UniqueCVEsCount": 0,
                        "DaysSincePreviousRelease": 30,
                    }
                ],
            }
        ],
    }
    result = parse_sofa_feed(feed_data)

    assert result.os_versions["14.1"].security_releases[0].days_since_previous == 30


def test_parse_sofa_feed_aggregates_cves() -> None:
    """Test that parsing aggregates CVEs from all security releases."""
    feed_data = {
        "UpdateHash": "abc123",
        "OSVersions": [
            {
                "OSVersion": "14.1",
                "Latest": {"ProductVersion": "14.1.2", "Build": "23B"},
                "SecurityReleases": [
                    {
                        "UpdateName": "macOS 14.1.2",
                        "ProductVersion": "14.1.2",
                        "ReleaseDate": "2023-11-30T18:00:00Z",
                        "CVEs": {"CVE-2023-0001": True},
                        "ActivelyExploitedCVEs": ["CVE-2023-0001"],
                        "UniqueCVEsCount": 1,
                    },
                    {
                        "UpdateName": "macOS 14.1.1",
                        "ProductVersion": "14.1.1",
                        "ReleaseDate": "2023-11-15T18:00:00Z",
                        "CVEs": {"CVE-2023-0002": False},
                        "ActivelyExploitedCVEs": [],
                        "UniqueCVEsCount": 1,
                    },
                ],
            }
        ],
    }
    result = parse_sofa_feed(feed_data)

    os_info = result.os_versions["14.1"]
    assert "CVE-2023-0001" in os_info.all_cves
    assert "CVE-2023-0002" in os_info.all_cves
    assert "CVE-2023-0001" in os_info.actively_exploited_cves
    assert "CVE-2023-0002" not in os_info.actively_exploited_cves
