"""Tests for version comparison and distance utility functions.

These functions are now part of the client module but are tested
separately since they're pure utility functions.
"""

from typing import TYPE_CHECKING

import pytest

from sofapy.client import _SofaClientBase

if TYPE_CHECKING:
    pass


@pytest.fixture
def base_client() -> _SofaClientBase:
    """Provide a base client instance for testing utility methods."""
    return _SofaClientBase()


def test_version_is_newer_major_version(base_client: _SofaClientBase) -> None:
    """Test version comparison with different major versions."""
    assert base_client._version_is_newer([15, 0, 0], [14, 0, 0]) is True
    assert base_client._version_is_newer([14, 0, 0], [15, 0, 0]) is False


def test_version_is_newer_minor_version(base_client: _SofaClientBase) -> None:
    """Test version comparison with different minor versions."""
    assert base_client._version_is_newer([14, 2, 0], [14, 1, 0]) is True
    assert base_client._version_is_newer([14, 1, 0], [14, 2, 0]) is False


def test_version_is_newer_patch_version(base_client: _SofaClientBase) -> None:
    """Test version comparison with different patch versions."""
    assert base_client._version_is_newer([14, 1, 2], [14, 1, 1]) is True
    assert base_client._version_is_newer([14, 1, 1], [14, 1, 2]) is False


def test_version_is_newer_equal_versions(base_client: _SofaClientBase) -> None:
    """Test version comparison with equal versions."""
    assert base_client._version_is_newer([14, 1, 1], [14, 1, 1]) is False


def test_version_is_newer_different_lengths(base_client: _SofaClientBase) -> None:
    """Test version comparison with different version lengths."""
    assert base_client._version_is_newer([14, 2], [14, 1, 5]) is True
    assert base_client._version_is_newer([14, 1, 5], [14, 2]) is False
    assert base_client._version_is_newer([14, 1], [14, 1, 0]) is False  # Equal when padded


def test_version_is_newer_empty_versions(base_client: _SofaClientBase) -> None:
    """Test version comparison with empty version lists."""
    assert base_client._version_is_newer([1], []) is True
    assert base_client._version_is_newer([], [1]) is False
    assert base_client._version_is_newer([], []) is False


def test_calculate_version_distance_same_version(base_client: _SofaClientBase) -> None:
    """Test distance calculation when versions are the same."""
    assert base_client._calculate_version_distance([14, 1, 0], [14, 1, 0]) == 0


def test_calculate_version_distance_current_is_newer(base_client: _SofaClientBase) -> None:
    """Test distance calculation when current is newer than latest."""
    assert base_client._calculate_version_distance([15, 0, 0], [14, 0, 0]) == 0


def test_calculate_version_distance_major_difference(base_client: _SofaClientBase) -> None:
    """Test distance calculation with major version difference."""
    distance = base_client._calculate_version_distance([14, 0, 0], [15, 0, 0])
    assert distance > 0


def test_calculate_version_distance_minor_difference(base_client: _SofaClientBase) -> None:
    """Test distance calculation with minor version difference."""
    distance = base_client._calculate_version_distance([14, 1, 0], [14, 3, 0])
    assert distance > 0


def test_calculate_version_distance_patch_difference(base_client: _SofaClientBase) -> None:
    """Test distance calculation with patch version difference."""
    distance = base_client._calculate_version_distance([14, 1, 0], [14, 1, 2])
    assert distance > 0


def test_calculate_version_distance_weighting(base_client: _SofaClientBase) -> None:
    """Test that major version differences are weighted more heavily."""
    major_distance = base_client._calculate_version_distance([14, 0, 0], [15, 0, 0])
    minor_distance = base_client._calculate_version_distance([14, 0, 0], [14, 1, 0])
    patch_distance = base_client._calculate_version_distance([14, 0, 0], [14, 0, 1])

    assert major_distance > minor_distance
    assert minor_distance > patch_distance


def test_get_currency_recommendation_current(base_client: _SofaClientBase) -> None:
    """Test recommendation when OS is current."""
    result = base_client._get_currency_recommendation(
        is_current=True, versions_behind=0, updates_missed=0
    )
    assert "no action needed" in result.lower()


def test_get_currency_recommendation_critical(base_client: _SofaClientBase) -> None:
    """Test recommendation when multiple security updates are missed."""
    result = base_client._get_currency_recommendation(
        is_current=False, versions_behind=1, updates_missed=3
    )
    assert "CRITICAL" in result


def test_get_currency_recommendation_high(base_client: _SofaClientBase) -> None:
    """Test recommendation when multiple versions behind."""
    result = base_client._get_currency_recommendation(
        is_current=False, versions_behind=3, updates_missed=0
    )
    assert "HIGH" in result


def test_get_currency_recommendation_medium(base_client: _SofaClientBase) -> None:
    """Test recommendation when security updates available."""
    result = base_client._get_currency_recommendation(
        is_current=False, versions_behind=1, updates_missed=1
    )
    assert "MEDIUM" in result


def test_get_currency_recommendation_low(base_client: _SofaClientBase) -> None:
    """Test recommendation for minor version update."""
    result = base_client._get_currency_recommendation(
        is_current=False, versions_behind=1, updates_missed=0
    )
    assert "LOW" in result
