"""Tests for sofapy.models module Pydantic models."""

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from sofapy.models import CVEInfo, OSVersionInfo, SecurityRelease, SOFAFeed

if TYPE_CHECKING:
    pass


def test_cve_info_valid() -> None:
    """Test CVEInfo model with valid data."""
    cve = CVEInfo(cve_id="CVE-2023-42940", actively_exploited=True)

    assert cve.cve_id == "CVE-2023-42940"
    assert cve.actively_exploited is True


def test_cve_info_not_exploited() -> None:
    """Test CVEInfo model with non-exploited CVE."""
    cve = CVEInfo(cve_id="CVE-2023-12345", actively_exploited=False)

    assert cve.cve_id == "CVE-2023-12345"
    assert cve.actively_exploited is False


def test_cve_info_missing_cve_id() -> None:
    """Test CVEInfo model raises error when cve_id is missing."""
    with pytest.raises(ValidationError):
        CVEInfo(actively_exploited=True)  # type: ignore[call-arg]


def test_cve_info_missing_actively_exploited() -> None:
    """Test CVEInfo model raises error when actively_exploited is missing."""
    with pytest.raises(ValidationError):
        CVEInfo(cve_id="CVE-2023-12345")  # type: ignore[call-arg]


def test_security_release_minimal() -> None:
    """Test SecurityRelease model with minimal required fields."""
    release = SecurityRelease(
        update_name="macOS Sonoma 14.2.1",
        product_version="14.2.1",
        release_date="2023-12-11T18:00:00Z",
    )

    assert release.update_name == "macOS Sonoma 14.2.1"
    assert release.product_version == "14.2.1"
    assert release.release_date == "2023-12-11T18:00:00Z"
    assert release.cves == {}
    assert release.actively_exploited_cves == []
    assert release.unique_cves_count == 0
    assert release.days_since_previous is None


def test_security_release_full() -> None:
    """Test SecurityRelease model with all fields populated."""
    release = SecurityRelease(
        update_name="macOS Sonoma 14.2.1",
        product_version="14.2.1",
        release_date="2023-12-11T18:00:00Z",
        cves={"CVE-2023-42940": False, "CVE-2023-42942": True},
        actively_exploited_cves=["CVE-2023-42942"],
        unique_cves_count=2,
        days_since_previous=30,
    )

    assert len(release.cves) == 2
    assert release.cves["CVE-2023-42942"] is True
    assert "CVE-2023-42942" in release.actively_exploited_cves
    assert release.unique_cves_count == 2
    assert release.days_since_previous == 30


def test_security_release_default_values() -> None:
    """Test SecurityRelease model default values."""
    release = SecurityRelease(
        update_name="Test",
        product_version="1.0",
        release_date="2023-01-01T00:00:00Z",
    )

    assert release.cves == {}
    assert release.actively_exploited_cves == []
    assert release.unique_cves_count == 0
    assert release.days_since_previous is None


def test_os_version_info_minimal() -> None:
    """Test OSVersionInfo model with minimal required fields."""
    os_info = OSVersionInfo(
        os_version="Sequoia 15",
        latest_version="15.1.0",
        latest_build="24A100",
        latest_release_date="2024-01-01T00:00:00Z",
    )

    assert os_info.os_version == "Sequoia 15"
    assert os_info.latest_version == "15.1.0"
    assert os_info.latest_build == "24A100"
    assert os_info.security_releases == []
    assert os_info.all_cves == set()
    assert os_info.actively_exploited_cves == set()


def test_os_version_info_with_releases() -> None:
    """Test OSVersionInfo model with security releases."""
    release = SecurityRelease(
        update_name="macOS 15.1",
        product_version="15.1.0",
        release_date="2024-01-01T00:00:00Z",
        cves={"CVE-2024-0001": True},
        actively_exploited_cves=["CVE-2024-0001"],
        unique_cves_count=1,
    )

    os_info = OSVersionInfo(
        os_version="Sequoia 15",
        latest_version="15.1.0",
        latest_build="24A100",
        latest_release_date="2024-01-01T00:00:00Z",
        security_releases=[release],
        all_cves={"CVE-2024-0001"},
        actively_exploited_cves={"CVE-2024-0001"},
    )

    assert len(os_info.security_releases) == 1
    assert "CVE-2024-0001" in os_info.all_cves
    assert "CVE-2024-0001" in os_info.actively_exploited_cves


def test_os_version_info_multiple_releases() -> None:
    """Test OSVersionInfo model with multiple security releases."""
    releases = [
        SecurityRelease(
            update_name="macOS 15.1.1",
            product_version="15.1.1",
            release_date="2024-02-01T00:00:00Z",
        ),
        SecurityRelease(
            update_name="macOS 15.1.0",
            product_version="15.1.0",
            release_date="2024-01-01T00:00:00Z",
        ),
    ]

    os_info = OSVersionInfo(
        os_version="Sequoia 15",
        latest_version="15.1.1",
        latest_build="24A200",
        latest_release_date="2024-02-01T00:00:00Z",
        security_releases=releases,
    )

    assert len(os_info.security_releases) == 2


def test_sofa_feed_minimal() -> None:
    """Test SOFAFeed model with minimal required fields."""
    feed = SOFAFeed(update_hash="abc123")

    assert feed.update_hash == "abc123"
    assert feed.os_versions == {}
    assert isinstance(feed.last_updated, datetime)


def test_sofa_feed_with_os_versions() -> None:
    """Test SOFAFeed model with OS versions."""
    os_info = OSVersionInfo(
        os_version="Sequoia 15",
        latest_version="15.1.0",
        latest_build="24A100",
        latest_release_date="2024-01-01T00:00:00Z",
    )

    feed = SOFAFeed(
        update_hash="abc123",
        os_versions={"Sequoia 15": os_info},
    )

    assert "Sequoia 15" in feed.os_versions
    assert feed.os_versions["Sequoia 15"].latest_version == "15.1.0"


def test_sofa_feed_last_updated_default() -> None:
    """Test SOFAFeed model sets last_updated to current time by default."""
    before = datetime.now(UTC)
    feed = SOFAFeed(update_hash="abc123")
    after = datetime.now(UTC)

    assert before <= feed.last_updated <= after


def test_sofa_feed_multiple_os_versions() -> None:
    """Test SOFAFeed model with multiple OS versions."""
    os_versions = {
        "Sequoia 15": OSVersionInfo(
            os_version="Sequoia 15",
            latest_version="15.1.0",
            latest_build="24A100",
            latest_release_date="2024-01-01T00:00:00Z",
        ),
        "Sonoma 14": OSVersionInfo(
            os_version="Sonoma 14",
            latest_version="14.2.1",
            latest_build="23C71",
            latest_release_date="2023-12-11T00:00:00Z",
        ),
    }

    feed = SOFAFeed(update_hash="abc123", os_versions=os_versions)

    assert len(feed.os_versions) == 2
    assert "Sequoia 15" in feed.os_versions
    assert "Sonoma 14" in feed.os_versions


def test_sofa_feed_model_dump() -> None:
    """Test SOFAFeed model can be serialized to dict."""
    feed = SOFAFeed(update_hash="abc123")

    dumped = feed.model_dump()

    assert isinstance(dumped, dict)
    assert dumped["update_hash"] == "abc123"
    assert "os_versions" in dumped
    assert "last_updated" in dumped


def test_sofa_feed_model_dump_json() -> None:
    """Test SOFAFeed model can be serialized to JSON-compatible dict."""
    feed = SOFAFeed(update_hash="abc123")

    dumped = feed.model_dump(mode="json")

    assert isinstance(dumped, dict)
    # datetime should be serialized to string in json mode
    assert isinstance(dumped["last_updated"], str)
