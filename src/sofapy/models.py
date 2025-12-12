"""Pydantic models for SOFA feed data structures and client results."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class CVEInfo(BaseModel):
    """
    CVE information with exploitation status.

    :param cve_id: CVE identifier
    :type cve_id: str
    :param actively_exploited: Whether the CVE is actively exploited
    :type actively_exploited: bool
    """

    cve_id: str = Field(..., description="CVE identifier (e.g., CVE-2024-12345)")
    actively_exploited: bool = Field(..., description="Whether CVE is actively exploited")


class SecurityRelease(BaseModel):
    """
    Security release information.

    :param update_name: Name of the security update
    :type update_name: str
    :param product_version: Product version number
    :type product_version: str
    :param release_date: Release date in ISO format
    :type release_date: str
    :param cves: Dictionary of CVE IDs to exploitation status
    :type cves: dict[str, bool]
    :param actively_exploited_cves: List of actively exploited CVE IDs
    :type actively_exploited_cves: list[str]
    :param unique_cves_count: Number of unique CVEs addressed
    :type unique_cves_count: int
    :param days_since_previous: Days since previous release
    :type days_since_previous: int | None
    """

    update_name: str
    product_version: str
    release_date: str
    cves: dict[str, bool] = Field(default_factory=dict)
    actively_exploited_cves: list[str] = Field(default_factory=list)
    unique_cves_count: int = 0
    days_since_previous: int | None = None


class OSVersionInfo(BaseModel):
    """
    Operating system version information.

    :param os_version: OS version name (e.g., "Sequoia 15")
    :type os_version: str
    :param latest_version: Latest available product version
    :type latest_version: str
    :param latest_build: Latest build number
    :type latest_build: str
    :param latest_release_date: Latest release date
    :type latest_release_date: str
    :param security_releases: List of security releases for this OS version
    :type security_releases: list[SecurityRelease]
    :param all_cves: Set of all CVEs affecting this OS version
    :type all_cves: set[str]
    :param actively_exploited_cves: Set of actively exploited CVEs
    :type actively_exploited_cves: set[str]
    """

    os_version: str
    latest_version: str
    latest_build: str
    latest_release_date: str
    security_releases: list[SecurityRelease] = Field(default_factory=list)
    all_cves: set[str] = Field(default_factory=set)
    actively_exploited_cves: set[str] = Field(default_factory=set)


class SOFAFeed(BaseModel):
    """
    Complete SOFA feed data structure.

    :param update_hash: Feed update hash
    :type update_hash: str
    :param os_versions: Dictionary of OS versions to their information
    :type os_versions: dict[str, OSVersionInfo]
    :param last_updated: When the feed was last processed
    :type last_updated: datetime
    """

    update_hash: str
    os_versions: dict[str, OSVersionInfo] = Field(default_factory=dict)
    last_updated: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CVEResult(BaseModel):
    """
    Result from client CVE lookup methods.

    Contains CVE information for a specific macOS version, including
    all CVEs and actively exploited CVEs that affect the version.

    :param version: The macOS version queried
    :type version: str
    :param os_family: The OS family name (e.g., "Sequoia 15")
    :type os_family: str
    :param all_cves: Set of all CVE IDs affecting this version
    :type all_cves: set[str]
    :param actively_exploited_cves: Set of actively exploited CVE IDs
    :type actively_exploited_cves: set[str]
    :param total_count: Total number of CVEs
    :type total_count: int
    :param exploited_count: Number of actively exploited CVEs
    :type exploited_count: int
    """

    version: str = Field(..., description="The macOS version queried")
    os_family: str = Field(..., description="The OS family name (e.g., 'Sequoia 15')")
    all_cves: set[str] = Field(
        default_factory=set, description="All CVE IDs affecting this version"
    )
    actively_exploited_cves: set[str] = Field(
        default_factory=set, description="Actively exploited CVE IDs"
    )
    total_count: int = Field(0, description="Total number of CVEs")
    exploited_count: int = Field(0, description="Number of actively exploited CVEs")

    @property
    def has_exploited_cves(self) -> bool:
        """Check if there are any actively exploited CVEs."""
        return self.exploited_count > 0

    @property
    def is_vulnerable(self) -> bool:
        """Check if the version has any known CVEs."""
        return self.total_count > 0


class CurrencyInfo(BaseModel):
    """
    Result from client currency info methods.

    Contains information about how current a macOS version is compared
    to the latest available version, including a currency score.

    :param is_current: Whether the version is the latest
    :type is_current: bool
    :param current_version: The version being checked
    :type current_version: str
    :param latest_version: The latest available version
    :type latest_version: str
    :param os_family: The OS family name
    :type os_family: str
    :param versions_behind: How many versions behind (weighted)
    :type versions_behind: int
    :param security_updates_missed: Number of security updates missed
    :type security_updates_missed: int
    :param days_behind: Approximate days behind latest
    :type days_behind: int
    :param currency_score: Score from 0-100 (100 = current)
    :type currency_score: int
    :param recommendation: Human-readable recommendation
    :type recommendation: str
    """

    is_current: bool = Field(..., description="Whether the version is the latest")
    current_version: str = Field(..., description="The version being checked")
    latest_version: str = Field(..., description="The latest available version")
    os_family: str = Field(..., description="The OS family name")
    versions_behind: int = Field(0, description="How many versions behind (weighted)")
    security_updates_missed: int = Field(0, description="Number of security updates missed")
    days_behind: int = Field(0, description="Approximate days behind latest")
    currency_score: int = Field(100, description="Score from 0-100 (100 = current)")
    recommendation: str = Field("", description="Human-readable recommendation")

    @property
    def needs_update(self) -> bool:
        """Check if the version needs updating."""
        return not self.is_current

    @property
    def is_critical(self) -> bool:
        """Check if the update is critical (multiple security updates missed)."""
        return self.security_updates_missed >= 3


class LatestInfo(BaseModel):
    """
    Latest version information for an OS family.

    Contains details about the most recent release for a specific
    macOS family (e.g., Sequoia, Sonoma).

    :param os_family: The OS family name (e.g., "Sequoia 15")
    :type os_family: str
    :param latest_version: The latest product version
    :type latest_version: str
    :param latest_build: The latest build number
    :type latest_build: str
    :param release_date: The release date
    :type release_date: str
    :param total_cves: Total CVEs in this OS family
    :type total_cves: int
    :param actively_exploited_count: Number of actively exploited CVEs
    :type actively_exploited_count: int
    """

    os_family: str = Field(..., description="The OS family name (e.g., 'Sequoia 15')")
    latest_version: str = Field(..., description="The latest product version")
    latest_build: str = Field(..., description="The latest build number")
    release_date: str = Field(..., description="The release date")
    total_cves: int = Field(0, description="Total CVEs in this OS family")
    actively_exploited_count: int = Field(0, description="Number of actively exploited CVEs")

    @property
    def has_exploited_cves(self) -> bool:
        """Check if there are any actively exploited CVEs."""
        return self.actively_exploited_count > 0
