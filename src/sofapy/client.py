"""
Synchronous and asynchronous client classes for the SOFA API.

This module provides both sync and async clients for interacting with
the MacAdmins SOFA (Simple Organized Feed for Apple) API.

Example usage:

    # Synchronous
    from sofapy import SofaClient

    client = SofaClient()
    feed = client.get_feed()
    cves = client.get_cves("15.1.1", exploited_only=True)

    # Asynchronous
    from sofapy import AsyncSofaClient

    async_client = AsyncSofaClient()
    feed = await async_client.get_feed()
    cves = await async_client.get_cves("15.1.1")
"""

from __future__ import annotations

import logging
from typing import Any, overload

import httpx
from pydantic import ValidationError

from sofapy.models import (
    CurrencyInfo,
    CVEResult,
    LatestInfo,
    OSVersionInfo,
    SecurityRelease,
    SOFAFeed,
)

logger = logging.getLogger("sofapy")

SOFA_FEED_URL = "https://sofafeed.macadmins.io/v1/macos_data_feed.json"
DEFAULT_TIMEOUT = 30.0


class _SofaClientBase:
    """
    Base class with shared functionality for SOFA clients.

    This class contains all the parsing and business logic shared between
    the synchronous and asynchronous client implementations.
    """

    def __init__(self, timeout: float = DEFAULT_TIMEOUT, base_url: str = SOFA_FEED_URL) -> None:
        """
        Initialize the SOFA client base.

        :param timeout: Request timeout in seconds
        :type timeout: float
        :param base_url: Base URL for the SOFA feed API
        :type base_url: str
        """
        self.timeout = timeout
        self.base_url = base_url
        self._cached_feed: SOFAFeed | None = None

    def _parse_feed(self, feed_data: dict[str, Any]) -> SOFAFeed:
        """
        Parse raw SOFA feed data into structured models.

        :param feed_data: Raw SOFA feed data from API
        :type feed_data: dict[str, Any]
        :return: Parsed and structured SOFA feed
        :rtype: SOFAFeed
        :raises ValueError: If feed data is invalid or missing required fields
        """
        try:
            update_hash = feed_data.get("UpdateHash", "")
            os_versions_data = feed_data.get("OSVersions", [])

            os_versions = {}

            for os_data in os_versions_data:
                os_version_name = os_data.get("OSVersion", "")
                if not os_version_name:
                    continue

                # Parse latest version info
                latest = os_data.get("Latest", {})
                latest_version = latest.get("ProductVersion", "")
                latest_build = latest.get("Build", "")
                latest_release_date = latest.get("ReleaseDate", "")

                security_releases = []
                all_cves: set[str] = set()
                actively_exploited_cves: set[str] = set()

                for release_data in os_data.get("SecurityReleases", []):
                    release = SecurityRelease(
                        update_name=release_data.get("UpdateName", ""),
                        product_version=release_data.get("ProductVersion", ""),
                        release_date=release_data.get("ReleaseDate", ""),
                        cves=release_data.get("CVEs", {}),
                        actively_exploited_cves=release_data.get("ActivelyExploitedCVEs", []),
                        unique_cves_count=release_data.get("UniqueCVEsCount", 0),
                        days_since_previous=release_data.get("DaysSincePreviousRelease"),
                    )
                    security_releases.append(release)

                    all_cves.update(release.cves.keys())
                    actively_exploited_cves.update(release.actively_exploited_cves)

                os_version_info = OSVersionInfo(
                    os_version=os_version_name,
                    latest_version=latest_version,
                    latest_build=latest_build,
                    latest_release_date=latest_release_date,
                    security_releases=security_releases,
                    all_cves=all_cves,
                    actively_exploited_cves=actively_exploited_cves,
                )

                os_versions[os_version_name] = os_version_info

            return SOFAFeed(update_hash=update_hash, os_versions=os_versions)
        except (ValidationError, ValueError, KeyError, AttributeError) as e:
            logger.error(f"Error parsing SOFA feed: {str(e)}")
            raise ValueError(f"Failed to parse SOFA feed: {str(e)}") from e

    def _infer_os_family(self, feed: SOFAFeed, version: str) -> str | None:
        """
        Infer the OS family from a version number by checking SOFA feed.

        :param feed: Parsed SOFA feed
        :type feed: SOFAFeed
        :param version: Version string (e.g., "15.1.0", "26.0.0")
        :type version: str
        :return: OS family name or None if not found
        :rtype: str | None
        """
        major = version.split(".")[0]
        for os_name, os_info in feed.os_versions.items():
            for release in os_info.security_releases:
                if release.product_version.startswith(f"{major}."):
                    return os_name
            if os_info.latest_version.startswith(f"{major}."):
                return os_name
        return None

    def _version_is_newer(self, version_a: list[int], version_b: list[int]) -> bool:
        """
        Compare two version number lists to determine if A is newer than B.

        :param version_a: Version A as list of integers
        :type version_a: list[int]
        :param version_b: Version B as list of integers
        :type version_b: list[int]
        :return: True if version A is newer than version B
        :rtype: bool
        """
        max_len = max(len(version_a), len(version_b))
        a_padded = version_a + [0] * (max_len - len(version_a))
        b_padded = version_b + [0] * (max_len - len(version_b))
        return a_padded > b_padded

    def _calculate_version_distance(self, current: list[int], latest: list[int]) -> int:
        """
        Calculate the 'distance' between two versions.

        :param current: Current version as list of integers
        :type current: list[int]
        :param latest: Latest version as list of integers
        :type latest: list[int]
        :return: Version distance (higher = further behind)
        :rtype: int
        """
        if not self._version_is_newer(latest, current):
            return 0

        max_len = max(len(current), len(latest))
        current_padded = current + [0] * (max_len - len(current))
        latest_padded = latest + [0] * (max_len - len(latest))

        distance = 0
        for i, (current_part, latest_part) in enumerate(
            zip(current_padded, latest_padded, strict=False)
        ):
            if latest_part > current_part:
                weight = max_len - i
                distance += (latest_part - current_part) * weight

        return distance

    def _get_currency_recommendation(
        self, is_current: bool, versions_behind: int, updates_missed: int
    ) -> str:
        """
        Get a human-readable recommendation based on version currency.

        :param is_current: Whether the version is current
        :type is_current: bool
        :param versions_behind: How many versions behind
        :type versions_behind: int
        :param updates_missed: How many security updates missed
        :type updates_missed: int
        :return: Recommendation string
        :rtype: str
        """
        if is_current:
            return "OS is current - no action needed"
        elif updates_missed >= 3:
            return "CRITICAL: Multiple security updates missed - update immediately"
        elif versions_behind >= 3:
            return "HIGH: Multiple versions behind - schedule update soon"
        elif updates_missed >= 1:
            return "MEDIUM: Security updates available - update when convenient"
        else:
            return "LOW: Minor version update available"

    def _compute_cves_for_version(
        self, feed: SOFAFeed, version: str, os_family: str
    ) -> tuple[set[str], set[str]]:
        """
        Compute CVEs that affect a specific OS version.

        :param feed: Parsed SOFA feed data
        :type feed: SOFAFeed
        :param version: Current OS version (e.g., "15.1.0")
        :type version: str
        :param os_family: OS family to check (e.g., "Sequoia 15")
        :type os_family: str
        :return: Tuple of (all_affecting_cves, actively_exploited_cves)
        :rtype: tuple[set[str], set[str]]
        :raises ValueError: If OS family not found in feed
        """
        if os_family not in feed.os_versions:
            raise ValueError(f"OS family '{os_family}' not found in SOFA feed")

        os_info = feed.os_versions[os_family]
        affecting_cves: set[str] = set()
        exploited_cves: set[str] = set()

        try:
            current_parts = [int(x) for x in version.split(".")]

            for release in os_info.security_releases:
                try:
                    release_parts = [int(x) for x in release.product_version.split(".")]

                    if self._version_is_newer(release_parts, current_parts):
                        affecting_cves.update(release.cves.keys())
                        exploited_cves.update(release.actively_exploited_cves)

                except (ValueError, AttributeError):
                    continue

        except (ValueError, AttributeError):
            logger.warning(f"Failed to parse current version: {version}")
            affecting_cves = os_info.all_cves
            exploited_cves = os_info.actively_exploited_cves

        return affecting_cves, exploited_cves

    def _compute_currency_info(self, feed: SOFAFeed, version: str, os_family: str) -> CurrencyInfo:
        """
        Compute currency information for a version.

        :param feed: Parsed SOFA feed data
        :type feed: SOFAFeed
        :param version: Current OS version (e.g., "15.1.0")
        :type version: str
        :param os_family: OS family to check (e.g., "Sequoia 15")
        :type os_family: str
        :return: Currency information
        :rtype: CurrencyInfo
        :raises ValueError: If OS family not found in feed
        """
        if os_family not in feed.os_versions:
            raise ValueError(f"OS family '{os_family}' not found in SOFA feed")

        os_info = feed.os_versions[os_family]
        latest_version = os_info.latest_version

        is_current = version == latest_version
        versions_behind = 0
        security_updates_missed = 0
        days_behind = 0

        try:
            current_parts = [int(x) for x in version.split(".")]
            latest_parts = [int(x) for x in latest_version.split(".")]

            for release in os_info.security_releases:
                try:
                    release_parts = [int(x) for x in release.product_version.split(".")]

                    if self._version_is_newer(
                        release_parts, current_parts
                    ) and not self._version_is_newer(release_parts, latest_parts):
                        security_updates_missed += 1
                        if release.days_since_previous:
                            days_behind += release.days_since_previous

                except (ValueError, AttributeError):
                    continue

            versions_behind = self._calculate_version_distance(current_parts, latest_parts)

        except (ValueError, AttributeError):
            logger.warning("Failed to parse versions for currency calculation")

        # Calculate scoring (0-100, 100 is current)
        currency_score = 100
        if not is_current:
            currency_score -= min(versions_behind * 10, 50)
            currency_score -= min(security_updates_missed * 5, 30)
            currency_score -= min(days_behind // 30, 20)

        return CurrencyInfo(
            is_current=is_current,
            current_version=version,
            latest_version=latest_version,
            os_family=os_family,
            versions_behind=versions_behind,
            security_updates_missed=security_updates_missed,
            days_behind=days_behind,
            currency_score=max(0, currency_score),
            recommendation=self._get_currency_recommendation(
                is_current, versions_behind, security_updates_missed
            ),
        )


class AsyncSofaClient(_SofaClientBase):
    """
    Asynchronous client for the SOFA API.

    This client uses httpx.AsyncClient for non-blocking HTTP requests.
    All methods that fetch data are async and must be awaited.

    Example:
        async_client = AsyncSofaClient()
        feed = await async_client.get_feed()
        cves = await async_client.get_cves("15.1.1", exploited_only=True)

    :param timeout: Request timeout in seconds (default: 30.0)
    :type timeout: float
    :param base_url: Base URL for the SOFA feed API
    :type base_url: str
    """

    @overload
    async def get_feed(self, *, raw: bool = False) -> SOFAFeed: ...

    @overload
    async def get_feed(self, *, raw: bool = True) -> dict[str, Any]: ...

    async def get_feed(self, *, raw: bool = False) -> SOFAFeed | dict[str, Any]:
        """
        Fetch the SOFA macOS data feed.

        :param raw: If True, return raw JSON dict; if False, return SOFAFeed model
        :type raw: bool
        :return: SOFA feed data (parsed model or raw dict)
        :rtype: SOFAFeed | dict[str, Any]
        :raises httpx.HTTPError: If there's an error fetching the feed
        :raises ValueError: If the response is not valid JSON
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.base_url, headers={"accept": "application/json"})
                response.raise_for_status()
                data = response.json()
                logger.info(
                    "Successfully retrieved SOFA feed with %d OS versions",
                    len(data.get("OSVersions", [])),
                )

                if raw:
                    return data

                feed = self._parse_feed(data)
                self._cached_feed = feed
                return feed

        except httpx.HTTPError as e:
            logger.error(f"Failed to retrieve SOFA feed: {str(e)}")
            raise
        except (ValueError, TypeError, KeyError) as e:
            logger.error(f"Unexpected error retrieving SOFA feed: {str(e)}")
            raise ValueError(f"Failed to parse SOFA feed response: {str(e)}") from e

    async def get_cves(
        self,
        version: str,
        *,
        os_family: str | None = None,
        exploited_only: bool = False,
    ) -> CVEResult:
        """
        Get CVEs affecting a specific macOS version.

        If os_family is not provided, it will be automatically inferred
        from the version number.

        :param version: macOS version (e.g., "15.1.1", "14.5.0")
        :type version: str
        :param os_family: OS family name (e.g., "Sequoia 15"), auto-inferred if None
        :type os_family: str | None
        :param exploited_only: If True, only include actively exploited CVEs
        :type exploited_only: bool
        :return: CVE result with all CVEs and actively exploited CVEs
        :rtype: CVEResult
        :raises ValueError: If OS family cannot be determined or not found
        """
        feed = await self.get_feed()

        if os_family is None:
            os_family = self._infer_os_family(feed, version)
            if os_family is None:
                raise ValueError(
                    f"Could not determine OS family for version {version}. "
                    "Please specify os_family explicitly."
                )

        all_cves, exploited_cves = self._compute_cves_for_version(feed, version, os_family)

        if exploited_only:
            all_cves = exploited_cves

        return CVEResult(
            version=version,
            os_family=os_family,
            all_cves=all_cves,
            actively_exploited_cves=exploited_cves,
            total_count=len(all_cves),
            exploited_count=len(exploited_cves),
        )

    async def get_currency_info(
        self,
        version: str,
        *,
        os_family: str | None = None,
    ) -> CurrencyInfo:
        """
        Get currency information for a specific macOS version.

        Determines how current/behind an OS version is compared to the latest,
        including a currency score and update recommendation.

        If os_family is not provided, it will be automatically inferred
        from the version number.

        :param version: macOS version (e.g., "15.1.1", "14.5.0")
        :type version: str
        :param os_family: OS family name (e.g., "Sequoia 15"), auto-inferred if None
        :type os_family: str | None
        :return: Currency information with score and recommendation
        :rtype: CurrencyInfo
        :raises ValueError: If OS family cannot be determined or not found
        """
        feed = await self.get_feed()

        if os_family is None:
            os_family = self._infer_os_family(feed, version)
            if os_family is None:
                raise ValueError(
                    f"Could not determine OS family for version {version}. "
                    "Please specify os_family explicitly."
                )

        return self._compute_currency_info(feed, version, os_family)

    async def get_latest(
        self,
        *,
        os_filter: str | None = None,
    ) -> dict[str, LatestInfo]:
        """
        Get the latest version information for macOS releases.

        :param os_filter: Filter to specific OS family (case-insensitive substring match)
        :type os_filter: str | None
        :return: Dictionary mapping OS family names to their latest info
        :rtype: dict[str, LatestInfo]
        """
        feed = await self.get_feed()

        results: dict[str, LatestInfo] = {}
        for name, os_info in feed.os_versions.items():
            if os_filter and os_filter.lower() not in name.lower():
                continue

            results[name] = LatestInfo(
                os_family=name,
                latest_version=os_info.latest_version,
                latest_build=os_info.latest_build,
                release_date=os_info.latest_release_date,
                total_cves=len(os_info.all_cves),
                actively_exploited_count=len(os_info.actively_exploited_cves),
            )

        return results


class SofaClient(_SofaClientBase):
    """
    Synchronous client for the SOFA API.

    This client uses httpx.Client for blocking HTTP requests.
    All methods are synchronous and return directly.

    Example:
        client = SofaClient()
        feed = client.get_feed()
        cves = client.get_cves("15.1.1", exploited_only=True)

    :param timeout: Request timeout in seconds (default: 30.0)
    :type timeout: float
    :param base_url: Base URL for the SOFA feed API
    :type base_url: str
    """

    @overload
    def get_feed(self, *, raw: bool = False) -> SOFAFeed: ...

    @overload
    def get_feed(self, *, raw: bool = True) -> dict[str, Any]: ...

    def get_feed(self, *, raw: bool = False) -> SOFAFeed | dict[str, Any]:
        """
        Fetch the SOFA macOS data feed.

        :param raw: If True, return raw JSON dict; if False, return SOFAFeed model
        :type raw: bool
        :return: SOFA feed data (parsed model or raw dict)
        :rtype: SOFAFeed | dict[str, Any]
        :raises httpx.HTTPError: If there's an error fetching the feed
        :raises ValueError: If the response is not valid JSON
        """
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(self.base_url, headers={"accept": "application/json"})
                response.raise_for_status()
                data = response.json()
                logger.info(
                    "Successfully retrieved SOFA feed with %d OS versions",
                    len(data.get("OSVersions", [])),
                )

                if raw:
                    return data

                feed = self._parse_feed(data)
                self._cached_feed = feed
                return feed

        except httpx.HTTPError as e:
            logger.error(f"Failed to retrieve SOFA feed: {str(e)}")
            raise
        except (ValueError, TypeError, KeyError) as e:
            logger.error(f"Unexpected error retrieving SOFA feed: {str(e)}")
            raise ValueError(f"Failed to parse SOFA feed response: {str(e)}") from e

    def get_cves(
        self,
        version: str,
        *,
        os_family: str | None = None,
        exploited_only: bool = False,
    ) -> CVEResult:
        """
        Get CVEs affecting a specific macOS version.

        If os_family is not provided, it will be automatically inferred
        from the version number.

        :param version: macOS version (e.g., "15.1.1", "14.5.0")
        :type version: str
        :param os_family: OS family name (e.g., "Sequoia 15"), auto-inferred if None
        :type os_family: str | None
        :param exploited_only: If True, only include actively exploited CVEs
        :type exploited_only: bool
        :return: CVE result with all CVEs and actively exploited CVEs
        :rtype: CVEResult
        :raises ValueError: If OS family cannot be determined or not found
        """
        feed = self.get_feed()

        if os_family is None:
            os_family = self._infer_os_family(feed, version)
            if os_family is None:
                raise ValueError(
                    f"Could not determine OS family for version {version}. "
                    "Please specify os_family explicitly."
                )

        all_cves, exploited_cves = self._compute_cves_for_version(feed, version, os_family)

        if exploited_only:
            all_cves = exploited_cves

        return CVEResult(
            version=version,
            os_family=os_family,
            all_cves=all_cves,
            actively_exploited_cves=exploited_cves,
            total_count=len(all_cves),
            exploited_count=len(exploited_cves),
        )

    def get_currency_info(
        self,
        version: str,
        *,
        os_family: str | None = None,
    ) -> CurrencyInfo:
        """
        Get currency information for a specific macOS version.

        Determines how current/behind an OS version is compared to the latest,
        including a currency score and update recommendation.

        If os_family is not provided, it will be automatically inferred
        from the version number.

        :param version: macOS version (e.g., "15.1.1", "14.5.0")
        :type version: str
        :param os_family: OS family name (e.g., "Sequoia 15"), auto-inferred if None
        :type os_family: str | None
        :return: Currency information with score and recommendation
        :rtype: CurrencyInfo
        :raises ValueError: If OS family cannot be determined or not found
        """
        feed = self.get_feed()

        if os_family is None:
            os_family = self._infer_os_family(feed, version)
            if os_family is None:
                raise ValueError(
                    f"Could not determine OS family for version {version}. "
                    "Please specify os_family explicitly."
                )

        return self._compute_currency_info(feed, version, os_family)

    def get_latest(
        self,
        *,
        os_filter: str | None = None,
    ) -> dict[str, LatestInfo]:
        """
        Get the latest version information for macOS releases.

        :param os_filter: Filter to specific OS family (case-insensitive substring match)
        :type os_filter: str | None
        :return: Dictionary mapping OS family names to their latest info
        :rtype: dict[str, LatestInfo]
        """
        feed = self.get_feed()

        results: dict[str, LatestInfo] = {}
        for name, os_info in feed.os_versions.items():
            if os_filter and os_filter.lower() not in name.lower():
                continue

            results[name] = LatestInfo(
                os_family=name,
                latest_version=os_info.latest_version,
                latest_build=os_info.latest_build,
                release_date=os_info.latest_release_date,
                total_cves=len(os_info.all_cves),
                actively_exploited_count=len(os_info.actively_exploited_cves),
            )

        return results
