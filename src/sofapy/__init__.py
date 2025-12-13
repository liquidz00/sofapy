"""
sofapy - A Python client library for the MacAdmins SOFA API.

This library provides both synchronous and asynchronous clients for
interacting with the SOFA (Simple Organized Feed for Apple) API to
query Apple software update information and security CVEs.

Example usage:

    # Synchronous client
    from sofapy import SofaClient

    client = SofaClient()
    feed = client.get_feed()
    cves = client.get_cves("15.1.1", exploited_only=True)
    currency = client.get_currency_info("15.1.1")
    latest = client.get_latest(os_filter="Sequoia")

    # Asynchronous client
    from sofapy import AsyncSofaClient

    async_client = AsyncSofaClient()
    feed = await async_client.get_feed()
    cves = await async_client.get_cves("15.1.1")

    # Raw JSON access
    client = SofaClient()
    raw_feed = client.get_feed(raw=True)  # Returns dict instead of SOFAFeed

For more information, see: https://sofa.macadmins.io
"""

from sofapy.client import SOFA_FEED_URL, AsyncSofaClient, SofaClient
from sofapy.models import (
    CurrencyInfo,
    CVEInfo,
    CVEResult,
    LatestInfo,
    OSVersionInfo,
    SecurityRelease,
    SOFAFeed,
)

__title__ = "sofapy"
__version__ = "0.1.1"
__all__ = [
    # Client classes (primary API)
    "SofaClient",
    "AsyncSofaClient",
    # Constants
    "SOFA_FEED_URL",
    # Result models
    "CVEResult",
    "CurrencyInfo",
    "LatestInfo",
    # Core models
    "SOFAFeed",
    "OSVersionInfo",
    "SecurityRelease",
    "CVEInfo",
]
