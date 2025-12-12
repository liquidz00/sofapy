"""Tests for sofapy.client module - SofaClient and AsyncSofaClient classes."""

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import httpx
import pytest

from sofapy.client import AsyncSofaClient, SofaClient, _SofaClientBase
from sofapy.models import CurrencyInfo, CVEResult, LatestInfo, SOFAFeed

if TYPE_CHECKING:
    pass


def test_base_client_init_defaults() -> None:
    """Test _SofaClientBase initialization with defaults."""
    base = _SofaClientBase()

    assert base.timeout == 30.0
    assert base.base_url == "https://sofafeed.macadmins.io/v1/macos_data_feed.json"
    assert base._cached_feed is None


def test_base_client_init_custom() -> None:
    """Test _SofaClientBase initialization with custom values."""
    base = _SofaClientBase(timeout=60.0, base_url="https://custom.url/feed.json")

    assert base.timeout == 60.0
    assert base.base_url == "https://custom.url/feed.json"


def test_base_client_parse_feed(sofa_feed_response: dict[str, Any]) -> None:
    """Test _SofaClientBase._parse_feed parses feed correctly."""
    base = _SofaClientBase()
    feed = base._parse_feed(sofa_feed_response)

    assert isinstance(feed, SOFAFeed)
    assert feed.update_hash == sofa_feed_response["UpdateHash"]
    assert len(feed.os_versions) > 0


def test_base_client_parse_feed_invalid() -> None:
    """Test _SofaClientBase._parse_feed raises on invalid data."""
    base = _SofaClientBase()

    with pytest.raises(ValueError, match="Failed to parse"):
        base._parse_feed(None)  # type: ignore[arg-type]


def test_base_client_infer_os_family(sofa_feed_response: dict[str, Any]) -> None:
    """Test _SofaClientBase._infer_os_family finds OS family."""
    base = _SofaClientBase()
    feed = base._parse_feed(sofa_feed_response)

    result = base._infer_os_family(feed, "14.2.1")
    assert result is not None


def test_base_client_infer_os_family_not_found(sofa_feed_response: dict[str, Any]) -> None:
    """Test _SofaClientBase._infer_os_family returns None when not found."""
    base = _SofaClientBase()
    feed = base._parse_feed(sofa_feed_response)

    result = base._infer_os_family(feed, "99.0.0")
    assert result is None


def test_base_client_version_is_newer() -> None:
    """Test _SofaClientBase._version_is_newer compares versions."""
    base = _SofaClientBase()

    assert base._version_is_newer([15, 0, 0], [14, 0, 0]) is True
    assert base._version_is_newer([14, 0, 0], [15, 0, 0]) is False
    assert base._version_is_newer([14, 1, 0], [14, 1, 0]) is False


def test_base_client_calculate_version_distance() -> None:
    """Test _SofaClientBase._calculate_version_distance calculates distance."""
    base = _SofaClientBase()

    assert base._calculate_version_distance([14, 0, 0], [14, 0, 0]) == 0
    assert base._calculate_version_distance([15, 0, 0], [14, 0, 0]) == 0  # current newer
    assert base._calculate_version_distance([14, 0, 0], [15, 0, 0]) > 0


def test_base_client_get_currency_recommendation() -> None:
    """Test _SofaClientBase._get_currency_recommendation returns recommendations."""
    base = _SofaClientBase()

    assert "no action" in base._get_currency_recommendation(True, 0, 0).lower()
    assert "CRITICAL" in base._get_currency_recommendation(False, 0, 3)
    assert "HIGH" in base._get_currency_recommendation(False, 3, 0)
    assert "MEDIUM" in base._get_currency_recommendation(False, 1, 1)
    assert "LOW" in base._get_currency_recommendation(False, 1, 0)


# -----------------------------------------------------------------------------
# Tests for SofaClient (Synchronous)
# -----------------------------------------------------------------------------


def test_sofa_client_init() -> None:
    """Test SofaClient initialization."""
    client = SofaClient()

    assert client.timeout == 30.0
    assert isinstance(client, _SofaClientBase)


def test_sofa_client_init_custom_timeout() -> None:
    """Test SofaClient initialization with custom timeout."""
    client = SofaClient(timeout=60.0)

    assert client.timeout == 60.0


def test_sofa_client_get_feed_returns_model(sofa_feed_response: dict[str, Any]) -> None:
    """Test SofaClient.get_feed returns SOFAFeed model by default."""
    client = SofaClient()

    mock_response = MagicMock()
    mock_response.json.return_value = sofa_feed_response
    mock_response.raise_for_status.return_value = None

    with patch("sofapy.client.httpx.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.get.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_instance

        result = client.get_feed()

    assert isinstance(result, SOFAFeed)
    assert result.update_hash == sofa_feed_response["UpdateHash"]


def test_sofa_client_get_feed_raw(sofa_feed_response: dict[str, Any]) -> None:
    """Test SofaClient.get_feed with raw=True returns dict."""
    client = SofaClient()

    mock_response = MagicMock()
    mock_response.json.return_value = sofa_feed_response
    mock_response.raise_for_status.return_value = None

    with patch("sofapy.client.httpx.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.get.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_instance

        result = client.get_feed(raw=True)

    assert isinstance(result, dict)
    assert result["UpdateHash"] == sofa_feed_response["UpdateHash"]


def test_sofa_client_get_feed_http_error() -> None:
    """Test SofaClient.get_feed raises on HTTP error."""
    client = SofaClient()

    with patch("sofapy.client.httpx.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.get.side_effect = httpx.HTTPError("Connection failed")
        mock_client.return_value.__enter__.return_value = mock_instance

        with pytest.raises(httpx.HTTPError):
            client.get_feed()


def test_sofa_client_get_cves(sofa_feed_response: dict[str, Any]) -> None:
    """Test SofaClient.get_cves returns CVEResult."""
    client = SofaClient()

    mock_response = MagicMock()
    mock_response.json.return_value = sofa_feed_response
    mock_response.raise_for_status.return_value = None

    with patch("sofapy.client.httpx.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.get.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_instance

        result = client.get_cves("14.1.0")

    assert isinstance(result, CVEResult)
    assert result.version == "14.1.0"
    assert result.os_family is not None


def test_sofa_client_get_cves_exploited_only(feed_with_critical_cves: dict[str, Any]) -> None:
    """Test SofaClient.get_cves with exploited_only=True."""
    client = SofaClient()

    mock_response = MagicMock()
    mock_response.json.return_value = feed_with_critical_cves
    mock_response.raise_for_status.return_value = None

    with patch("sofapy.client.httpx.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.get.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_instance

        # Use version from the fixture (14.0) with explicit os_family
        result = client.get_cves("14.0", os_family="14.0", exploited_only=True)

    assert isinstance(result, CVEResult)
    # When exploited_only, all_cves should only contain exploited CVEs
    assert result.all_cves == result.actively_exploited_cves


def test_sofa_client_get_cves_explicit_os_family(sofa_feed_response: dict[str, Any]) -> None:
    """Test SofaClient.get_cves with explicit os_family."""
    client = SofaClient()

    mock_response = MagicMock()
    mock_response.json.return_value = sofa_feed_response
    mock_response.raise_for_status.return_value = None

    with patch("sofapy.client.httpx.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.get.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_instance

        result = client.get_cves("14.1.0", os_family="14.2.1")

    assert result.os_family == "14.2.1"


def test_sofa_client_get_cves_unknown_version(sofa_feed_response: dict[str, Any]) -> None:
    """Test SofaClient.get_cves raises for unknown version."""
    client = SofaClient()

    mock_response = MagicMock()
    mock_response.json.return_value = sofa_feed_response
    mock_response.raise_for_status.return_value = None

    with patch("sofapy.client.httpx.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.get.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_instance

        with pytest.raises(ValueError, match="Could not determine OS family"):
            client.get_cves("99.0.0")


def test_sofa_client_get_currency_info(sofa_feed_response: dict[str, Any]) -> None:
    """Test SofaClient.get_currency_info returns CurrencyInfo."""
    client = SofaClient()

    mock_response = MagicMock()
    mock_response.json.return_value = sofa_feed_response
    mock_response.raise_for_status.return_value = None

    with patch("sofapy.client.httpx.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.get.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_instance

        result = client.get_currency_info("14.1.0")

    assert isinstance(result, CurrencyInfo)
    assert result.current_version == "14.1.0"
    assert result.os_family is not None


def test_sofa_client_get_latest(sofa_feed_response: dict[str, Any]) -> None:
    """Test SofaClient.get_latest returns LatestInfo dict."""
    client = SofaClient()

    mock_response = MagicMock()
    mock_response.json.return_value = sofa_feed_response
    mock_response.raise_for_status.return_value = None

    with patch("sofapy.client.httpx.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.get.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_instance

        result = client.get_latest()

    assert isinstance(result, dict)
    assert len(result) > 0
    for name, info in result.items():
        assert isinstance(info, LatestInfo)
        assert info.os_family == name


def test_sofa_client_get_latest_with_filter(sofa_feed_response: dict[str, Any]) -> None:
    """Test SofaClient.get_latest with os_filter."""
    client = SofaClient()

    mock_response = MagicMock()
    mock_response.json.return_value = sofa_feed_response
    mock_response.raise_for_status.return_value = None

    with patch("sofapy.client.httpx.Client") as mock_client:
        mock_instance = MagicMock()
        mock_instance.get.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_instance

        result = client.get_latest(os_filter="14")

    # Should only include OS families containing "14"
    for name in result.keys():
        assert "14" in name


# -----------------------------------------------------------------------------
# Tests for AsyncSofaClient
# -----------------------------------------------------------------------------


def test_async_sofa_client_init() -> None:
    """Test AsyncSofaClient initialization."""
    client = AsyncSofaClient()

    assert client.timeout == 30.0
    assert isinstance(client, _SofaClientBase)


@pytest.mark.asyncio
async def test_async_sofa_client_get_feed(sofa_feed_response: dict[str, Any]) -> None:
    """Test AsyncSofaClient.get_feed returns SOFAFeed model."""
    from unittest.mock import AsyncMock

    client = AsyncSofaClient()

    mock_response = MagicMock()
    mock_response.json.return_value = sofa_feed_response
    mock_response.raise_for_status.return_value = None

    with patch("sofapy.client.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_instance

        result = await client.get_feed()

    assert isinstance(result, SOFAFeed)


@pytest.mark.asyncio
async def test_async_sofa_client_get_feed_raw(sofa_feed_response: dict[str, Any]) -> None:
    """Test AsyncSofaClient.get_feed with raw=True returns dict."""
    from unittest.mock import AsyncMock

    client = AsyncSofaClient()

    mock_response = MagicMock()
    mock_response.json.return_value = sofa_feed_response
    mock_response.raise_for_status.return_value = None

    with patch("sofapy.client.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_instance

        result = await client.get_feed(raw=True)

    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_async_sofa_client_get_feed_http_error() -> None:
    """Test AsyncSofaClient.get_feed raises on HTTP error."""
    from unittest.mock import AsyncMock

    client = AsyncSofaClient()

    with patch("sofapy.client.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.get.side_effect = httpx.HTTPError("Connection failed")
        mock_client.return_value.__aenter__.return_value = mock_instance

        with pytest.raises(httpx.HTTPError):
            await client.get_feed()


@pytest.mark.asyncio
async def test_async_sofa_client_get_cves(sofa_feed_response: dict[str, Any]) -> None:
    """Test AsyncSofaClient.get_cves returns CVEResult."""
    from unittest.mock import AsyncMock

    client = AsyncSofaClient()

    mock_response = MagicMock()
    mock_response.json.return_value = sofa_feed_response
    mock_response.raise_for_status.return_value = None

    with patch("sofapy.client.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_instance

        result = await client.get_cves("14.1.0")

    assert isinstance(result, CVEResult)
    assert result.version == "14.1.0"


@pytest.mark.asyncio
async def test_async_sofa_client_get_currency_info(sofa_feed_response: dict[str, Any]) -> None:
    """Test AsyncSofaClient.get_currency_info returns CurrencyInfo."""
    from unittest.mock import AsyncMock

    client = AsyncSofaClient()

    mock_response = MagicMock()
    mock_response.json.return_value = sofa_feed_response
    mock_response.raise_for_status.return_value = None

    with patch("sofapy.client.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_instance

        result = await client.get_currency_info("14.1.0")

    assert isinstance(result, CurrencyInfo)


@pytest.mark.asyncio
async def test_async_sofa_client_get_latest(sofa_feed_response: dict[str, Any]) -> None:
    """Test AsyncSofaClient.get_latest returns LatestInfo dict."""
    from unittest.mock import AsyncMock

    client = AsyncSofaClient()

    mock_response = MagicMock()
    mock_response.json.return_value = sofa_feed_response
    mock_response.raise_for_status.return_value = None

    with patch("sofapy.client.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_instance

        result = await client.get_latest()

    assert isinstance(result, dict)
    assert len(result) > 0


# -----------------------------------------------------------------------------
# Tests for CVEResult model properties
# -----------------------------------------------------------------------------


def test_cve_result_has_exploited_cves() -> None:
    """Test CVEResult.has_exploited_cves property."""
    result_with = CVEResult(
        version="15.0",
        os_family="Sequoia 15",
        all_cves={"CVE-1", "CVE-2"},
        actively_exploited_cves={"CVE-1"},
        total_count=2,
        exploited_count=1,
    )
    result_without = CVEResult(
        version="15.0",
        os_family="Sequoia 15",
        total_count=0,
        exploited_count=0,
    )

    assert result_with.has_exploited_cves is True
    assert result_without.has_exploited_cves is False


def test_cve_result_is_vulnerable() -> None:
    """Test CVEResult.is_vulnerable property."""
    vulnerable = CVEResult(
        version="15.0",
        os_family="Sequoia 15",
        all_cves={"CVE-1"},
        total_count=1,
        exploited_count=0,
    )
    not_vulnerable = CVEResult(
        version="15.0",
        os_family="Sequoia 15",
        total_count=0,
        exploited_count=0,
    )

    assert vulnerable.is_vulnerable is True
    assert not_vulnerable.is_vulnerable is False


# -----------------------------------------------------------------------------
# Tests for CurrencyInfo model properties
# -----------------------------------------------------------------------------


def test_currency_info_needs_update() -> None:
    """Test CurrencyInfo.needs_update property."""
    current = CurrencyInfo(
        is_current=True,
        current_version="15.1",
        latest_version="15.1",
        os_family="Sequoia 15",
    )
    outdated = CurrencyInfo(
        is_current=False,
        current_version="15.0",
        latest_version="15.1",
        os_family="Sequoia 15",
    )

    assert current.needs_update is False
    assert outdated.needs_update is True


def test_currency_info_is_critical() -> None:
    """Test CurrencyInfo.is_critical property."""
    critical = CurrencyInfo(
        is_current=False,
        current_version="14.0",
        latest_version="15.1",
        os_family="Sequoia 15",
        security_updates_missed=3,
    )
    not_critical = CurrencyInfo(
        is_current=False,
        current_version="15.0",
        latest_version="15.1",
        os_family="Sequoia 15",
        security_updates_missed=1,
    )

    assert critical.is_critical is True
    assert not_critical.is_critical is False


# -----------------------------------------------------------------------------
# Tests for LatestInfo model properties
# -----------------------------------------------------------------------------


def test_latest_info_has_exploited_cves() -> None:
    """Test LatestInfo.has_exploited_cves property."""
    with_exploited = LatestInfo(
        os_family="Sequoia 15",
        latest_version="15.1",
        latest_build="24A100",
        release_date="2024-01-01",
        total_cves=5,
        actively_exploited_count=2,
    )
    without_exploited = LatestInfo(
        os_family="Sequoia 15",
        latest_version="15.1",
        latest_build="24A100",
        release_date="2024-01-01",
        total_cves=5,
        actively_exploited_count=0,
    )

    assert with_exploited.has_exploited_cves is True
    assert without_exploited.has_exploited_cves is False
