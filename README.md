# SOFApy

![](https://img.shields.io/badge/Python-3.12+-3776AB.svg?style=flat&logo=python&logoColor=white)&nbsp;![](https://img.shields.io/github/v/release/liquidz00/sofapy?color=orange)&nbsp;![](https://github.com/liquidz00/sofapy/actions/workflows/run-tests.yml/badge.svg)&nbsp;![](https://img.shields.io/pypi/v/sofapy?color=yellow)&nbsp;![](https://img.shields.io/badge/macOS-10.13%2B-blueviolet?logo=apple&logoSize=auto)

A Python client library for the [MacAdmins SOFA](https://sofa.macadmins.io) (Simple Organized Feed for Apple) API.

Query Apple macOS software update information, security releases, and CVE data with both synchronous and asynchronous clients.

## Installation

**Using uv (recommended):**

```bash
uv add sofapy
```

**Using pip:**

```bash
pip install sofapy
```

## Quick Start

### Synchronous Client

```python
from sofapy import SofaClient

client = SofaClient()

# Get the full SOFA feed
feed = client.get_feed()
print(f"Feed updated: {feed.update_hash}")

# Get CVEs affecting a specific macOS version
cves = client.get_cves("15.1.0")
print(f"Total CVEs: {cves.total_count}")
print(f"Actively exploited: {cves.exploited_count}")

# Only get actively exploited CVEs
exploited = client.get_cves("15.1.0", exploited_only=True)
for cve in exploited.actively_exploited_cves:
    print(f"  ⚠️  {cve}")

# Check how current a version is
currency = client.get_currency_info("15.0.0")
print(f"Score: {currency.currency_score}/100")
print(f"Recommendation: {currency.recommendation}")

# Get latest versions for all OS families
latest = client.get_latest()
for name, info in latest.items():
    print(f"{name}: {info.latest_version}")

# Filter to specific OS family
sequoia = client.get_latest(os_filter="Sequoia")
```

### Asynchronous Client

```python
import asyncio
from sofapy import AsyncSofaClient

async def main():
    client = AsyncSofaClient()

    # Same API, just await the calls
    feed = await client.get_feed()
    cves = await client.get_cves("15.1.0", exploited_only=True)
    currency = await client.get_currency_info("15.0.0")
    latest = await client.get_latest()

    print(f"Latest Sequoia: {latest.get('Sequoia 15').latest_version}")

asyncio.run(main())
```

### Raw JSON Access

```python
from sofapy import SofaClient

client = SofaClient()

# Get raw JSON dict instead of parsed models
raw_feed = client.get_feed(raw=True)
print(raw_feed["UpdateHash"])
```

## Command Line Interface

sofapy includes a CLI for quick queries:

```bash
# Show latest versions for all macOS releases
sofapy latest

# Filter to specific OS family
sofapy latest --os Sequoia

# Output as JSON
sofapy latest --json

# Get CVEs affecting a version
sofapy cves 15.1.0

# Only show actively exploited CVEs
sofapy cves 15.1.0 --exploited-only

# Check version currency
sofapy currency 15.0.0

# Get the full feed (parsed)
sofapy feed

# Get raw JSON feed
sofapy feed --raw

# Enable debug logging
sofapy --debug latest

# Show help
sofapy --help
```

## Models

sofapy returns strongly-typed Pydantic models:

| Model | Description |
|-------|-------------|
| `SOFAFeed` | Complete feed with all OS versions |
| `OSVersionInfo` | Info for a specific OS family |
| `SecurityRelease` | Individual security release details |
| `CVEResult` | Result from `get_cves()` |
| `CurrencyInfo` | Result from `get_currency_info()` |
| `LatestInfo` | Result from `get_latest()` |

### Helpful Properties

```python
# CVEResult
cves.has_exploited_cves  # bool - any actively exploited?
cves.is_vulnerable       # bool - any CVEs at all?

# CurrencyInfo
currency.needs_update    # bool - not on latest?
currency.is_critical     # bool - 3+ security updates missed?

# LatestInfo
latest.has_exploited_cves  # bool - any actively exploited?
```

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please [open an issue](https://github.com/liquidz00/sofapy/issues) on GitHub.

To contribute code:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `uv run pytest`
5. Submit a pull request

## Acknowledgments

This library is a wrapper for the excellent [SOFA](https://sofa.macadmins.io) project by [MacAdmins](https://macadmins.io).

- **SOFA Website:** https://sofa.macadmins.io
- **SOFA Documentation:** https://sofa.macadmins.io/docs
- **SOFA GitHub:** https://github.com/macadmins/sofa

SOFA provides comprehensive, up-to-date information about macOS security releases and CVEs. All data served by sofapy comes from the official SOFA feed.

## License

Apache 2.0 License - see [LICENSE](LICENSE) for details.
