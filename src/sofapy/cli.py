"""Command-line interface for sofapy."""

import asyncio
import json
import sys
from typing import Any

import asyncclick as click

from sofapy import __version__
from sofapy.client import AsyncSofaClient
from sofapy.logger import SofaLog

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


def format_err(exc: Exception) -> None:
    """Formats error messages to console."""
    click.echo(click.style(f"❌ Error: {str(exc)}", fg="red", bold=True), err=True)


def output_json(data: Any) -> None:
    """Output data as formatted JSON."""
    click.echo(json.dumps(data, indent=2, default=str))


@click.group(
    context_settings=CONTEXT_SETTINGS, options_metavar="<options>", invoke_without_command=True
)
@click.version_option(version=__version__)
@click.option("--debug", "-x", is_flag=True, help="Enable debug logging (verbose mode).")
@click.option(
    "--logfile",
    "-l",
    type=click.Path(),
    default=None,
    metavar="<PATH>",
    help="Path to log file (optional).",
)
@click.pass_context
async def cli(ctx: click.Context, debug: bool, logfile: str | None) -> None:
    """
    sofapy - A Python wrapper for MacAdmins SOFA.

    Query Apple software update information and security CVEs.
    https://sofa.macadmins.io
    """
    ctx.ensure_object(dict)

    # Initialize logging
    logger = SofaLog(logfile=logfile) if logfile else SofaLog()
    logger.setup_logger(debug=debug)
    sys.excepthook = logger.custom_excepthook

    ctx.obj["logger"] = logger
    ctx.obj["debug"] = debug
    ctx.obj["client"] = AsyncSofaClient()

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command("feed")
@click.option("--raw", "-r", is_flag=True, help="Output raw JSON feed without parsing.")
@click.pass_context
async def feed_cmd(ctx: click.Context, raw: bool) -> None:
    """Fetch and display the SOFA macOS data feed."""
    logger: SofaLog = ctx.obj["logger"]
    client: AsyncSofaClient = ctx.obj["client"]
    logger.debug("Fetching SOFA feed...")

    if raw:
        feed_data = await client.get_feed(raw=True)
        output_json(feed_data)
    else:
        sofa_feed = await client.get_feed()
        output_json(sofa_feed.model_dump(mode="json"))


@cli.command("latest")
@click.option(
    "--os",
    "-o",
    "os_filter",
    default=None,
    metavar="<NAME>",
    help="Filter to specific OS family (e.g., 'Tahoe', 'Sequoia').",
)
@click.option("--json", "-j", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
async def latest_cmd(ctx: click.Context, os_filter: str | None, as_json: bool) -> None:
    """
    Show the latest version info for macOS releases.

    Examples:
        sofapy latest
        sofapy latest --os Tahoe
        sofapy latest -j
    """
    logger: SofaLog = ctx.obj["logger"]
    client: AsyncSofaClient = ctx.obj["client"]
    logger.debug("Fetching latest version info...")

    results = await client.get_latest(os_filter=os_filter)

    if as_json:
        output_json({name: info.model_dump() for name, info in results.items()})
    else:
        for name, info in results.items():
            click.echo(click.style(f"\n{name}", fg="cyan", bold=True))
            click.echo(f"  Latest: {info.latest_version} ({info.latest_build})")
            click.echo(f"  Released: {info.release_date}")
            click.echo(f"  CVEs: {info.total_cves}")
            if info.has_exploited_cves:
                click.echo(
                    click.style(
                        f"  ⚠️  Actively Exploited: {info.actively_exploited_count}",
                        fg="yellow",
                        bold=True,
                    )
                )


@cli.command("cves")
@click.argument("version", metavar="<VERSION>")
@click.option("--json", "-j", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--exploited-only", "-e", is_flag=True, help="Only show actively exploited CVEs.")
@click.pass_context
async def cves_cmd(
    ctx: click.Context,
    version: str,
    as_json: bool,
    exploited_only: bool,
) -> None:
    """
    List CVEs affecting a specific macOS VERSION.

    The OS family is automatically inferred from the version number.

    Examples:
        sofapy cves 15.1.0
        sofapy cves 26.0.0 --json
        sofapy cves 14.5.0 --exploited-only
    """
    logger: SofaLog = ctx.obj["logger"]
    client: AsyncSofaClient = ctx.obj["client"]
    logger.debug(f"Finding CVEs affecting version {version}...")

    try:
        cve_result = await client.get_cves(version, exploited_only=exploited_only)
    except ValueError as e:
        raise click.ClickException(str(e))

    if as_json:
        result_dict = cve_result.model_dump(mode="json")
        # Convert sets to sorted lists for cleaner JSON output
        result_dict["all_cves"] = sorted(cve_result.all_cves)
        result_dict["actively_exploited_cves"] = sorted(cve_result.actively_exploited_cves)
        output_json(result_dict)
    else:
        click.echo(
            click.style(
                f"\n🔒 CVEs affecting {version} ({cve_result.os_family})", fg="cyan", bold=True
            )
        )
        click.echo(f"  Total: {cve_result.total_count}")

        if cve_result.has_exploited_cves:
            click.echo(
                click.style(
                    f"\n  ⚠️  Actively Exploited ({cve_result.exploited_count}):",
                    fg="red",
                    bold=True,
                )
            )
            for cve in sorted(cve_result.actively_exploited_cves):
                click.echo(click.style(f"    • {cve}", fg="red"))

        if not exploited_only and cve_result.all_cves:
            other_cves = cve_result.all_cves - cve_result.actively_exploited_cves
            if other_cves:
                click.echo(f"\n  Other CVEs ({len(other_cves)}):")
                for cve in sorted(other_cves):
                    click.echo(f"    • {cve}")

        if not cve_result.is_vulnerable:
            click.echo(click.style("  ✅ No known CVEs!", fg="green"))


@cli.command("currency")
@click.argument("version", metavar="<VERSION>")
@click.option("--json", "-j", "as_json", is_flag=True, help="Output as JSON.")
@click.pass_context
async def currency_cmd(
    ctx: click.Context,
    version: str,
    as_json: bool,
) -> None:
    """
    Check how current a macOS VERSION is.

    Shows version currency information including a score (0-100) and
    update recommendations.

    Examples:
        sofapy currency 15.1.0
        sofapy currency 14.5.0 --json
    """
    logger: SofaLog = ctx.obj["logger"]
    client: AsyncSofaClient = ctx.obj["client"]
    logger.debug(f"Checking currency for version {version}...")

    try:
        currency_info = await client.get_currency_info(version)
    except ValueError as e:
        raise click.ClickException(str(e))

    if as_json:
        output_json(currency_info.model_dump(mode="json"))
    else:
        click.echo(
            click.style(
                f"\n📊 Currency Info for {version} ({currency_info.os_family})",
                fg="cyan",
                bold=True,
            )
        )

        if currency_info.is_current:
            click.echo(click.style("  ✅ You're up to date!", fg="green", bold=True))
        else:
            click.echo(f"  Latest Version: {currency_info.latest_version}")
            click.echo(f"  Versions Behind: {currency_info.versions_behind}")
            click.echo(f"  Security Updates Missed: {currency_info.security_updates_missed}")
            if currency_info.days_behind > 0:
                click.echo(f"  Days Behind: ~{currency_info.days_behind}")

        # Score display with color coding
        score = currency_info.currency_score
        if score >= 80:
            score_color = "green"
        elif score >= 50:
            score_color = "yellow"
        else:
            score_color = "red"

        click.echo(click.style(f"\n  Currency Score: {score}/100", fg=score_color, bold=True))

        # Recommendation
        rec = currency_info.recommendation
        if "CRITICAL" in rec:
            click.echo(click.style(f"\n  💀 {rec}", fg="red", bold=True))
        elif "HIGH" in rec:
            click.echo(click.style(f"\n  ⚠️  {rec}", fg="yellow", bold=True))
        elif "MEDIUM" in rec:
            click.echo(click.style(f"\n  📋 {rec}", fg="yellow"))
        else:
            click.echo(f"\n  💡 {rec}")


if __name__ == "__main__":
    try:
        asyncio.run(cli())
    except Exception as e:
        format_err(e)
        sys.exit(1)
