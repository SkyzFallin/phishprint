"""phishprint CLI."""
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from phishprint import __version__
from phishprint.core.resolver import DoHResolver, SystemResolver
from phishprint.output.json_writer import to_json
from phishprint.output.markdown_writer import to_markdown
from phishprint.scan import scan


def _version_cb(value: bool):
    if value:
        typer.echo(f"phishprint {__version__}")
        raise typer.Exit()


def main(
    domain: str = typer.Argument(..., help="Target domain (e.g. example.com)"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write Markdown report to path"),
    json_path: Path | None = typer.Option(None, "--json", help="Write JSON to path (in addition to stdout)"),
    score_only: bool = typer.Option(False, "--score", help="Output only the readiness score (0-100)"),
    selectors: Path | None = typer.Option(None, "--selectors", help="Custom DKIM selector wordlist"),
    resolver_ip: str | None = typer.Option(None, "--resolver", help="Use specific DNS resolver IP"),
    doh: bool = typer.Option(False, "--doh", help="Use DNS-over-HTTPS (Cloudflare 1.1.1.1)"),
    timeout: float = typer.Option(5.0, "--timeout", help="Per-query timeout (seconds)"),
    no_asn: bool = typer.Option(False, "--no-asn", help="Skip ASN enrichment of MX IPs"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show DNS query trace"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI color"),
    _version: bool = typer.Option(False, "--version", callback=_version_cb, is_eager=True, help="Show version"),
) -> None:
    """phishprint — pre-engagement email security recon. Authorized use only."""
    console = Console(no_color=no_color, soft_wrap=False, highlight=False)

    sels = None
    if selectors is not None:
        sels = [
            line.strip()
            for line in selectors.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]

    if doh:
        resolver = DoHResolver(timeout=timeout)
    else:
        ns = [resolver_ip] if resolver_ip else None
        resolver = SystemResolver(nameservers=ns, timeout=timeout)

    if verbose:
        console.print(f"[dim]resolver={'doh' if doh else (resolver_ip or 'system')}, timeout={timeout}s[/dim]")

    report = scan(domain, resolver, selectors=sels, do_asn=not no_asn)

    if score_only:
        typer.echo(str(report.score.total))
        return

    json_text = to_json(report)

    if output:
        output.write_text(to_markdown(report), encoding="utf-8")
        console.print(f"[green]wrote[/green] {output}")
    if json_path:
        json_path.write_text(json_text, encoding="utf-8")
        console.print(f"[green]wrote[/green] {json_path}")

    if not output and not json_path:
        typer.echo(json_text)
        return

    _render_summary(console, report)


def _render_summary(console: Console, report) -> None:
    band_color = {
        "Hardened": "red",
        "Moderate": "yellow",
        "Permissive": "green",
        "Open": "bright_green",
    }.get(report.score.band, "white")

    head = Text()
    head.append(f"{report.domain}\n", style="bold")
    head.append(f"score {report.score.total}/100  ", style="bold")
    head.append(f"[{report.score.band}]", style=f"bold {band_color}")
    console.print(Panel(head, title="phishprint", border_style="blue"))

    if report.vendors:
        t = Table(title="Vendors", show_header=True, header_style="bold")
        t.add_column("name")
        t.add_column("category")
        t.add_column("inspection")
        t.add_column("conf.")
        for v in report.vendors:
            t.add_row(v.name, v.category, v.inspection, v.confidence)
        console.print(t)

    if report.findings:
        t = Table(title="Findings", show_header=True, header_style="bold")
        t.add_column("sev")
        t.add_column("title")
        for f in report.findings:
            color = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}.get(
                f.severity, "white"
            )
            t.add_row(f"[{color}]{f.severity}[/{color}]", f.title)
        console.print(t)


# Build a Typer app with `main` as the sole command callback. Using
# typer.run() at call time would also work for the CLI, but exposing a
# stable app object here makes CliRunner (and future programmatic use)
# straightforward.
_typer_app = typer.Typer(add_completion=False, rich_markup_mode=None)
_typer_app.command()(main)


def app() -> None:
    """Console-script entry point."""
    _typer_app()


if __name__ == "__main__":
    app()
