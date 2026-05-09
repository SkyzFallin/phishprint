"""phishprint CLI."""
from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from phishprint import __version__
from phishprint.core.resolver import DoHResolver, SystemResolver
from phishprint.output.json_writer import to_json
from phishprint.output.markdown_writer import to_markdown
from phishprint.scan import Report
from phishprint.scan import scan

_BAND_COLOR = {
    "Hardened": "bright_red",
    "Moderate": "yellow",
    "Permissive": "green",
    "Open": "bright_green",
}
_SEV_COLOR = {
    "critical": "bright_red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _version_cb(value: bool):
    if value:
        typer.echo(f"phishprint {__version__}")
        raise typer.Exit()


def main(
    domain: str = typer.Argument(..., help="Target domain (e.g. example.com)"),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write Markdown report to file"
    ),
    json_out: bool = typer.Option(
        False, "--json", help="Force JSON to stdout (default if stdout is piped)"
    ),
    json_file: Path | None = typer.Option(
        None, "--json-file", help="Also write JSON to a file"
    ),
    out_dir: Path = typer.Option(
        Path("./output"), "--out-dir", "-d",
        help="Dump <domain>.txt, <domain>.json, <domain>.md into this directory",
    ),
    no_save: bool = typer.Option(
        False, "--no-save", help="Do not write any files (overrides --out-dir)"
    ),
    score_only: bool = typer.Option(
        False, "--score", help="Print only the readiness score (0-100)"
    ),
    selectors: Path | None = typer.Option(
        None, "--selectors", help="Custom DKIM selector wordlist"
    ),
    resolver_ip: str | None = typer.Option(
        None, "--resolver", help="Use a specific DNS resolver IP"
    ),
    doh: bool = typer.Option(False, "--doh", help="Use DNS-over-HTTPS (Cloudflare 1.1.1.1)"),
    timeout: float = typer.Option(5.0, "--timeout", help="Per-query timeout (seconds)"),
    no_asn: bool = typer.Option(False, "--no-asn", help="Skip ASN enrichment of MX IPs"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show resolver setup line"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI color"),
    _version: bool = typer.Option(
        False, "--version", callback=_version_cb, is_eager=True, help="Show version and exit"
    ),
) -> None:
    """phishprint — pre-engagement email security recon. Authorized use only."""
    err = Console(stderr=True, no_color=no_color, highlight=False)

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
        err.print(
            f"[dim]resolver={'doh' if doh else (resolver_ip or 'system')} "
            f"timeout={timeout}s asn={'off' if no_asn else 'on'}[/dim]"
        )

    report = scan(domain, resolver, selectors=sels, do_asn=not no_asn)

    # Side-channel writes (don't influence stdout decision). Skip all file
    # writes when --score (pipeline use) or --no-save (explicit opt-out).
    if not score_only and not no_save:
        if output:
            output.write_text(to_markdown(report), encoding="utf-8")
            err.print(f"[green]wrote[/green] {output}")
        if json_file:
            json_file.write_text(to_json(report), encoding="utf-8")
            err.print(f"[green]wrote[/green] {json_file}")
        for path in _dump_to_dir(out_dir, report):
            err.print(f"[green]wrote[/green] {path}")

    # Stdout decision tree.
    if score_only:
        typer.echo(str(report.score.total))
        return

    stdout_is_tty = sys.stdout.isatty()
    want_json = json_out or not stdout_is_tty

    if want_json:
        typer.echo(to_json(report))
        return

    out = Console(no_color=no_color, highlight=False, soft_wrap=False)
    _render_summary(out, report)


# ---------------------------------------------------------------------------
# Pretty summary
# ---------------------------------------------------------------------------

def _render_summary(console: Console, report: Report) -> None:
    console.print(_header(report))
    console.print()
    console.print(_mx_section(report))
    console.print()
    console.print(_spf_section(report))
    console.print()
    console.print(_dmarc_section(report))
    console.print()
    console.print(_dkim_section(report))
    console.print()
    console.print(_aux_section(report))
    console.print()
    if report.vendors:
        console.print(_vendors_section(report))
        console.print()
    console.print(_findings_section(report))
    console.print()
    console.print(_recs_section(report))
    console.print()
    console.print(
        Text(
            "Authorized use only. phishprint performs passive DNS recon; "
            "operators are responsible for engagement scope.",
            style="dim italic",
        )
    )


def _header(report: Report) -> Panel:
    band = report.score.band
    color = _BAND_COLOR.get(band, "white")
    title = Text()
    title.append(report.domain, style="bold white")
    title.append("\n")
    title.append(f"score {report.score.total}/100   ", style="bold")
    title.append(f"[{band}]", style=f"bold {color}")
    sub = Text(
        f"   dmarc {report.score.components['dmarc']}  "
        f"spf {report.score.components['spf']}  "
        f"vendor {report.score.components['vendor']}  "
        f"dkim {report.score.components['dkim']}",
        style="dim",
    )
    return Panel(
        Group(title, sub),
        title=f"phishprint v{report.tool_version}",
        border_style="blue",
        padding=(0, 2),
    )


def _section_header(label: str) -> Rule:
    return Rule(Text(label, style="bold blue"), align="left", style="blue")


def _mx_section(report: Report) -> Group:
    rule = _section_header("MX")
    if report.mx.error:
        body = Text(f"  error: {report.mx.error}", style="red")
        return Group(rule, body)
    if not report.mx.hosts:
        body = Text("  (no MX records)", style="dim")
        return Group(rule, body)
    t = Table(show_header=True, header_style="bold", box=None, pad_edge=False, padding=(0, 2))
    t.add_column("pref", justify="right")
    t.add_column("hostname")
    t.add_column("ips")
    t.add_column("asn")
    for h in report.mx.hosts:
        ips = ", ".join(h.ips) if h.ips else "—"
        asn = f"AS{h.asn} {h.asn_org}" if h.asn else "—"
        t.add_row(str(h.preference), h.hostname, ips, asn)
    return Group(rule, Padding(t, (0, 0, 0, 2)))


def _spf_section(report: Report) -> Group:
    rule = _section_header("SPF")
    s = report.spf
    if not s.present:
        return Group(rule, Text("  (no SPF record)", style="red"))
    body = Text()
    body.append("  record   ", style="dim")
    body.append(s.record or "", style="white")
    body.append("\n")

    body.append("  terminal ", style="dim")
    qcolor = {"-": "green", "~": "yellow", "?": "yellow", "+": "red", None: "red"}.get(
        s.all_qualifier, "white"
    )
    body.append(f"{s.all_qualifier or 'missing'} ", style=qcolor)
    body.append(f"({s.strictness})", style="dim")
    body.append("    lookups ", style="dim")
    lc_color = "red" if s.lookup_count > 10 else ("yellow" if s.lookup_count >= 8 else "white")
    body.append(f"{s.lookup_count}/10", style=lc_color)
    body.append("    status ", style="dim")
    st_color = {"ok": "green", "permerror": "red", "none": "red"}.get(s.status, "yellow")
    body.append(s.status, style=st_color)
    if s.includes:
        body.append("\n  includes ", style="dim")
        body.append(", ".join(s.includes), style="white")
    if s.errors:
        for e in s.errors:
            body.append("\n  error    ", style="dim")
            body.append(e, style="red")
    return Group(rule, body)


def _dmarc_section(report: Report) -> Group:
    rule = _section_header("DMARC")
    d = report.dmarc
    if not d.present:
        return Group(rule, Text("  (no DMARC record)", style="red"))
    body = Text()
    body.append("  record   ", style="dim")
    body.append(d.record or "", style="white")
    body.append("\n")

    body.append("  policy   ", style="dim")
    pcolor = {"reject": "green", "quarantine": "yellow", "none": "red"}.get(d.policy or "", "white")
    body.append(f"p={d.policy}", style=pcolor)
    body.append("   sp=", style="dim")
    sp = d.sub_policy or "(inherits p)"
    body.append(sp, style=pcolor if d.sub_policy in (None, d.policy) else "yellow")
    body.append(f"   pct={d.pct}", style="dim" if d.pct == 100 else "yellow")
    body.append(f"   adkim={d.adkim} aspf={d.aspf}", style="dim")
    if d.rua:
        body.append("\n  rua      ", style="dim")
        body.append(", ".join(d.rua), style="white")
    if d.ruf:
        body.append("\n  ruf      ", style="dim")
        body.append(", ".join(d.ruf), style="white")
    return Group(rule, body)


def _dkim_section(report: Report) -> Group:
    rule = _section_header("DKIM")
    dk = report.dkim
    if not dk.found:
        body = Text(
            f"  no selectors observable (tried {dk.selectors_tried}; not proof of absence)",
            style="dim",
        )
        return Group(rule, body)
    t = Table(show_header=True, header_style="bold", box=None, pad_edge=False, padding=(0, 2))
    t.add_column("selector")
    t.add_column("key type")
    t.add_column("state")
    for s in dk.found:
        state = "revoked (p=)" if s.revoked else ("present" if s.has_public_key else "no key")
        sty = "yellow" if s.revoked else ("green" if s.has_public_key else "dim")
        t.add_row(s.selector, s.key_type or "—", Text(state, style=sty))
    return Group(rule, Padding(t, (0, 0, 0, 2)))


def _aux_section(report: Report) -> Group:
    rule = _section_header("Auxiliary")
    body = Text()
    body.append("  BIMI     ", style="dim")
    body.append("present" if report.bimi.present else "absent",
                style="green" if report.bimi.present else "dim")
    if report.bimi.vmc:
        body.append(f"   vmc={report.bimi.vmc}", style="dim")
    body.append("\n  MTA-STS  ", style="dim")
    body.append("published" if report.mta_sts.present else "absent",
                style="green" if report.mta_sts.present else "dim")
    body.append("\n  TLS-RPT  ", style="dim")
    body.append("present" if report.tls_rpt.present else "absent",
                style="green" if report.tls_rpt.present else "dim")
    if report.tls_rpt.rua:
        body.append(f"   rua={report.tls_rpt.rua}", style="dim")
    return Group(rule, body)


def _vendors_section(report: Report) -> Group:
    rule = _section_header("Vendors")
    t = Table(show_header=True, header_style="bold", box=None, pad_edge=False, padding=(0, 2))
    t.add_column("vendor")
    t.add_column("category")
    t.add_column("inspection")
    t.add_column("conf.")
    t.add_column("evidence")
    for v in report.vendors:
        ev = "; ".join(f"{e.kind}={e.matched}" for e in v.evidence)
        ccolor = {"high": "green", "medium": "yellow", "low": "dim"}[v.confidence]
        t.add_row(
            v.name,
            v.category,
            v.inspection,
            Text(v.confidence, style=ccolor),
            Text(ev, style="dim"),
        )
    return Group(rule, Padding(t, (0, 0, 0, 2)))


def _findings_section(report: Report) -> Group:
    rule = _section_header(f"Findings ({len(report.findings)})")
    if not report.findings:
        return Group(rule, Text("  none detected", style="green"))
    parts: list = [rule]
    sorted_f = sorted(report.findings, key=lambda f: _SEV_ORDER.get(f.severity, 99))
    for f in sorted_f:
        line = Text()
        color = _SEV_COLOR.get(f.severity, "white")
        line.append(f"  [{f.severity:^8}] ", style=f"bold {color}")
        line.append(f.title, style="bold")
        parts.append(line)
        # Wrap detail lines indented under the title.
        for ln in _wrap(f.detail, width=92):
            parts.append(Text("            " + ln, style="dim"))
        parts.append(Text(""))
    return Group(*parts)


def _recs_section(report: Report) -> Group:
    rule = _section_header("Recommendations")
    if not report.recommendations:
        return Group(rule, Text("  (none)", style="dim"))
    parts: list = [rule]
    for r in report.recommendations:
        parts.append(Text(f"  • {r.topic}", style="bold cyan"))
        for ln in _wrap(r.guidance, width=92):
            parts.append(Text("      " + ln))
        parts.append(Text(""))
    return Group(*parts)


def _dump_to_dir(out_dir: Path, report: Report) -> list[Path]:
    """Write <domain>.txt / .json / .md into out_dir. Returns the paths written."""
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = report.domain.replace("/", "_").replace("\\", "_")
    txt_path = out_dir / f"{safe}.txt"
    json_path = out_dir / f"{safe}.json"
    md_path = out_dir / f"{safe}.md"

    # Render the pretty summary into a plain-text file. force_terminal=False
    # + no_color=True strips ANSI; width=120 keeps tables sane.
    with txt_path.open("w", encoding="utf-8") as f:
        plain = Console(file=f, force_terminal=False, no_color=True,
                        highlight=False, width=120)
        _render_summary(plain, report)

    json_path.write_text(to_json(report), encoding="utf-8")
    md_path.write_text(to_markdown(report), encoding="utf-8")
    return [txt_path, json_path, md_path]


def _wrap(text: str, width: int) -> list[str]:
    """Cheap word wrap that preserves intentional newlines."""
    out: list[str] = []
    for paragraph in text.splitlines():
        paragraph = paragraph.strip()
        if not paragraph:
            out.append("")
            continue
        line = ""
        for word in paragraph.split():
            if line and len(line) + 1 + len(word) > width:
                out.append(line)
                line = word
            else:
                line = f"{line} {word}".strip()
        if line:
            out.append(line)
    return out


# ---------------------------------------------------------------------------
# Entry-point plumbing
# ---------------------------------------------------------------------------

_typer_app = typer.Typer(add_completion=False, rich_markup_mode=None)
_typer_app.command()(main)


def app() -> None:
    """Console-script entry point."""
    _typer_app()


if __name__ == "__main__":
    app()
