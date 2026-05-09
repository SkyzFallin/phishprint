"""CLI smoke tests using a monkey-patched scan() backed by a fake resolver."""
from __future__ import annotations

import json

from typer.testing import CliRunner

from phishprint import cli as cli_module
from phishprint.core.resolver import FakeResolver
from phishprint.scan import scan as real_scan


def _fake_scan_factory(resolver: FakeResolver):
    def _scan(domain, _resolver, *, selectors=None, do_asn=True):
        return real_scan(domain, resolver, selectors=selectors, do_asn=False)
    return _scan


def test_cli_json_flag(monkeypatch, hardened_m365):
    r, domain = hardened_m365
    monkeypatch.setattr(cli_module, "scan", _fake_scan_factory(r))
    runner = CliRunner()
    result = runner.invoke(cli_module._typer_app, [domain, "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["domain"] == domain
    assert data["score"]["band"] == "Hardened"


def test_cli_default_pipe_yields_json(monkeypatch, hardened_m365):
    """When stdout isn't a TTY (CliRunner case), we should fall back to JSON."""
    r, domain = hardened_m365
    monkeypatch.setattr(cli_module, "scan", _fake_scan_factory(r))
    runner = CliRunner()
    result = runner.invoke(cli_module._typer_app, [domain])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["domain"] == domain


def test_cli_score_only(monkeypatch, open_domain):
    r, domain = open_domain
    monkeypatch.setattr(cli_module, "scan", _fake_scan_factory(r))
    runner = CliRunner()
    result = runner.invoke(cli_module._typer_app, [domain, "--score"])
    assert result.exit_code == 0
    assert result.stdout.strip().isdigit()


def test_cli_writes_markdown_file(monkeypatch, hardened_m365, tmp_path):
    r, domain = hardened_m365
    monkeypatch.setattr(cli_module, "scan", _fake_scan_factory(r))
    out = tmp_path / "report.md"
    runner = CliRunner()
    result = runner.invoke(cli_module._typer_app, [domain, "-o", str(out), "--json"])
    assert result.exit_code == 0, result.output
    assert out.exists()
    md = out.read_text(encoding="utf-8")
    assert "phishprint report" in md
    assert "Readiness" in md


def test_cli_writes_json_file(monkeypatch, hardened_m365, tmp_path):
    r, domain = hardened_m365
    monkeypatch.setattr(cli_module, "scan", _fake_scan_factory(r))
    out = tmp_path / "scan.json"
    runner = CliRunner()
    result = runner.invoke(cli_module._typer_app, [domain, "--json-file", str(out), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text(encoding="utf-8"))["domain"] == domain
