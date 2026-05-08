"""CLI smoke test using a monkey-patched scan() backed by a fake resolver."""
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


def test_cli_json_default(monkeypatch, hardened_m365):
    r, domain = hardened_m365
    monkeypatch.setattr(cli_module, "scan", _fake_scan_factory(r))
    runner = CliRunner()
    result = runner.invoke(cli_module._typer_app, [domain])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["domain"] == domain
    assert "score" in data and data["score"]["band"] == "Hardened"


def test_cli_score_only(monkeypatch, open_domain):
    r, domain = open_domain
    monkeypatch.setattr(cli_module, "scan", _fake_scan_factory(r))
    runner = CliRunner()
    result = runner.invoke(cli_module._typer_app, [domain, "--score"])
    assert result.exit_code == 0
    assert result.stdout.strip().isdigit()
