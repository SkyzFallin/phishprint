"""Shared fixtures: canned DNS scenarios. No live network in tests."""
from __future__ import annotations

import pytest

from phishprint.core.resolver import FakeResolver


@pytest.fixture
def hardened_m365():
    """A well-configured Microsoft 365 tenant: p=reject, -all, MX in protection.outlook.com."""
    r = FakeResolver()
    domain = "hardened.test"
    r.add(domain, "MX", ["10 hardened-test.mail.protection.outlook.com"])
    r.add(
        "hardened-test.mail.protection.outlook.com", "A",
        ["104.47.0.1"],
    )
    r.add(domain, "TXT", ["v=spf1 include:spf.protection.outlook.com -all"])
    r.add("spf.protection.outlook.com", "TXT", ["v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 -all"])
    r.add(
        f"_dmarc.{domain}", "TXT",
        ["v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; rua=mailto:dmarc@hardened.test"],
    )
    r.add(f"selector1._domainkey.{domain}", "TXT",
          ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxxxxx"])
    return r, domain


@pytest.fixture
def open_domain():
    """No SPF, no DMARC, no DKIM, MX present."""
    r = FakeResolver()
    domain = "open.test"
    r.add(domain, "MX", ["10 mail.open.test"])
    r.add("mail.open.test", "A", ["198.51.100.10"])
    return r, domain


@pytest.fixture
def softfail_domain():
    """SPF ~all, DMARC p=none — common 'monitoring only' posture."""
    r = FakeResolver()
    domain = "softfail.test"
    r.add(domain, "MX", ["10 mx.softfail.test"])
    r.add("mx.softfail.test", "A", ["203.0.113.5"])
    r.add(domain, "TXT", ["v=spf1 ip4:203.0.113.0/24 ~all"])
    r.add(f"_dmarc.{domain}", "TXT", ["v=DMARC1; p=none; rua=mailto:r@softfail.test"])
    return r, domain


@pytest.fixture
def spf_overflow_domain():
    """Build an SPF chain whose total lookup count exceeds 10."""
    r = FakeResolver()
    domain = "overflow.test"
    # 11 includes — each contributes 1 lookup => 11 > 10.
    includes = " ".join(f"include:s{i}.overflow.test" for i in range(11))
    r.add(domain, "TXT", [f"v=spf1 {includes} -all"])
    for i in range(11):
        r.add(f"s{i}.overflow.test", "TXT", [f"v=spf1 ip4:198.51.100.{i} -all"])
    r.add(domain, "MX", ["10 mx.overflow.test"])
    r.add("mx.overflow.test", "A", ["198.51.100.20"])
    return r, domain


@pytest.fixture
def google_workspace_domain():
    r = FakeResolver()
    domain = "gws.test"
    for pref, host in [(1, "aspmx.l.google.com"), (5, "alt1.aspmx.l.google.com")]:
        r.add(domain, "MX", [f"{pref} {host}"]) if False else None
    r.add(domain, "MX", ["1 aspmx.l.google.com", "5 alt1.aspmx.l.google.com"])
    r.add("aspmx.l.google.com", "A", ["142.250.1.27"])
    r.add("alt1.aspmx.l.google.com", "A", ["142.250.1.28"])
    r.add(domain, "TXT", ["v=spf1 include:_spf.google.com -all"])
    r.add("_spf.google.com", "TXT",
          ["v=spf1 include:_netblocks.google.com include:_netblocks2.google.com -all"])
    r.add("_netblocks.google.com", "TXT", ["v=spf1 ip4:35.190.247.0/24 -all"])
    r.add("_netblocks2.google.com", "TXT", ["v=spf1 ip6:2001:4860:4000::/36 -all"])
    r.add(f"_dmarc.{domain}", "TXT", ["v=DMARC1; p=quarantine; pct=100; sp=quarantine"])
    return r, domain
