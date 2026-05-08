"""Auxiliary email-security signals: BIMI, MTA-STS, TLS-RPT.

These are presence/posture checks; we don't validate VMC certs or enforce
the policy semantics — that's compliance-tool territory.
"""
from __future__ import annotations

from dataclasses import dataclass

from phishprint.core.resolver import NXDomain, Resolver, ResolverError


@dataclass
class BIMIResult:
    present: bool = False
    record: str | None = None
    location: str | None = None  # l=
    vmc: str | None = None       # a= (Verified Mark Cert URL)


@dataclass
class MTASTSResult:
    present: bool = False
    record: str | None = None
    mode: str | None = None      # enforce / testing / none


@dataclass
class TLSRPTResult:
    present: bool = False
    record: str | None = None
    rua: str | None = None


def evaluate_bimi(domain: str, resolver: Resolver, selector: str = "default") -> BIMIResult:
    qname = f"{selector}._bimi.{domain}"
    out = BIMIResult()
    try:
        ans = resolver.query(qname, "TXT")
    except (NXDomain, ResolverError):
        return out
    recs = [v for v in ans.values if v.lower().startswith("v=bimi1")]
    if not recs:
        return out
    out.present = True
    out.record = recs[0]
    for tag in recs[0].split(";"):
        k, _, v = tag.strip().partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "l":
            out.location = v
        elif k == "a":
            out.vmc = v
    return out


def evaluate_mta_sts(domain: str, resolver: Resolver) -> MTASTSResult:
    out = MTASTSResult()
    try:
        ans = resolver.query(f"_mta-sts.{domain}", "TXT")
    except (NXDomain, ResolverError):
        return out
    recs = [v for v in ans.values if v.lower().startswith("v=stsv1")]
    if not recs:
        return out
    out.present = True
    out.record = recs[0]
    # Mode is in the policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt
    # The TXT record itself only carries v= and id=. We mark "published" without
    # fetching the policy to stay strictly DNS-only in v0.1.
    return out


def evaluate_tls_rpt(domain: str, resolver: Resolver) -> TLSRPTResult:
    out = TLSRPTResult()
    try:
        ans = resolver.query(f"_smtp._tls.{domain}", "TXT")
    except (NXDomain, ResolverError):
        return out
    recs = [v for v in ans.values if v.lower().startswith("v=tlsrptv1")]
    if not recs:
        return out
    out.present = True
    out.record = recs[0]
    for tag in recs[0].split(";"):
        k, _, v = tag.strip().partition("=")
        if k.strip().lower() == "rua":
            out.rua = v.strip()
    return out
