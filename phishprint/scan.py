"""Top-level orchestration: run all checks and assemble a Report."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from phishprint import __version__
from phishprint.analysis.bypass import Finding, detect
from phishprint.analysis.recommend import Recommendation, build as build_recs
from phishprint.analysis.score import Score, compute as compute_score
from phishprint.core.auxiliary import (
    BIMIResult,
    MTASTSResult,
    TLSRPTResult,
    evaluate_bimi,
    evaluate_mta_sts,
    evaluate_tls_rpt,
)
from phishprint.core.dkim import DKIMResult, discover_dkim
from phishprint.core.dmarc import DMARCResult, evaluate_dmarc
from phishprint.core.mx import MXResult, resolve_mx
from phishprint.core.resolver import Resolver
from phishprint.core.spf import SPFResult, evaluate_spf
from phishprint.fingerprint.vendors import VendorMatch, fingerprint


@dataclass
class Report:
    domain: str
    tool_version: str
    mx: MXResult
    spf: SPFResult
    dmarc: DMARCResult
    dkim: DKIMResult
    bimi: BIMIResult
    mta_sts: MTASTSResult
    tls_rpt: TLSRPTResult
    vendors: list[VendorMatch]
    findings: list[Finding]
    score: Score
    recommendations: list[Recommendation] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def scan(
    domain: str,
    resolver: Resolver,
    *,
    selectors: list[str] | None = None,
    do_asn: bool = True,
) -> Report:
    domain = domain.lower().strip(".")
    mx = resolve_mx(domain, resolver, do_asn=do_asn)
    spf = evaluate_spf(domain, resolver)
    dmarc = evaluate_dmarc(domain, resolver)
    dkim = discover_dkim(domain, resolver, selectors=selectors)
    bimi = evaluate_bimi(domain, resolver)
    mta_sts = evaluate_mta_sts(domain, resolver)
    tls_rpt = evaluate_tls_rpt(domain, resolver)

    vendors = fingerprint(mx, spf)
    findings = detect(spf, dmarc, dkim, mx)
    score = compute_score(spf, dmarc, dkim, vendors)
    recs = build_recs(score=score, spf=spf, dmarc=dmarc, mta_sts=mta_sts, vendors=vendors)

    return Report(
        domain=domain,
        tool_version=__version__,
        mx=mx,
        spf=spf,
        dmarc=dmarc,
        dkim=dkim,
        bimi=bimi,
        mta_sts=mta_sts,
        tls_rpt=tls_rpt,
        vendors=vendors,
        findings=findings,
        score=score,
        recommendations=recs,
    )
