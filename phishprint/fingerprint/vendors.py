"""Vendor fingerprinting against MX hostnames, SPF includes, and ASN orgs."""
from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from typing import Iterable

import yaml

from phishprint.core.mx import MXResult
from phishprint.core.spf import SPFResult


@dataclass
class VendorEvidence:
    kind: str   # mx_suffix | spf_include | asn_org | asn
    value: str
    matched: str


@dataclass
class VendorMatch:
    id: str
    name: str
    category: str
    inspection: str
    notes: str | None
    confidence: str       # high | medium | low
    score: int
    evidence: list[VendorEvidence] = field(default_factory=list)


def _load_signatures() -> list[dict]:
    text = resources.files("phishprint.fingerprint").joinpath("signatures.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    return data.get("vendors", [])


_SIGNATURES = _load_signatures()


def _confidence(score: int) -> str:
    if score >= 3:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


def fingerprint(mx: MXResult, spf: SPFResult) -> list[VendorMatch]:
    matches: dict[str, VendorMatch] = {}

    mx_hosts = [h.hostname.lower() for h in mx.hosts]
    asn_orgs = [(h.asn, (h.asn_org or "").lower()) for h in mx.hosts if h.asn_org]
    asns = {h.asn for h in mx.hosts if h.asn is not None}

    spf_includes_lower = {i.lower() for i in spf.includes}

    for sig in _SIGNATURES:
        sid = sig["id"]
        m = VendorMatch(
            id=sid,
            name=sig.get("name", sid),
            category=sig.get("category", "unknown"),
            inspection=sig.get("inspection", "unknown"),
            notes=sig.get("notes"),
            confidence="low",
            score=0,
        )

        for suf in sig.get("mx_suffixes", []) or []:
            suf_l = suf.lower()
            for host in mx_hosts:
                if host == suf_l.lstrip(".") or host.endswith(suf_l):
                    m.evidence.append(VendorEvidence("mx_suffix", suf, host))
                    m.score += 2

        for inc in sig.get("spf_includes", []) or []:
            if inc.lower() in spf_includes_lower:
                m.evidence.append(VendorEvidence("spf_include", inc, inc))
                m.score += 2

        for needle in sig.get("asn_orgs", []) or []:
            n = needle.lower()
            for asn, org in asn_orgs:
                if n in org:
                    m.evidence.append(VendorEvidence("asn_org", needle, f"AS{asn} {org}"))
                    m.score += 1

        for asn in sig.get("asns", []) or []:
            if asn in asns:
                m.evidence.append(VendorEvidence("asn", str(asn), f"AS{asn}"))
                m.score += 1

        if m.evidence:
            # When multiple suffixes match the same host (e.g. both
            # `.mail.protection.outlook.com` and `.protection.outlook.com`),
            # keep only the most specific evidence per (kind, matched) so
            # we don't double-count score or spam the report.
            m.evidence, m.score = _dedupe_evidence(m.evidence)
            m.confidence = _confidence(m.score)
            matches[sid] = m

    return sorted(matches.values(), key=lambda v: (-v.score, v.name))


def _dedupe_evidence(evidence: list[VendorEvidence]) -> tuple[list[VendorEvidence], int]:
    """Collapse evidence to one entry per (kind, matched). Returns (list, score)."""
    seen: dict[tuple[str, str], VendorEvidence] = {}
    for e in evidence:
        key = (e.kind, e.matched)
        # Prefer the most specific signature value (longest) when multiple
        # signatures match the same host.
        prev = seen.get(key)
        if prev is None or len(e.value) > len(prev.value):
            seen[key] = e
    deduped = list(seen.values())
    score = 0
    for e in deduped:
        score += {"mx_suffix": 2, "spf_include": 2, "asn_org": 1, "asn": 1}.get(e.kind, 1)
    return deduped, score


def categories(matches: Iterable[VendorMatch]) -> set[str]:
    return {m.category for m in matches}


def has_heavy_inspection(matches: Iterable[VendorMatch]) -> bool:
    return any(m.inspection in ("heavy", "medium_to_heavy") and m.confidence != "low" for m in matches)
