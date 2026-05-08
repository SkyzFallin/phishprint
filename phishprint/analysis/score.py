"""Composite readiness score (0-100). Higher = harder to phish.

Weights (per spec):
  DMARC enforcement:    35
  SPF strictness/health:25
  Vendor inspection:    25
  DKIM signing posture: 15
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from phishprint.core.dkim import DKIMResult
from phishprint.core.dmarc import DMARCResult
from phishprint.core.spf import SPFResult
from phishprint.fingerprint.vendors import VendorMatch


@dataclass
class Score:
    total: int          # 0-100
    band: str           # Hardened | Moderate | Permissive | Open
    components: dict[str, int]


def _band(total: int) -> str:
    if total >= 75:
        return "Hardened"
    if total >= 50:
        return "Moderate"
    if total >= 25:
        return "Permissive"
    return "Open"


def _dmarc_component(dmarc: DMARCResult) -> int:
    if not dmarc.present:
        return 0
    pct_factor = max(0, min(dmarc.pct, 100)) / 100.0
    base = {"none": 5, "quarantine": 22, "reject": 33}.get(dmarc.policy or "", 0)
    val = round(base * pct_factor) if dmarc.policy in ("quarantine", "reject") else base
    # Bonus for strict alignment.
    if dmarc.adkim == "s":
        val += 1
    if dmarc.aspf == "s":
        val += 1
    # Subdomain coverage.
    eff_sub = dmarc.effective_sub_policy
    if eff_sub == "reject":
        val += 0  # already accounted for via inheritance
    elif eff_sub == "none" and dmarc.policy == "reject":
        val -= 4
    return max(0, min(35, val))


def _spf_component(spf: SPFResult) -> int:
    if not spf.present:
        return 0
    if spf.lookup_count > 10 or spf.multiple_records:
        return 2  # broken — many receivers won't enforce
    base = {
        "-": 25,   # hard fail
        "~": 12,   # softfail
        "?": 4,    # neutral
        "+": 0,    # pass-all = broken
        None: 3,   # no terminal `all`
    }.get(spf.all_qualifier, 5)
    if spf.errors:
        base = max(0, base - 5)
    return max(0, min(25, base))


def _vendor_component(matches: Iterable[VendorMatch]) -> int:
    score = 0
    seen = set()
    for m in matches:
        if m.confidence == "low":
            continue
        if m.id in seen:
            continue
        seen.add(m.id)
        if m.inspection == "heavy":
            score += 12
        elif m.inspection == "medium_to_heavy":
            score += 9
        elif m.inspection == "medium":
            score += 5
        elif m.inspection == "low":
            score += 1
    return min(25, score)


def _dkim_component(dkim: DKIMResult) -> int:
    if not dkim.observable:
        return 0
    keys = sum(1 for s in dkim.found if s.has_public_key and not s.revoked)
    if keys >= 2:
        return 15
    return 10


def compute(
    spf: SPFResult,
    dmarc: DMARCResult,
    dkim: DKIMResult,
    vendors: Iterable[VendorMatch],
) -> Score:
    components = {
        "dmarc": _dmarc_component(dmarc),
        "spf": _spf_component(spf),
        "vendor": _vendor_component(vendors),
        "dkim": _dkim_component(dkim),
    }
    total = sum(components.values())
    total = max(0, min(100, total))
    return Score(total=total, band=_band(total), components=components)
