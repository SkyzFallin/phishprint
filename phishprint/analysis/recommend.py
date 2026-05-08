"""Operator-facing sending-infrastructure recommendations."""
from __future__ import annotations

from dataclasses import dataclass

from phishprint.analysis.score import Score
from phishprint.core.auxiliary import MTASTSResult
from phishprint.core.dmarc import DMARCResult
from phishprint.core.spf import SPFResult
from phishprint.fingerprint.vendors import VendorMatch


@dataclass
class Recommendation:
    topic: str
    guidance: str


def build(
    *,
    score: Score,
    spf: SPFResult,
    dmarc: DMARCResult,
    mta_sts: MTASTSResult,
    vendors: list[VendorMatch],
) -> list[Recommendation]:
    recs: list[Recommendation] = []

    # ---- Sender domain choice -------------------------------------------
    if score.band in ("Hardened", "Moderate"):
        recs.append(Recommendation(
            "sender_domain",
            "Use a fresh unrelated domain (clean reputation, aged ≥ 14d). Lookalikes of the target "
            "are likely to be flagged by the gateway's brand-protection or homoglyph checks at this posture.",
        ))
    else:
        recs.append(Recommendation(
            "sender_domain",
            "Lookalike or cousin domain is viable. Still age the domain ≥ 7d and warm sending volume "
            "to avoid first-contact reputation penalties.",
        ))

    # ---- Auth on the sender side ----------------------------------------
    needs_strict_auth = (
        (dmarc.present and dmarc.policy in ("quarantine", "reject"))
        or any(v.inspection in ("heavy", "medium_to_heavy") and v.confidence != "low" for v in vendors)
    )
    if needs_strict_auth:
        recs.append(Recommendation(
            "sender_auth",
            "Configure SPF (-all), DKIM (2048-bit, selector published), and DMARC (p=quarantine pct=100) "
            "on the sender domain. Aligned identifiers will clear DMARC at the receiver and reduce "
            "spam-folder placement.",
        ))
    else:
        recs.append(Recommendation(
            "sender_auth",
            "Publish SPF and DKIM at minimum. DMARC on the sender is optional given target posture but "
            "recommended for inbox placement on adjacent receivers.",
        ))

    # ---- Transport / TLS -------------------------------------------------
    if mta_sts.present:
        recs.append(Recommendation(
            "transport_tls",
            "Target publishes MTA-STS — ensure the sending MTA presents a valid cert chain matching "
            "the HELO name. Self-signed or expired certs will be rejected.",
        ))
    else:
        recs.append(Recommendation(
            "transport_tls",
            "No MTA-STS published. Opportunistic TLS is fine; mismatched certs are tolerated.",
        ))

    # ---- Vendor-specific notes ------------------------------------------
    for v in vendors:
        if v.confidence == "low" or not v.notes:
            continue
        recs.append(Recommendation(f"vendor:{v.id}", v.notes.strip()))

    # ---- Subdomain gap exploit -----------------------------------------
    if dmarc.present and dmarc.policy == "reject" and (dmarc.sub_policy in (None, "none")):
        recs.append(Recommendation(
            "subdomain_attack",
            "Bare domain is hardened (p=reject) but subdomain policy is permissive. Spoofing "
            "`anything.target.tld` may bypass DMARC at the receiver — useful for display-name + "
            "look-real-from-domain pretexts.",
        ))

    # ---- SPF overflow exploit -------------------------------------------
    if spf.present and spf.lookup_count > 10:
        recs.append(Recommendation(
            "spf_overflow_exploit",
            "Target's SPF exceeds the 10-lookup limit (permerror). Many receivers ignore SPF for the "
            "domain entirely — direct from-address spoofing is feasible if DMARC is also weak.",
        ))

    # ---- Pre-flight checks ----------------------------------------------
    recs.append(Recommendation(
        "preflight",
        "Before launch: warm sender for 48-72h, send a test from sender → operator-controlled inbox "
        "behind the same gateway category (M365 → M365, Workspace → Workspace), validate SPF/DKIM "
        "alignment in the received headers, and confirm the lure URL is not on URIBL/SURBL.",
    ))

    return recs
