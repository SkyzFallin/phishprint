"""Bypass condition detection.

Each finding is a discrete, named condition with an operator-facing
severity. Severity drives surfacing in reports; scoring uses the raw
posture data (not these findings) so the two can evolve independently.
"""
from __future__ import annotations

from dataclasses import dataclass

from phishprint.core.dkim import DKIMResult
from phishprint.core.dmarc import DMARCResult
from phishprint.core.mx import MXResult
from phishprint.core.spf import SPFResult


@dataclass
class Finding:
    id: str
    severity: str   # info | low | medium | high | critical
    title: str
    detail: str


def detect(spf: SPFResult, dmarc: DMARCResult, dkim: DKIMResult, mx: MXResult) -> list[Finding]:
    out: list[Finding] = []

    # ---- SPF -------------------------------------------------------------
    if not spf.present:
        out.append(Finding(
            id="spf_absent",
            severity="critical",
            title="SPF record absent",
            detail="No v=spf1 TXT record published. Sender authentication is effectively off; "
                   "spoofed mail-from is unimpeded by SPF at any receiver.",
        ))
    else:
        if spf.lookup_count > 10:
            out.append(Finding(
                id="spf_lookup_overflow",
                severity="high",
                title=f"SPF DNS lookup limit exceeded ({spf.lookup_count} > 10)",
                detail="RFC 7208 §4.6.4 mandates permerror. Most receivers stop SPF evaluation; "
                       "spoofs of the bare domain often pass for that reason.",
            ))
        if spf.all_qualifier in (None, "?"):
            out.append(Finding(
                id="spf_no_terminal_fail",
                severity="high",
                title="SPF has no `-all` or `~all` terminal",
                detail=f"all_qualifier={spf.all_qualifier!r}. Receivers will not treat unauthorized "
                       "senders as failed; spoofing is largely unimpeded.",
            ))
        elif spf.all_qualifier == "~":
            out.append(Finding(
                id="spf_softfail",
                severity="medium",
                title="SPF terminal is `~all` (softfail)",
                detail="Receivers may deliver to inbox or spam at their discretion. Combined with "
                       "weak DMARC, spoofing is feasible.",
            ))
        elif spf.all_qualifier == "+":
            out.append(Finding(
                id="spf_pass_all",
                severity="critical",
                title="SPF terminal is `+all`",
                detail="Record passes any sender. Equivalent to no SPF.",
            ))
        if spf.multiple_records:
            out.append(Finding(
                id="spf_multiple_records",
                severity="high",
                title="Multiple SPF records published",
                detail="RFC 7208 mandates permerror. SPF is effectively broken at compliant receivers.",
            ))

    # ---- DMARC -----------------------------------------------------------
    if not dmarc.present:
        out.append(Finding(
            id="dmarc_absent",
            severity="critical",
            title="DMARC record absent",
            detail="No _dmarc TXT record. No alignment check or reporting; spoofs of the bare "
                   "domain land at the receiver's default disposition.",
        ))
    else:
        if dmarc.policy == "none":
            out.append(Finding(
                id="dmarc_p_none",
                severity="high",
                title="DMARC policy is p=none (monitor only)",
                detail="Domain owner is observing but not enforcing. Spoofed mail aligned to the "
                       "bare domain still delivers in most cases.",
            ))
        elif dmarc.policy == "quarantine" and dmarc.pct < 100:
            out.append(Finding(
                id="dmarc_partial_quarantine",
                severity="medium",
                title=f"DMARC quarantine applied to only {dmarc.pct}% of mail",
                detail="Statistically a fraction of spoofs will still inbox.",
            ))
        elif dmarc.policy == "reject" and dmarc.pct < 100:
            out.append(Finding(
                id="dmarc_partial_reject",
                severity="medium",
                title=f"DMARC reject applied to only {dmarc.pct}% of mail",
                detail="Partial enforcement; some spoofs will still deliver.",
            ))
        if dmarc.policy == "reject" and dmarc.sub_policy in (None, "none"):
            sp = dmarc.sub_policy or "(absent → inherits p)"
            out.append(Finding(
                id="dmarc_subdomain_gap",
                severity="high",
                title="DMARC subdomain policy weaker than parent",
                detail=f"p=reject but sp={sp}. Subdomains may be unprotected — "
                       "consider phishing from `*.target.tld` lookalikes hosted on cousin domains.",
            ))

    # ---- DKIM ------------------------------------------------------------
    if not dkim.observable:
        out.append(Finding(
            id="dkim_not_observable",
            severity="low",
            title="No DKIM selectors observable via wordlist",
            detail=f"Tried {dkim.selectors_tried} common selectors; none returned a key. "
                   "Domain may still sign with a custom selector — this is a hint, not proof.",
        ))

    # ---- MX --------------------------------------------------------------
    if mx.error:
        out.append(Finding(
            id="mx_error",
            severity="info",
            title=f"MX resolution issue: {mx.error}",
            detail="Posture conclusions limited; investigate manually.",
        ))
    elif not mx.hosts:
        out.append(Finding(
            id="mx_absent",
            severity="info",
            title="No MX records",
            detail="Domain may not receive mail. Phishing target is likely a sister/parent domain.",
        ))
    else:
        # Hybrid signal: cloud MX + on-prem looking SPF mechanisms (ip4/ip6 lots of them).
        cloud_mx = any(
            any(s in h.hostname.lower() for s in ("outlook.com", "google.com", "googlemail.com"))
            for h in mx.hosts
        )
        if cloud_mx and spf.present and (spf.record or "").lower().count("ip4:") >= 3:
            out.append(Finding(
                id="mx_hybrid_split_delivery",
                severity="medium",
                title="Possible hybrid mail (cloud MX + on-prem SPF mechanisms)",
                detail="Cloud-hosted inbound MX with several ip4: ranges in SPF often indicates "
                       "a hybrid Exchange / split-delivery setup. Look for legacy on-prem submission "
                       "paths that may bypass cloud inspection.",
            ))

    return out
