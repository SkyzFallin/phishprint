"""DMARC parser."""
from __future__ import annotations

from dataclasses import dataclass, field

from phishprint.core.resolver import NXDomain, Resolver, ResolverError


@dataclass
class DMARCResult:
    domain: str
    present: bool = False
    record: str | None = None
    policy: str | None = None       # p=
    sub_policy: str | None = None   # sp=
    pct: int = 100                  # pct= (default 100)
    rua: list[str] = field(default_factory=list)
    ruf: list[str] = field(default_factory=list)
    adkim: str = "r"                # default relaxed
    aspf: str = "r"
    fo: str | None = None
    multiple_records: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def effective_sub_policy(self) -> str | None:
        """If sp= absent, RFC 7489 says subdomain inherits p=."""
        return self.sub_policy or self.policy


def evaluate_dmarc(domain: str, resolver: Resolver) -> DMARCResult:
    result = DMARCResult(domain=domain)
    qname = f"_dmarc.{domain}"
    try:
        ans = resolver.query(qname, "TXT")
    except NXDomain:
        return result
    except ResolverError as e:
        result.errors.append(f"TXT lookup failed for {qname}: {e}")
        return result

    records = [v for v in ans.values if v.lower().startswith("v=dmarc1")]
    if not records:
        return result
    if len(records) > 1:
        result.multiple_records = True
        result.errors.append("multiple DMARC records")

    rec = records[0]
    result.present = True
    result.record = rec

    for tag in rec.split(";"):
        tag = tag.strip()
        if not tag or "=" not in tag:
            continue
        k, _, v = tag.partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "v":
            continue
        if k == "p":
            result.policy = v.lower()
        elif k == "sp":
            result.sub_policy = v.lower()
        elif k == "pct":
            try:
                result.pct = int(v)
            except ValueError:
                result.errors.append(f"invalid pct={v}")
        elif k == "rua":
            result.rua = [a.strip() for a in v.split(",") if a.strip()]
        elif k == "ruf":
            result.ruf = [a.strip() for a in v.split(",") if a.strip()]
        elif k == "adkim":
            result.adkim = v.lower() or "r"
        elif k == "aspf":
            result.aspf = v.lower() or "r"
        elif k == "fo":
            result.fo = v
    if result.policy not in ("none", "quarantine", "reject"):
        result.errors.append(f"invalid or missing policy: {result.policy!r}")
    return result
