"""DKIM selector discovery.

DNS-only: we cannot enumerate selectors; we probe a wordlist of common ones
and report which exist. Absence is *not* proof that the domain doesn't sign;
it just means we couldn't observe a published key.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources

from phishprint.core.resolver import NXDomain, Resolver, ResolverError


@dataclass
class DKIMSelector:
    selector: str
    record: str
    key_type: str | None = None  # k=
    has_public_key: bool = False
    revoked: bool = False        # p= empty


@dataclass
class DKIMResult:
    domain: str
    found: list[DKIMSelector] = field(default_factory=list)
    selectors_tried: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def observable(self) -> bool:
        return any(s.has_public_key and not s.revoked for s in self.found)


def load_default_selectors() -> list[str]:
    text = resources.files("phishprint.data").joinpath("dkim_selectors.txt").read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def discover_dkim(domain: str, resolver: Resolver, selectors: list[str] | None = None) -> DKIMResult:
    result = DKIMResult(domain=domain)
    sels = selectors or load_default_selectors()
    for sel in sels:
        result.selectors_tried += 1
        qname = f"{sel}._domainkey.{domain}"
        try:
            ans = resolver.query(qname, "TXT")
        except NXDomain:
            continue
        except ResolverError:
            continue
        if not ans.values:
            continue
        # Stitch character-strings, then parse k=/p=.
        record = "".join(ans.values)
        if "p=" not in record and "v=DKIM1" not in record.upper():
            continue
        ds = DKIMSelector(selector=sel, record=record)
        for tag in record.split(";"):
            tag = tag.strip()
            if "=" not in tag:
                continue
            k, _, v = tag.partition("=")
            k = k.strip().lower()
            v = v.strip()
            if k == "k":
                ds.key_type = v
            elif k == "p":
                ds.has_public_key = bool(v)
                ds.revoked = not v
        result.found.append(ds)
    return result
