"""MX resolution and IP/ASN enrichment.

ASN lookup uses Team Cymru's `origin.asn.cymru.com` whois-over-DNS service —
no API key, just a TXT query against the reversed IP. Best-effort: failures
return None for asn fields.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address

from phishprint.core.resolver import Answer, NXDomain, Resolver, ResolverError


@dataclass
class MXHost:
    preference: int
    hostname: str
    ips: list[str] = field(default_factory=list)
    asn: int | None = None
    asn_org: str | None = None


@dataclass
class MXResult:
    domain: str
    hosts: list[MXHost] = field(default_factory=list)
    error: str | None = None


def resolve_mx(domain: str, resolver: Resolver, *, do_asn: bool = True) -> MXResult:
    result = MXResult(domain=domain)
    try:
        ans = resolver.query(domain, "MX")
    except NXDomain:
        result.error = "NXDOMAIN"
        return result
    except ResolverError as e:
        result.error = f"DNS error: {e}"
        return result

    for v in ans.values:
        pref_s, _, host = v.partition(" ")
        try:
            pref = int(pref_s)
        except ValueError:
            continue
        host = host.rstrip(".")
        mx = MXHost(preference=pref, hostname=host)
        mx.ips = _resolve_ips(host, resolver)
        if do_asn and mx.ips:
            asn, org = _lookup_asn(mx.ips[0], resolver)
            mx.asn, mx.asn_org = asn, org
        result.hosts.append(mx)

    result.hosts.sort(key=lambda m: (m.preference, m.hostname))
    return result


def _resolve_ips(host: str, resolver: Resolver) -> list[str]:
    out: list[str] = []
    for rrtype in ("A", "AAAA"):
        try:
            ans = resolver.query(host, rrtype)
        except (NXDomain, ResolverError):
            continue
        out.extend(ans.values)
    return out


def _lookup_asn(ip: str, resolver: Resolver) -> tuple[int | None, str | None]:
    try:
        addr = ip_address(ip)
    except ValueError:
        return None, None
    if addr.version != 4:
        return None, None  # v6 lookup uses different zone; skip in v0.1
    reversed_ip = ".".join(reversed(ip.split(".")))
    qname = f"{reversed_ip}.origin.asn.cymru.com"
    try:
        ans: Answer = resolver.query(qname, "TXT")
    except (NXDomain, ResolverError):
        return None, None
    if not ans.values:
        return None, None
    # Format: "ASN | prefix | CC | registry | allocated"
    parts = [p.strip() for p in ans.values[0].split("|")]
    if not parts:
        return None, None
    asn_str = parts[0].split()[0] if parts[0] else ""
    try:
        asn = int(asn_str)
    except ValueError:
        return None, None
    org = _lookup_asn_org(asn, resolver)
    return asn, org


def _lookup_asn_org(asn: int, resolver: Resolver) -> str | None:
    qname = f"AS{asn}.asn.cymru.com"
    try:
        ans = resolver.query(qname, "TXT")
    except (NXDomain, ResolverError):
        return None
    if not ans.values:
        return None
    parts = [p.strip() for p in ans.values[0].split("|")]
    # Last field is the org name.
    return parts[-1] if parts else None
