"""DNS resolver abstraction.

Tests substitute a FakeResolver that returns canned answers. Production code
uses SystemResolver (default) or DoHResolver (Cloudflare 1.1.1.1).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Protocol

import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import httpx


class ResolverError(Exception):
    pass


class NXDomain(ResolverError):
    pass


class Timeout(ResolverError):
    pass


@dataclass(frozen=True)
class Answer:
    rrtype: str
    name: str
    values: tuple[str, ...]


class Resolver(Protocol):
    def query(self, name: str, rrtype: str) -> Answer: ...


class SystemResolver:
    def __init__(self, nameservers: list[str] | None = None, timeout: float = 5.0):
        self._r = dns.resolver.Resolver()
        if nameservers:
            self._r.nameservers = nameservers
        self._r.lifetime = timeout
        self._r.timeout = timeout

    def query(self, name: str, rrtype: str) -> Answer:
        try:
            ans = self._r.resolve(name, rrtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN as e:
            raise NXDomain(name) from e
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as e:
            raise Timeout(name) from e
        except dns.resolver.NoNameservers as e:
            raise ResolverError(str(e)) from e
        if ans.rrset is None:
            return Answer(rrtype=rrtype, name=name, values=())
        values = tuple(_rdata_to_str(rrtype, r) for r in ans.rrset)
        return Answer(rrtype=rrtype, name=name, values=values)


class DoHResolver:
    """DNS-over-HTTPS via Cloudflare's JSON API (1.1.1.1)."""

    URL = "https://cloudflare-dns.com/dns-query"

    def __init__(self, timeout: float = 5.0):
        self._client = httpx.Client(
            timeout=timeout,
            headers={"accept": "application/dns-json"},
        )

    def query(self, name: str, rrtype: str) -> Answer:
        try:
            r = self._client.get(self.URL, params={"name": name, "type": rrtype})
        except httpx.TimeoutException as e:
            raise Timeout(name) from e
        except httpx.HTTPError as e:
            raise ResolverError(str(e)) from e
        if r.status_code != 200:
            raise ResolverError(f"DoH HTTP {r.status_code}")
        data = r.json()
        status = data.get("Status", 2)
        if status == 3:
            raise NXDomain(name)
        if status != 0:
            raise ResolverError(f"DoH status {status}")
        answers = data.get("Answer", []) or []
        # Filter to requested type, since CNAME chains may be included.
        rtype_int = dns.rdatatype.from_text(rrtype)
        wanted = [a["data"] for a in answers if a.get("type") == rtype_int]
        return Answer(rrtype=rrtype, name=name, values=tuple(_normalize_doh(rrtype, v) for v in wanted))


def _rdata_to_str(rrtype: str, rdata) -> str:
    if rrtype.upper() == "MX":
        return f"{rdata.preference} {rdata.exchange.to_text(omit_final_dot=True)}"
    if rrtype.upper() == "TXT":
        # Concatenate character-strings into a single quoted-stripped value.
        return "".join(s.decode("utf-8", "replace") if isinstance(s, bytes) else s for s in rdata.strings)
    if rrtype.upper() in ("A", "AAAA"):
        return rdata.address
    return rdata.to_text()


def _normalize_doh(rrtype: str, value: str) -> str:
    rrtype = rrtype.upper()
    if rrtype == "TXT":
        # DoH returns TXT joined with quoting; strip surrounding quotes and
        # join character-strings.
        parts = []
        cur = ""
        in_q = False
        for ch in value:
            if ch == '"':
                in_q = not in_q
                if not in_q:
                    parts.append(cur)
                    cur = ""
                continue
            if in_q:
                cur += ch
        return "".join(parts) if parts else value.strip('"')
    if rrtype == "MX":
        # DoH returns "10 mail.example.com." — strip trailing dot.
        pref, _, host = value.partition(" ")
        return f"{pref} {host.rstrip('.')}"
    if rrtype in ("CNAME", "NS"):
        return value.rstrip(".")
    return value


# ---- Test helper ----------------------------------------------------------

class FakeResolver:
    """In-memory resolver for tests. Map (name, rrtype) -> list[str] or NXDomain.

    Names are lowercased; trailing dot tolerated.
    """

    NX = object()

    def __init__(self, table: dict[tuple[str, str], object] | None = None):
        self.table: dict[tuple[str, str], object] = {}
        if table:
            for (n, t), v in table.items():
                self.table[(n.lower().rstrip("."), t.upper())] = v
        self.calls: list[tuple[str, str]] = []

    def add(self, name: str, rrtype: str, values: Iterable[str]) -> None:
        self.table[(name.lower().rstrip("."), rrtype.upper())] = list(values)

    def add_nx(self, name: str, rrtype: str) -> None:
        self.table[(name.lower().rstrip("."), rrtype.upper())] = self.NX

    def query(self, name: str, rrtype: str) -> Answer:
        key = (name.lower().rstrip("."), rrtype.upper())
        self.calls.append(key)
        if key not in self.table:
            return Answer(rrtype=rrtype, name=name, values=())
        v = self.table[key]
        if v is self.NX:
            raise NXDomain(name)
        return Answer(rrtype=rrtype, name=name, values=tuple(v))  # type: ignore[arg-type]
