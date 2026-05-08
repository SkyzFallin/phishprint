"""SPF parser with recursive include expansion and DNS lookup counting.

RFC 7208 §4.6.4 limits SPF to 10 DNS-lookup mechanisms (include, a, mx, ptr,
exists, redirect). Exceeding it is a permerror — many receivers then treat
SPF as effectively disabled for the domain. We track this directly because
none of the off-the-shelf Python SPF libraries get it right.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from phishprint.core.resolver import NXDomain, Resolver, ResolverError

LOOKUP_LIMIT = 10
VOID_LOOKUP_LIMIT = 2  # §4.6.4


# Mechanisms that trigger DNS lookups.
LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}
# Modifiers that trigger DNS lookups.
LOOKUP_MODIFIERS = {"redirect", "exp"}


@dataclass
class SPFResult:
    domain: str
    record: str | None = None
    records_seen: list[str] = field(default_factory=list)  # full chain
    includes: list[str] = field(default_factory=list)  # flat list of all includes resolved
    redirect: str | None = None
    all_qualifier: str | None = None  # "+", "-", "~", "?", or None
    lookup_count: int = 0
    void_lookups: int = 0
    errors: list[str] = field(default_factory=list)
    multiple_records: bool = False
    present: bool = False

    @property
    def status(self) -> str:
        if not self.present:
            return "none"
        if self.errors:
            return "permerror"
        if self.lookup_count > LOOKUP_LIMIT:
            return "permerror"
        return "ok"

    @property
    def strictness(self) -> str:
        """Operator-facing strictness label for the terminal `all`."""
        q = self.all_qualifier
        return {
            "-": "fail",        # hard fail — strict
            "~": "softfail",    # permissive
            "?": "neutral",     # permissive
            "+": "pass",        # broken (passes everything)
            None: "missing",    # no `all` mechanism
        }.get(q, "unknown")


def evaluate_spf(domain: str, resolver: Resolver) -> SPFResult:
    result = SPFResult(domain=domain)
    record = _fetch_spf(domain, resolver, result)
    if record is None:
        return result
    result.record = record
    result.present = True
    _walk(domain, record, resolver, result, depth=0, visited={domain.lower()})
    return result


def _fetch_spf(domain: str, resolver: Resolver, result: SPFResult) -> str | None:
    try:
        ans = resolver.query(domain, "TXT")
    except NXDomain:
        return None
    except ResolverError as e:
        result.errors.append(f"TXT lookup failed for {domain}: {e}")
        return None
    spfs = [v for v in ans.values if v.lower().startswith("v=spf1")]
    if not spfs:
        return None
    if len(spfs) > 1:
        result.multiple_records = True
        result.errors.append(f"multiple SPF records on {domain}")
    return spfs[0]


def _walk(
    domain: str,
    record: str,
    resolver: Resolver,
    result: SPFResult,
    *,
    depth: int,
    visited: set[str],
) -> None:
    """Recursively expand a record, counting DNS-lookup mechanisms."""
    if depth > LOOKUP_LIMIT:
        result.errors.append("recursion depth exceeded")
        return
    result.records_seen.append(f"{domain}: {record}")
    terms = record.split()[1:]  # drop v=spf1
    for term in terms:
        if "=" in term and not term.startswith(("+", "-", "~", "?")):
            mod, _, value = term.partition("=")
            mod_l = mod.lower()
            if mod_l == "redirect":
                result.lookup_count += 1
                target = value.strip()
                result.redirect = target
                if target.lower() in visited:
                    result.errors.append(f"redirect loop on {target}")
                    continue
                sub = _fetch_spf(target, resolver, result)
                if sub is None:
                    result.void_lookups += 1
                    continue
                _walk(target, sub, resolver, result, depth=depth + 1, visited=visited | {target.lower()})
            elif mod_l == "exp":
                result.lookup_count += 1
            continue

        qual = "+"
        body = term
        if term[:1] in ("+", "-", "~", "?"):
            qual, body = term[0], term[1:]

        name, _, _arg = body.partition(":")
        name = name.lower()

        if name == "all":
            # First `all` wins; subsequent ones ignored per spec.
            if result.all_qualifier is None:
                result.all_qualifier = qual
            continue

        if name in LOOKUP_MECHANISMS:
            result.lookup_count += 1
            if name == "include":
                target = body.partition(":")[2].strip()
                if not target:
                    result.errors.append("empty include target")
                    continue
                if target.lower() in visited:
                    result.errors.append(f"include loop on {target}")
                    continue
                result.includes.append(target)
                sub = _fetch_spf(target, resolver, result)
                if sub is None:
                    result.void_lookups += 1
                    continue
                _walk(
                    target,
                    sub,
                    resolver,
                    result,
                    depth=depth + 1,
                    visited=visited | {target.lower()},
                )
            # For a/mx/ptr/exists we just count the lookup; we don't need
            # the resolved IP set for posture analysis.
        # ip4: / ip6: are not lookups; nothing to count.

    if result.void_lookups > VOID_LOOKUP_LIMIT:
        # Avoid duplicating the same error string.
        msg = f"void lookups exceed limit ({result.void_lookups} > {VOID_LOOKUP_LIMIT})"
        if msg not in result.errors:
            result.errors.append(msg)
