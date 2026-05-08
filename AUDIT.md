# AUDIT

Standing audit of phishprint. Updated alongside code changes.

## Code Quality

- **Layering.** Core DNS modules (`phishprint/core/*`) depend only on the
  resolver abstraction. Analysis (`phishprint/analysis/*`) depends on core
  but not on output. Output writers depend on the `Report` shape only.
  No backwards imports.
- **Testability.** Every module that touches DNS takes a `Resolver`
  protocol parameter. The test suite uses `FakeResolver` exclusively;
  there is no live network in `pytest`.
- **SPF parser.** Hand-rolled rather than depending on a third-party SPF
  library — every actively maintained one we evaluated had edge-case
  bugs around redirect, recursive includes, or void-lookup counting.
  Trade-off accepted: maintenance burden in exchange for correctness.
- **Vendor signatures.** Data in YAML, not code. Adding a vendor is a
  one-file change.
- **Linting.** `ruff` at line 100, Py 3.11 target.

### Known limitations

- ASN lookup uses Cymru's whois-over-DNS for IPv4 only. IPv6 reverse
  zone (`origin6.asn.cymru.com`) is not implemented in v0.1.
- MTA-STS detection checks the `_mta-sts` TXT record only; we do not
  fetch `https://mta-sts.<domain>/.well-known/mta-sts.txt` to read the
  policy mode. Staying strictly DNS-only in v0.1.
- DKIM discovery is wordlist-based; selectors outside the wordlist are
  invisible.

## Security

- **No outbound traffic to target infrastructure.** Only DNS queries,
  routed through the operator's chosen resolver (system, custom IP, or
  Cloudflare DoH).
- **No credential or token storage.** Tool is stateless in v0.1.
- **No code execution from data.** Vendor signatures and DKIM selector
  wordlists are loaded with `yaml.safe_load` and plain text reads.
- **Input validation.** All DNS responses are treated as untrusted; the
  parsers tolerate malformed records without crashing the run (errors
  are surfaced in the report).
- **DoH endpoint hardcoded** to Cloudflare (`cloudflare-dns.com`).
  Changing this requires a code change so an operator cannot be tricked
  by an env var into leaking queries elsewhere.

### Operator responsibility

- DNS queries originate from whatever box phishprint runs on. Run on a
  jumpbox you control, not from a personal workstation, if attribution
  matters.
- The default system resolver may log queries upstream (corporate DNS,
  ISP). Use `--doh` or `--resolver` to control egress.

## GitHub Repo

- Single MIT license at the root.
- README has banner, one-liner, author, what-it-does, quick start,
  output table, options table, notes, changelog, roadmap, credits,
  hygiene, audit pointer, authorized-use notice, license.
- No third-party branding in code or docs.
- Test fixtures committed; live network is never required to run the
  suite.

### Backlog

- CI pipeline (GitHub Actions: `ruff check`, `pytest`).
- Pre-commit hook for `ruff` and `pytest -q`.
- `CHANGELOG.md` once v0.2 lands.

## Feature Backlog

In rough priority order. v0.2 candidates first.

1. **Batch mode** (`-f domains.txt`). Concurrent scans with bounded
   parallelism so a list of 50 domains finishes in seconds, not minutes.
2. **MTA-STS policy fetch.** Optional, gated behind a flag, to read the
   actual `mode=` (enforce/testing/none) from the well-known URL.
3. **IPv6 ASN lookup** via `origin6.asn.cymru.com`.
4. **DKIM selector enumeration from DMARC reporting** — many tenants
   list selectors implicitly via their reporting setup; mine those.
5. **Lookalike domain availability** — homoglyph, character-swap, and
   TLD-swap permutations checked against a registrar/WHOIS API.
6. **Historical tracking** — store each scan in `~/.phishprint/history.db`
   and surface deltas (e.g., DMARC tightened from `p=none` to
   `p=quarantine` since last scan).
7. **Gophish profile stub** — emit a sending-profile YAML keyed to the
   detected vendor's likely-tolerated configuration.
8. **Header analysis mode** — paste headers from a received message,
   get the actual delivery-path posture (which often differs from the
   DNS-only view).
9. **Censys/Shodan integration** for sender-side infra recon.
10. **Custom signatures path** — `--signatures path/to/extra.yaml` to
    layer engagement-specific vendor patterns on top of the bundled set.
