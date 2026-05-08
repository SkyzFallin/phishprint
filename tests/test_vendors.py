from phishprint.core.spf import evaluate_spf
from phishprint.core.mx import resolve_mx
from phishprint.fingerprint.vendors import fingerprint, has_heavy_inspection


def test_fingerprint_m365(hardened_m365):
    r, domain = hardened_m365
    mx = resolve_mx(domain, r, do_asn=False)
    spf = evaluate_spf(domain, r)
    matches = fingerprint(mx, spf)
    ids = [m.id for m in matches]
    assert "m365_defender" in ids
    m = next(m for m in matches if m.id == "m365_defender")
    # MX suffix + SPF include => high confidence
    assert m.confidence == "high"
    assert has_heavy_inspection(matches)


def test_fingerprint_google_workspace(google_workspace_domain):
    r, domain = google_workspace_domain
    mx = resolve_mx(domain, r, do_asn=False)
    spf = evaluate_spf(domain, r)
    matches = fingerprint(mx, spf)
    assert any(m.id == "google_workspace" and m.confidence == "high" for m in matches)


def test_fingerprint_no_match(open_domain):
    r, domain = open_domain
    mx = resolve_mx(domain, r, do_asn=False)
    spf = evaluate_spf(domain, r)
    matches = fingerprint(mx, spf)
    assert matches == []
