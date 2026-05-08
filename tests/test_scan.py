from phishprint.scan import scan
from phishprint.output.json_writer import to_json
from phishprint.output.markdown_writer import to_markdown


def test_hardened_full_scan(hardened_m365):
    r, domain = hardened_m365
    rep = scan(domain, r, do_asn=False)
    assert rep.score.band == "Hardened"
    assert rep.score.total >= 75
    # JSON serializable end-to-end.
    js = to_json(rep)
    assert domain in js and "score" in js
    md = to_markdown(rep)
    assert "Readiness" in md and "phishprint" in md


def test_open_full_scan(open_domain):
    r, domain = open_domain
    rep = scan(domain, r, do_asn=False)
    assert rep.score.band in ("Open", "Permissive")
    finding_ids = {f.id for f in rep.findings}
    assert "spf_absent" in finding_ids
    assert "dmarc_absent" in finding_ids


def test_softfail_findings(softfail_domain):
    r, domain = softfail_domain
    rep = scan(domain, r, do_asn=False)
    finding_ids = {f.id for f in rep.findings}
    assert "spf_softfail" in finding_ids
    assert "dmarc_p_none" in finding_ids


def test_overflow_findings(spf_overflow_domain):
    r, domain = spf_overflow_domain
    rep = scan(domain, r, do_asn=False)
    finding_ids = {f.id for f in rep.findings}
    assert "spf_lookup_overflow" in finding_ids
    assert rep.spf.status == "permerror"
