from phishprint.core.dmarc import evaluate_dmarc
from phishprint.core.resolver import FakeResolver


def test_dmarc_absent():
    r = FakeResolver()
    res = evaluate_dmarc("nope.test", r)
    assert not res.present


def test_dmarc_full_record():
    r = FakeResolver()
    r.add("_dmarc.x.test", "TXT",
          ["v=DMARC1; p=reject; sp=quarantine; pct=80; adkim=s; aspf=s; rua=mailto:a@x.test,mailto:b@x.test; fo=1"])
    res = evaluate_dmarc("x.test", r)
    assert res.present
    assert res.policy == "reject"
    assert res.sub_policy == "quarantine"
    assert res.pct == 80
    assert res.adkim == "s" and res.aspf == "s"
    assert res.rua == ["mailto:a@x.test", "mailto:b@x.test"]
    assert res.fo == "1"


def test_dmarc_sp_inherits_p():
    r = FakeResolver()
    r.add("_dmarc.y.test", "TXT", ["v=DMARC1; p=reject"])
    res = evaluate_dmarc("y.test", r)
    assert res.sub_policy is None
    assert res.effective_sub_policy == "reject"


def test_dmarc_invalid_policy_flagged():
    r = FakeResolver()
    r.add("_dmarc.z.test", "TXT", ["v=DMARC1; p=bogus"])
    res = evaluate_dmarc("z.test", r)
    assert res.errors
