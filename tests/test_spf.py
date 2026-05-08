from phishprint.core.resolver import FakeResolver
from phishprint.core.spf import evaluate_spf


def test_spf_absent():
    r = FakeResolver()
    res = evaluate_spf("nope.test", r)
    assert not res.present
    assert res.status == "none"


def test_spf_simple_hardfail():
    r = FakeResolver()
    r.add("a.test", "TXT", ["v=spf1 ip4:198.51.100.0/24 -all"])
    res = evaluate_spf("a.test", r)
    assert res.present
    assert res.all_qualifier == "-"
    assert res.strictness == "fail"
    assert res.lookup_count == 0
    assert res.status == "ok"


def test_spf_softfail():
    r = FakeResolver()
    r.add("b.test", "TXT", ["v=spf1 ~all"])
    res = evaluate_spf("b.test", r)
    assert res.all_qualifier == "~"
    assert res.strictness == "softfail"


def test_spf_recursive_includes_count_lookups():
    r = FakeResolver()
    r.add("root.test", "TXT", ["v=spf1 include:l1.test include:l2.test -all"])
    r.add("l1.test", "TXT", ["v=spf1 include:l3.test -all"])
    r.add("l2.test", "TXT", ["v=spf1 ip4:1.2.3.4 -all"])
    r.add("l3.test", "TXT", ["v=spf1 ip4:5.6.7.8 -all"])
    res = evaluate_spf("root.test", r)
    # 3 includes => 3 lookups
    assert res.lookup_count == 3
    assert "l1.test" in res.includes and "l3.test" in res.includes
    assert res.status == "ok"


def test_spf_overflow_permerror():
    r = FakeResolver()
    inc = " ".join(f"include:i{i}.test" for i in range(11))
    r.add("ovr.test", "TXT", [f"v=spf1 {inc} -all"])
    for i in range(11):
        r.add(f"i{i}.test", "TXT", [f"v=spf1 ip4:198.51.100.{i} -all"])
    res = evaluate_spf("ovr.test", r)
    assert res.lookup_count == 11
    assert res.status == "permerror"


def test_spf_redirect_followed():
    r = FakeResolver()
    r.add("rd.test", "TXT", ["v=spf1 redirect=other.test"])
    r.add("other.test", "TXT", ["v=spf1 ip4:9.9.9.9 -all"])
    res = evaluate_spf("rd.test", r)
    assert res.redirect == "other.test"
    assert res.lookup_count == 1
    assert res.all_qualifier == "-"


def test_spf_multiple_records_flagged():
    r = FakeResolver()
    r.add("dup.test", "TXT", ["v=spf1 -all", "v=spf1 ~all"])
    res = evaluate_spf("dup.test", r)
    assert res.multiple_records
    assert res.status == "permerror"


def test_spf_loop_detected():
    r = FakeResolver()
    r.add("a.test", "TXT", ["v=spf1 include:b.test -all"])
    r.add("b.test", "TXT", ["v=spf1 include:a.test -all"])
    res = evaluate_spf("a.test", r)
    assert any("loop" in e for e in res.errors)
