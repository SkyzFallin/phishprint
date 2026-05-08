from phishprint.core.dkim import discover_dkim
from phishprint.core.resolver import FakeResolver


def test_dkim_finds_selector():
    r = FakeResolver()
    r.add("selector1._domainkey.x.test", "TXT",
          ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgK"])
    res = discover_dkim("x.test", r, selectors=["selector1", "selector2"])
    assert len(res.found) == 1
    s = res.found[0]
    assert s.selector == "selector1"
    assert s.has_public_key
    assert s.key_type == "rsa"
    assert res.observable


def test_dkim_revoked():
    r = FakeResolver()
    r.add("k1._domainkey.x.test", "TXT", ["v=DKIM1; k=rsa; p="])
    res = discover_dkim("x.test", r, selectors=["k1"])
    assert res.found and res.found[0].revoked
    assert not res.observable


def test_dkim_none_observable():
    r = FakeResolver()
    res = discover_dkim("x.test", r, selectors=["a", "b", "c"])
    assert not res.found
    assert not res.observable
    assert res.selectors_tried == 3
