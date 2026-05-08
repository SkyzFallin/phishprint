from phishprint.core.mx import resolve_mx
from phishprint.core.resolver import FakeResolver


def test_mx_basic_no_asn():
    r = FakeResolver()
    r.add("x.test", "MX", ["20 b.x.test", "10 a.x.test"])
    r.add("a.x.test", "A", ["1.1.1.1"])
    r.add("b.x.test", "A", ["2.2.2.2"])
    res = resolve_mx("x.test", r, do_asn=False)
    assert [h.preference for h in res.hosts] == [10, 20]
    assert res.hosts[0].hostname == "a.x.test"
    assert res.hosts[0].ips == ["1.1.1.1"]


def test_mx_nxdomain():
    r = FakeResolver()
    r.add_nx("nope.test", "MX")
    res = resolve_mx("nope.test", r, do_asn=False)
    assert res.error == "NXDOMAIN"
    assert res.hosts == []


def test_mx_asn_lookup():
    r = FakeResolver()
    r.add("x.test", "MX", ["10 mail.x.test"])
    r.add("mail.x.test", "A", ["8.8.8.8"])
    # Cymru-format: "ASN | prefix | CC | registry | allocated"
    r.add("8.8.8.8.origin.asn.cymru.com", "TXT",
          ["15169 | 8.8.8.0/24 | US | arin | 1992-12-01"])
    r.add("AS15169.asn.cymru.com", "TXT",
          ["15169 | US | arin | 2000-03-30 | GOOGLE, US"])
    res = resolve_mx("x.test", r, do_asn=True)
    assert res.hosts[0].asn == 15169
    assert res.hosts[0].asn_org and "GOOGLE" in res.hosts[0].asn_org
