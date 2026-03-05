#!/usr/bin/env python

from __future__ import print_function

import dns

from authtests import AuthTest


class CrossZoneResolveBase(AuthTest):
    _config_template = """
any-to-tcp=no
launch={backend}
edns-subnet-processing=yes
"""
    target_otherzone_ip = "192.0.2.2"
    target_subzone_ip = "192.0.2.3"
    _zones = {
        "example.org": """
example.org.                 3600 IN SOA   {soa}
example.org.                 3600 IN NS    ns1.example.org.
example.org.                 3600 IN NS    ns2.example.org.
ns1.example.org.             3600 IN A     {prefix}.10
ns2.example.org.             3600 IN A     {prefix}.11
subzone.example.org.         3600 IN NS    ns1.example.org.
subzone.example.org.         3600 IN NS    ns2.example.org.
cname-otherzone.example.org. 3600 IN CNAME target.example.com.
cname-subzone.example.org.   3600 IN CNAME target.subzone.example.org.
        """,
        "subzone.example.org": """
subzone.example.org.         3600 IN SOA   {soa}
target.subzone.example.org.  3600 IN A     """
        + target_subzone_ip,
        "example.com": """
example.com.                 3600 IN SOA   {soa}
example.com.                 3600 IN NS    ns1.example.com.
example.com.                 3600 IN NS    ns2.example.com.
ns1.example.com.             3600 IN A     {prefix}.10
ns2.example.com.             3600 IN A     {prefix}.11
target.example.com.          3600 IN A     """
        + target_otherzone_ip,
    }


class TestCrossZoneResolveOff(CrossZoneResolveBase):
    _config_template = (
        CrossZoneResolveBase._config_template
        + """
resolve-across-zones=no
"""
    )

    def impl_cname_only_test(self, qname, target):
        expected_cname = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, "CNAME", target)
        query = dns.message.make_query(qname, "A")
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        assert res.answer == [expected_cname]
        assert res.additional == []

    def testCNAMEOtherZone(self):
        self.impl_cname_only_test("cname-otherzone.example.org.", "target.example.com.")

    def testCNAMESubZone(self):
        self.impl_cname_only_test("cname-subzone.example.org.", "target.subzone.example.org.")


class TestCrossZoneResolveOn(CrossZoneResolveBase):
    _config_template = (
        CrossZoneResolveBase._config_template
        + """
resolve-across-zones=yes
"""
    )

    def impl_cname_and_target_test(self, qname, target, target_ip):
        expected_cname = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, "CNAME", target)
        expected_target = dns.rrset.from_text(target, 0, dns.rdataclass.IN, "A", target_ip)
        query = dns.message.make_query(qname, "A")
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        assert res.answer == [expected_cname, expected_target]
        assert res.additional == []

    def testCNAMEOtherZone(self):
        self.impl_cname_and_target_test(
            "cname-otherzone.example.org.",
            "target.example.com.",
            self.target_otherzone_ip,
        )

    def testCNAMESubZone(self):
        self.impl_cname_and_target_test(
            "cname-subzone.example.org.",
            "target.subzone.example.org.",
            self.target_subzone_ip,
        )
