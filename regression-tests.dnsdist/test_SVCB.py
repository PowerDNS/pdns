#!/usr/bin/env python
import dns
from dnsdisttests import DNSDistTest

class TestSVCB(DNSDistTest):

    _config_template = """
    local basicSVC = { newSVCRecordParameters(1, "dot.powerdns.com.", { mandatory={"port"}, alpn={"dot"}, noDefaultAlpn=true, port=853, ipv4hint={ "192.0.2.1" }, ipv6hint={ "2001:db8::1" } }),
                       newSVCRecordParameters(2, "doh.powerdns.com.", { mandatory={"port"}, alpn={"h2"}, port=443, ipv4hint={ "192.0.2.2" }, ipv6hint={ "2001:db8::2" }, key42="/dns-query{?dns}" })
                     }
    addAction(AndRule{QTypeRule(64), makeRule("basic.svcb.tests.powerdns.com.")}, SpoofSVCAction(basicSVC, {aa=true}))

    local noHintsSVC = { newSVCRecordParameters(1, "dot.powerdns.com.", { mandatory={"port"}, alpn={"dot"}, noDefaultAlpn=true, port=853}),
                         newSVCRecordParameters(2, "doh.powerdns.com.", { mandatory={"port"}, alpn={"h2"}, port=443, key42="/dns-query{?dns}" })
                     }
    addAction(AndRule{QTypeRule(64), makeRule("no-hints.svcb.tests.powerdns.com.")}, SpoofSVCAction(noHintsSVC, {aa=true}))

    local effectiveTargetSVC = { newSVCRecordParameters(1, ".", { mandatory={"port"}, alpn={ "dot" }, noDefaultAlpn=true, port=853, ipv4hint={ "192.0.2.1" }, ipv6hint={ "2001:db8::1" }}),
                                 newSVCRecordParameters(2, ".", { mandatory={"port"}, alpn={ "h2" }, port=443, ipv4hint={ "192.0.2.1" }, ipv6hint={ "2001:db8::1" }, key42="/dns-query{?dns}"})
                     }
    addAction(AndRule{QTypeRule(64), makeRule("effective-target.svcb.tests.powerdns.com.")}, SpoofSVCAction(effectiveTargetSVC, {aa=true}))

    local httpsSVC = { newSVCRecordParameters(1, ".", { mandatory={"port"}, alpn={ "h2" }, noDefaultAlpn=true, port=8002, ipv4hint={ "192.0.2.2" }, ipv6hint={ "2001:db8::2" }}) }
    addAction(AndRule{QTypeRule(65), makeRule("https.svcb.tests.powerdns.com.")}, SpoofSVCAction(httpsSVC))

    newServer{address="127.0.0.1:%s"}
    """

    def testBasic(self):
        """
        SVCB: Basic service binding
        """
        name = 'basic.svcb.tests.powerdns.com.'
        query = dns.message.make_query(name, 64, 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(len(receivedResponse.answer), 1)
            self.assertEqual(receivedResponse.answer[0].rdtype, 64)
            self.assertEqual(len(receivedResponse.additional), 4)
            self.assertEqual(receivedResponse.additional[0], dns.rrset.from_text("doh.powerdns.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.2'))
            self.assertEqual(receivedResponse.additional[1], dns.rrset.from_text("dot.powerdns.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'))
            self.assertEqual(receivedResponse.additional[2], dns.rrset.from_text("doh.powerdns.com.", 60, dns.rdataclass.IN, dns.rdatatype.AAAA, '2001:db8::2'))
            self.assertEqual(receivedResponse.additional[3], dns.rrset.from_text("dot.powerdns.com.", 60, dns.rdataclass.IN, dns.rdatatype.AAAA, '2001:db8::1'))

    def testNoHints(self):
        """
        SVCB: No hints
        """
        name = 'no-hints.svcb.tests.powerdns.com.'
        query = dns.message.make_query(name, 64, 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(len(receivedResponse.answer), 1)
            self.assertEqual(receivedResponse.answer[0].rdtype, 64)
            self.assertEqual(len(receivedResponse.additional), 0)

    def testEffectiveTarget(self):
        """
        SVCB: Effective target
        """
        name = 'effective-target.svcb.tests.powerdns.com.'
        query = dns.message.make_query(name, 64, 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(len(receivedResponse.answer), 1)
            self.assertEqual(receivedResponse.answer[0].rdtype, 64)
            self.assertEqual(len(receivedResponse.additional), 2)
            self.assertEqual(receivedResponse.additional[0], dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'))
            self.assertEqual(receivedResponse.additional[1], dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.AAAA, '2001:db8::1'))

    def testHTTPS(self):
        """
        SVCB: HTTPS
        """
        name = 'https.svcb.tests.powerdns.com.'
        query = dns.message.make_query(name, 65, 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(len(receivedResponse.answer), 1)
            self.assertEqual(receivedResponse.answer[0].rdtype, 65)
            self.assertEqual(len(receivedResponse.additional), 2)
            self.assertEqual(receivedResponse.additional[0], dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.2'))
            self.assertEqual(receivedResponse.additional[1], dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.AAAA, '2001:db8::2'))
