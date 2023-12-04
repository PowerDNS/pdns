#!/usr/bin/env python
import dns
from dnsdisttests import DNSDistTest

class TestDeprecatedMakeRule(DNSDistTest):

    _config_template = """
    addAction(makeRule("make-rule-suffix.deprecated.tests.powerdns.com."), SpoofAction("192.0.2.1"))
    addAction("string-suffix.deprecated.tests.powerdns.com.", SpoofAction("192.0.2.2"))
    addAction({"list-of-string-suffixes.deprecated.tests.powerdns.com."}, SpoofAction("192.0.2.3"))

    newServer{address="127.0.0.1:%d"}
    """

    def testDeprecatedMakeRule(self):
        """
        Deprecated: makeRule
        """
        name = 'prefix.make-rule-suffix.deprecated.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testDeprecatedAddActionStringSuffix(self):
        """
        Deprecated: addAction string suffix
        """
        name = 'another.prefix.string-suffix.deprecated.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.2')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testDeprecatedAddActionListOfStringSuffixes(self):
        """
        Deprecated: addAction list of string suffixes
        """
        name = 'yet.another.prefix.list-of-string-suffixes.deprecated.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.3')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)
