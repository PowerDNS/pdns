#!/usr/bin/env python
import dns
from dnsdisttests import DNSDistTest

class TestRE2(DNSDistTest):
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    -- keep in mind this is a FULL match, as if the expression started with
    -- a '^' and ended with a '$'
    addAction(RE2Rule("re2\\\\.tests\\\\.powerdns\\\\.com"), RCodeAction(DNSRCode.REFUSED))
    """

    def testMatch(self):
        """
        RE2: Match
        """
        name = 're2.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

    def testNoMatch(self):
        """
        RE2: No match
        """
        name = 'sub.re2.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=response)
            receivedQuery.id = query.id
            self.assertEqual(receivedQuery, query)
            self.assertEqual(receivedResponse, response)
