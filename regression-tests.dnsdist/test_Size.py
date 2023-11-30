#!/usr/bin/env python
import dns
from dnsdisttests import DNSDistTest

class TestSize(DNSDistTest):

    _payloadSize = 49
    _config_template = """
    addAction(PayloadSizeRule("smaller", %d), SpoofAction("192.0.2.1"))
    addAction(PayloadSizeRule("greater", %d), SpoofAction("192.0.2.2"))
    addAction(PayloadSizeRule("equal", %d), SpoofAction("192.0.2.3"))
    newServer{address="127.0.0.1:%d"}
    """
    _config_params = ['_payloadSize', '_payloadSize', '_payloadSize', '_testServerPort']

    def testPayloadSize(self):
        """
        Size: Check that PayloadSizeRule works
        """
        name = 'payload.size.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
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
            self.assertEqual(receivedResponse, expectedResponse)
