#!/usr/bin/env python
import dns

from dnsdisttests import DNSDistTest


class TestTCPOnly(DNSDistTest):
    _config_template = """
    newServer{address="127.0.0.1:%d", tcpOnly=true}
    """

    def testUDP(self):
        """
        TCP Only: UDP query is sent via TCP
        """
        name = "udp.tcp-only.test.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        expectedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, expectedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, expectedResponse)

        if "UDP Responder" in self._responsesCounter:
            self.assertEqual(self._responsesCounter["UDP Responder"], 0)
        if "TCP Responder" in self._responsesCounter:
            self.assertEqual(self._responsesCounter["TCP Responder"], 1)

    def testTCP(self):
        """
        TCP Only: TCP query is sent via TCP
        """
        name = "tcp.tcp-only.test.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        expectedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, expectedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, expectedResponse)
        if "UDP Responder" in self._responsesCounter:
            self.assertEqual(self._responsesCounter["UDP Responder"], 0)
        if "TCP Responder" in self._responsesCounter:
            self.assertEqual(self._responsesCounter["TCP Responder"], 1)
