#!/usr/bin/env python
import clientsubnetoption
import dns
import unittest
from dnsdisttests import DNSDistTest

class TestBasics(DNSDistTest):

    def testBlockedA(self):
        """
        Send an A query for the powerdns.org domain,
        which is blocked by configuration. We expect
        no response.
        """
        name = 'blockeda.tests.powerdns.org.'
        query = dns.message.make_query(name, 'A', 'IN')
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=2.0)
        self.assertEquals(receivedResponse, None)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False, timeout=2.0)
        self.assertEquals(receivedResponse, None)

    def testAWithECS(self):
        """
        Send an A query with an ECS value.
        """
        name = 'awithecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('1.2.3.4')
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, options=[ecso])
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testSimpleA(self):
        """
        Send a simple A query without EDNS.
        """
        name = 'simplea.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text('simplea.tests.powerdns.com.',
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)


if __name__ == '__main__':
    unittest.main()
    exit(0)
