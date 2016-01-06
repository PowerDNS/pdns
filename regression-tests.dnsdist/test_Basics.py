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
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, None)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
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

    def testAnyIsTruncated(self):
        """
        dnsdist is configured to reply with TC to ANY queries,
        send an ANY query and check the result.
        """
        name = 'any.tests.powerdns.com.'
        query = dns.message.make_query(name, 'ANY', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags |= dns.flags.TC

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        receivedResponse.id = expectedResponse.id
        self.assertEquals(receivedResponse, expectedResponse)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        receivedResponse.id = expectedResponse.id
        self.assertEquals(receivedResponse, expectedResponse)

    def testTruncateTC(self):
        """
        dnsdist is configured to truncate TC (default),
        we make the backend send responses
        with TC set and additional content,
        and check that the received response has been fixed.
        """
        name = 'atruncatetc.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        response.answer.append(rrset)
        response.flags |= dns.flags.TC

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response.flags, receivedResponse.flags)
        self.assertEquals(response.question, receivedResponse.question)
        self.assertFalse(response.answer == receivedResponse.answer)
        self.assertEquals(len(receivedResponse.answer), 0)
        self.assertEquals(len(receivedResponse.authority), 0)
        self.assertEquals(len(receivedResponse.additional), 0)

    def testRegexReturnsRefused(self):
        """
        dnsdist is configured to reply 'refused' for query
        matching "evil[0-9]{4,}\\.regex\\.tests\\.powerdns\\.com$".
        We send a query for evil4242.powerdns.com
        and check that the response is "refused".
        """
        name = 'evil4242.regex.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        receivedResponse.id = expectedResponse.id
        self.assertEquals(receivedResponse, expectedResponse)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        receivedResponse.id = expectedResponse.id
        self.assertEquals(receivedResponse, expectedResponse)

    def testDomainAndQTypeReturnsNotImplemented(self):
        """
        dnsdist is configured to reply 'not implemented' for query
        matching "nameAndQtype.tests.powerdns.com." AND qtype TXT/
        We send a TXT query for "nameAndQtype.powerdns.com."
        and check that the response is 'not implemented'.
        """
        name = 'nameAndQtype.tests.powerdns.com.'
        query = dns.message.make_query(name, 'TXT', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.NOTIMP)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        receivedResponse.id = expectedResponse.id
        self.assertEquals(receivedResponse, expectedResponse)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        receivedResponse.id = expectedResponse.id
        self.assertEquals(receivedResponse, expectedResponse)

    def testDomainWithoutQTypeIsNotAffected(self):
        """
        dnsdist is configured to reply 'not implemented' for query
        matching "nameAndQtype.tests.powerdns.com." AND qtype TXT/
        We send a A query for "nameAndQtype.tests.powerdns.com."
        and check that the response is OK.
        """
        name = 'nameAndQtype.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
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

    def testOtherDomainANDQTypeIsNotAffected(self):
        """
        dnsdist is configured to reply 'not implemented' for query
        matching "nameAndQtype.tests.powerdns.com." AND qtype TXT/
        We send a TXT query for "OtherNameAndQtype.tests.powerdns.com."
        and check that the response is OK.
        """
        name = 'OtherNameAndQtype.tests.powerdns.com.'
        query = dns.message.make_query(name, 'TXT', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    'nothing to see here')
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
