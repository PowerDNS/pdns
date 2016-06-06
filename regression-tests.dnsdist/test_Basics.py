#!/usr/bin/env python
import unittest
import dns
import clientsubnetoption
from dnsdisttests import DNSDistTest

class TestBasics(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
    truncateTC(true)
    addAnyTCRule()
    addAction(RegexRule("evil[0-9]{4,}\\\\.regex\\\\.tests\\\\.powerdns\\\\.com$"), RCodeAction(dnsdist.REFUSED))
    mySMN = newSuffixMatchNode()
    mySMN:add(newDNSName("nameAndQtype.tests.powerdns.com."))
    addAction(AndRule{SuffixMatchNodeRule(mySMN), QTypeRule("TXT")}, RCodeAction(dnsdist.NOTIMP))
    addAction(makeRule("drop.test.powerdns.com."), DropAction())
    block=newDNSName("powerdns.org.")
    function blockFilter(dq)
        if(dq.qname:isPartOf(block))
        then
            print("Blocking *.powerdns.org")
            return true
        end
        return false
    end
    """

    def testDropped(self):
        """
        Basics: Dropped query

        Send an A query for drop.test.powerdns.com. domain,
        which is dropped by configuration. We expect
        no response.
        """
        name = 'drop.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, None)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, None)

    def testBlockedA(self):
        """
        Basics: Blocked A query

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
        Basics: A query with an ECS value
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
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testSimpleA(self):
        """
        Basics: A query without EDNS
        """
        name = 'simplea.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
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
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testAnyIsTruncated(self):
        """
        Basics: Truncate ANY query

        dnsdist is configured to reply with TC to ANY queries,
        send an ANY query and check the result.
        It should be truncated over UDP, not over TCP.
        """
        name = 'any.tests.powerdns.com.'
        query = dns.message.make_query(name, 'ANY', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags |= dns.flags.TC

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, expectedResponse)

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

    def testTruncateTC(self):
        """
        Basics: Truncate TC

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
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response.flags, receivedResponse.flags)
        self.assertEquals(response.question, receivedResponse.question)
        self.assertFalse(response.answer == receivedResponse.answer)
        self.assertEquals(len(receivedResponse.answer), 0)
        self.assertEquals(len(receivedResponse.authority), 0)
        self.assertEquals(len(receivedResponse.additional), 0)

    def testRegexReturnsRefused(self):
        """
        Basics: Refuse query matching regex

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
        self.assertEquals(receivedResponse, expectedResponse)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, expectedResponse)

    def testDomainAndQTypeReturnsNotImplemented(self):
        """
        Basics: NOTIMPL for specific name and qtype

        dnsdist is configured to reply 'not implemented' for query
        matching "nameAndQtype.tests.powerdns.com." AND qtype TXT.
        We send a TXT query for "nameAndQtype.powerdns.com."
        and check that the response is 'not implemented'.
        """
        name = 'nameAndQtype.tests.powerdns.com.'
        query = dns.message.make_query(name, 'TXT', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.NOTIMP)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, expectedResponse)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, expectedResponse)

    def testDomainWithoutQTypeIsNotAffected(self):
        """
        Basics: NOTIMPL qtype canary

        dnsdist is configured to reply 'not implemented' for query
        matching "nameAndQtype.tests.powerdns.com." AND qtype TXT.
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
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testOtherDomainANDQTypeIsNotAffected(self):
        """
        Basics: NOTIMPL qname canary

        dnsdist is configured to reply 'not implemented' for query
        matching "nameAndQtype.tests.powerdns.com." AND qtype TXT.
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
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testWrongResponse(self):
        """
        Basics: Unrelated response from the backend

        The backend send an unrelated answer over UDP, it should
        be discarded by dnsdist. It could happen if we wrap around
        maxOutstanding queries too quickly or have more than maxOustanding
        queries to a specific backend in the air over UDP,
        but does not really make sense over TCP.
        """
        name = 'query.unrelated.tests.powerdns.com.'
        unrelatedName = 'answer.unrelated.tests.powerdns.com.'
        query = dns.message.make_query(name, 'TXT', 'IN')
        unrelatedQuery = dns.message.make_query(unrelatedName, 'TXT', 'IN')
        unrelatedResponse = dns.message.make_response(unrelatedQuery)
        rrset = dns.rrset.from_text(unrelatedName,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    'nothing to see here')
        unrelatedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, unrelatedResponse)
        self.assertTrue(receivedQuery)
        self.assertEquals(receivedResponse, None)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, unrelatedResponse)
        self.assertTrue(receivedQuery)
        self.assertEquals(receivedResponse, None)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)


if __name__ == '__main__':
    unittest.main()
    exit(0)
