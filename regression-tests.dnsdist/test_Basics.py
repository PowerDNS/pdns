#!/usr/bin/env python
import unittest
import dns
import clientsubnetoption
from dnsdisttests import DNSDistTest

class TestBasics(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
    truncateTC(true)
    addAction(AndRule{QTypeRule(DNSQType.ANY), TCPRule(false)}, TCAction())
    addAction(RegexRule("evil[0-9]{4,}\\\\.regex\\\\.tests\\\\.powerdns\\\\.com$"), RCodeAction(DNSRCode.REFUSED))
    mySMN = newSuffixMatchNode()
    mySMN:add(newDNSName("nameAndQtype.tests.powerdns.com."))
    addAction(AndRule{SuffixMatchNodeRule(mySMN), QTypeRule("TXT")}, RCodeAction(DNSRCode.NOTIMP))
    addAction(makeRule("drop.test.powerdns.com."), DropAction())
    addAction(AndRule({QTypeRule(DNSQType.A),QNameRule("ds9a.nl")}), SpoofAction("1.2.3.4"))
    addAction(newDNSName("dnsname.addaction.powerdns.com."), RCodeAction(DNSRCode.REFUSED))
    addAction({newDNSName("dnsname-table1.addaction.powerdns.com."), newDNSName("dnsname-table2.addaction.powerdns.com.")}, RCodeAction(DNSRCode.REFUSED))
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
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
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
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
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

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
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
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags |= dns.flags.TC

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(expectedResponse.flags, receivedResponse.flags)
        self.assertEquals(expectedResponse.question, receivedResponse.question)
        self.assertFalse(response.answer == receivedResponse.answer)
        self.assertEquals(len(receivedResponse.answer), 0)
        self.assertEquals(len(receivedResponse.authority), 0)
        self.assertEquals(len(receivedResponse.additional), 0)
        self.checkMessageNoEDNS(expectedResponse, receivedResponse)

    def testTruncateTCEDNS(self):
        """
        Basics: Truncate TC with EDNS

        dnsdist is configured to truncate TC (default),
        we make the backend send responses
        with TC set and additional content,
        and check that the received response has been fixed.
        Note that the query and initial response had EDNS,
        so the final response should have it too.
        """
        name = 'atruncatetc.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, want_dnssec=True)
        response = dns.message.make_response(query)
        # force a different responder payload than the one in the query,
        # so we check that we don't just mirror it
        response.payload = 4242
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        response.answer.append(rrset)
        response.flags |= dns.flags.TC
        expectedResponse = dns.message.make_response(query)
        expectedResponse.payload = 4242
        expectedResponse.flags |= dns.flags.TC

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response.flags, receivedResponse.flags)
        self.assertEquals(response.question, receivedResponse.question)
        self.assertFalse(response.answer == receivedResponse.answer)
        self.assertEquals(len(receivedResponse.answer), 0)
        self.assertEquals(len(receivedResponse.authority), 0)
        self.assertEquals(len(receivedResponse.additional), 0)
        print(expectedResponse)
        print(receivedResponse)
        self.checkMessageEDNSWithoutOptions(expectedResponse, receivedResponse)
        self.assertFalse(receivedResponse.ednsflags & dns.flags.DO)
        self.assertEquals(receivedResponse.payload, 4242)

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

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, expectedResponse)

    def testQNameReturnsSpoofed(self):
        """
        Basics: test QNameRule and Spoof

        dnsdist is configured to reply 1.2.3.4 for A query for exactly ds9a.nl
        """
        name = 'ds9a.nl.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.NOERROR)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '1.2.3.4')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
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

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
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

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
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

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
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
        maxOutstanding queries too quickly or have more than maxOutstanding
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

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, unrelatedResponse)
            self.assertTrue(receivedQuery)
            self.assertEquals(receivedResponse, None)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)

    def testHeaderOnlyRefused(self):
        """
        Basics: Header-only refused response
        """
        name = 'header-only-refused-response.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)
        response.question = []

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(receivedResponse, response)

    def testHeaderOnlyNoErrorResponse(self):
        """
        Basics: Header-only NoError response should be dropped
        """
        name = 'header-only-noerror-response.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.question = []

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(receivedResponse, None)

    def testHeaderOnlyNXDResponse(self):
        """
        Basics: Header-only NXD response should be dropped
        """
        name = 'header-only-nxd-response.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)
        response.question = []

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(receivedResponse, None)

    def testAddActionDNSName(self):
        """
        Basics: test if addAction accepts a DNSName
        """
        name = 'dnsname.addaction.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, expectedResponse)

    def testAddActionDNSNames(self):
        """
        Basics: test if addAction accepts a table of DNSNames
        """
        for name in ['dnsname-table{}.addaction.powerdns.com.'.format(i) for i in range(1,2)]:
            query = dns.message.make_query(name, 'A', 'IN')
            expectedResponse = dns.message.make_response(query)
            expectedResponse.set_rcode(dns.rcode.REFUSED)

            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                (_, receivedResponse) = sender(query, response=None, useQueue=False)
                self.assertEquals(receivedResponse, expectedResponse)

