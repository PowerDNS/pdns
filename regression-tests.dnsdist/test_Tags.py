#!/usr/bin/env python
import unittest
import dns
import clientsubnetoption
from dnsdisttests import DNSDistTest

class TestBasics(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}

    function lol(dq)
      return DNSAction.None, ""
    end
    addAction(AllRule(), LuaAction(lol))

    addAction("tag-me-dns-1.tags.tests.powerdns.com.", TagAction("dns", "value1"))
    addAction("tag-me-dns-2.tags.tests.powerdns.com.", TagAction("dns", "value2"))
    addAction("tag-me-response-1.tags.tests.powerdns.com.", TagAction("response", "value1"))
    addAction("tag-me-response-2.tags.tests.powerdns.com.", TagAction("response", "value2"))

    addAction(TagRule("not-dns"), SpoofAction("1.2.3.4"))
    addAction(TagRule("dns", "value1"), SpoofAction("1.2.3.50"))
    addAction(TagRule("dns"), SpoofAction("1.2.3.100"))

    function responseHandlerSetTC(dr)
      dr.dh:setTC(true)
      return DNSResponseAction.HeaderModify, ""
    end

    function responseHandlerUnsetQR(dr)
      dr.dh:setQR(false)
      return DNSResponseAction.HeaderModify, ""
    end

    addResponseAction(TagRule("not-dns"), DropResponseAction())
    addResponseAction(TagRule("response", "value1"), LuaResponseAction(responseHandlerSetTC))
    addResponseAction(TagRule("response", "no-match-value"), DropResponseAction())

    addResponseAction("tag-me-response-3.tags.tests.powerdns.com.", TagResponseAction("response-tag", "value"))
    addResponseAction(TagRule("response-tag"), LuaResponseAction(responseHandlerUnsetQR))
    """

    def testQuestionNoTag(self):
        """
        Tag: No match
        """
        name = 'no-match.tags.tests.powerdns.com.'
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

    def testQuestionMatchTagAndValue(self):
        """
        Tag: Name and value match
        """
        name = 'tag-me-dns-1.tags.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '1.2.3.50')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEquals(expectedResponse, receivedResponse)

    def testQuestionMatchTagOnly(self):
        """
        Tag: Name matches
        """
        name = 'tag-me-dns-2.tags.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '1.2.3.100')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEquals(expectedResponse, receivedResponse)

    def testResponseNoMatch(self):
        """
        Tag: Tag set on query does not match anything
        """
        name = 'tag-me-response-2.tags.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

    def testResponseMatchTagAndValue(self):
        """
        Tag: Tag and value set on query matches on response
        """
        name = 'tag-me-response-1.tags.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '1.2.3.100')
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.answer.append(rrset)
        # we will set TC if the tag matches
        expectedResponse.flags |= dns.flags.TC

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(expectedResponse, receivedResponse)

    def testResponseMatchResponseTagMatches(self):
        """
        Tag: Tag set on response matches
        """
        name = 'tag-me-response-3.tags.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '1.2.3.100')
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.answer.append(rrset)
        # we will set QR=0 if the tag matches
        expectedResponse.flags &= ~dns.flags.QR

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(expectedResponse, receivedResponse)
