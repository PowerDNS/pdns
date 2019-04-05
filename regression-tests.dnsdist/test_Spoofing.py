#!/usr/bin/env python
import dns
from dnsdisttests import DNSDistTest

class TestSpoofingSpoof(DNSDistTest):

    _config_template = """
    addAction(makeRule("spoofaction.spoofing.tests.powerdns.com."), SpoofAction("192.0.2.1", "2001:DB8::1"))
    addAction(makeRule("cnamespoofaction.spoofing.tests.powerdns.com."), SpoofCNAMEAction("cnameaction.spoofing.tests.powerdns.com."))
    addAction("multispoof.spoofing.tests.powerdns.com", SpoofAction({"192.0.2.1", "192.0.2.2", "2001:DB8::1", "2001:DB8::2"}))
    newServer{address="127.0.0.1:%s"}
    """

    def testSpoofActionA(self):
        """
        Spoofing: Spoof A via Action

        Send an A query to "spoofaction.spoofing.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'spoofaction.spoofing.tests.powerdns.com.'
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
            self.assertEquals(expectedResponse, receivedResponse)

    def testSpoofActionAAAA(self):
        """
        Spoofing: Spoof AAAA via Action

        Send an AAAA query to "spoofaction.spoofing.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'spoofaction.spoofing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '2001:DB8::1')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEquals(expectedResponse, receivedResponse)

    def testSpoofActionCNAME(self):
        """
        Spoofing: Spoof CNAME via Action

        Send an A query for "cnamespoofaction.spoofing.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'cnamespoofaction.spoofing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'cnameaction.spoofing.tests.powerdns.com.')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEquals(expectedResponse, receivedResponse)

    def testSpoofActionMultiA(self):
        """
        Spoofing: Spoof multiple IPv4 addresses via AddDomainSpoof

        Send an A query for "multispoof.spoofing.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'multispoof.spoofing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.2', '192.0.2.1')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEquals(expectedResponse, receivedResponse)

    def testSpoofActionMultiAAAA(self):
        """
        Spoofing: Spoof multiple IPv6 addresses via AddDomainSpoof

        Send an AAAA query for "multispoof.spoofing.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'multispoof.spoofing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '2001:DB8::1', '2001:DB8::2')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEquals(expectedResponse, receivedResponse)

    def testSpoofActionMultiANY(self):
        """
        Spoofing: Spoof multiple addresses via AddDomainSpoof

        Send an ANY query for "multispoof.spoofing.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'multispoof.spoofing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'ANY', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)

        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.2', '192.0.2.1')
        expectedResponse.answer.append(rrset)

        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '2001:DB8::1', '2001:DB8::2')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEquals(expectedResponse, receivedResponse)

class TestSpoofingLuaSpoof(DNSDistTest):

    _config_template = """
    function spoof1rule(dq)
        if(dq.qtype==1) -- A
        then
                return DNSAction.Spoof, "192.0.2.1,192.0.2.2"
        elseif(dq.qtype == 28) -- AAAA
        then
                return DNSAction.Spoof, "2001:DB8::1"
        else
                return DNSAction.None, ""
        end
    end
    function spoof2rule(dq)
        return DNSAction.Spoof, "spoofedcname.spoofing.tests.powerdns.com."
    end
    addAction("luaspoof1.spoofing.tests.powerdns.com.", LuaAction(spoof1rule))
    addAction("luaspoof2.spoofing.tests.powerdns.com.", LuaAction(spoof2rule))
    newServer{address="127.0.0.1:%s"}
    """

    def testLuaSpoofA(self):
        """
        Spoofing: Spoofing an A via Lua

        Send an A query to "luaspoof1.spoofing.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'luaspoof1.spoofing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1', '192.0.2.2')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEquals(expectedResponse, receivedResponse)

    def testLuaSpoofAAAA(self):
        """
        Spoofing: Spoofing an AAAA via Lua

        Send an AAAA query to "luaspoof1.spoofing.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'luaspoof1.spoofing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '2001:DB8::1')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEquals(expectedResponse, receivedResponse)

    def testLuaSpoofAWithCNAME(self):
        """
        Spoofing: Spoofing an A with a CNAME via Lua

        Send an A query to "luaspoof2.spoofing.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'luaspoof2.spoofing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'spoofedcname.spoofing.tests.powerdns.com.')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEquals(expectedResponse, receivedResponse)

    def testLuaSpoofAAAAWithCNAME(self):
        """
        Spoofing: Spoofing an AAAA with a CNAME via Lua

        Send an AAAA query to "luaspoof2.spoofing.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'luaspoof2.spoofing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'spoofedcname.spoofing.tests.powerdns.com.')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEquals(expectedResponse, receivedResponse)

class TestSpoofingLuaWithStatistics(DNSDistTest):

    _config_template = """
    function spoof1rule(dq)
        queriesCount = getStatisticsCounters()['queries']
        if(queriesCount == 1) then
                return DNSAction.Spoof, "192.0.2.1"
        elseif(queriesCount == 2) then
                return DNSAction.Spoof, "192.0.2.2"
        else
                return DNSAction.Spoof, "192.0.2.0"
        end
    end
    addAction("luaspoofwithstats.spoofing.tests.powerdns.com.", LuaAction(spoof1rule))
    newServer{address="127.0.0.1:%s"}
    """

    def testLuaSpoofBasedOnStatistics(self):
        """
        Spoofing: Spoofing an A via Lua based on statistics counters

        """
        name = 'luaspoofwithstats.spoofing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse1 = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        expectedResponse1.answer.append(rrset)
        expectedResponse2 = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.2')
        expectedResponse2.answer.append(rrset)
        expectedResponseAfterwards = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.0')
        expectedResponseAfterwards.answer.append(rrset)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse1, receivedResponse)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse2, receivedResponse)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEquals(expectedResponseAfterwards, receivedResponse)
