#!/usr/bin/env python
import dns
from dnsdisttests import DNSDistTest

class TestSpoofingSpoof(DNSDistTest):

    _config_template = """
    addAction(SuffixMatchNodeRule("spoofaction.spoofing.tests.powerdns.com."), SpoofAction({"192.0.2.1", "2001:DB8::1"}))
    addAction(SuffixMatchNodeRule("spoofaction-aa.spoofing.tests.powerdns.com."), SpoofAction({"192.0.2.1", "2001:DB8::1"}, {aa=true}))
    addAction(SuffixMatchNodeRule("spoofaction-ad.spoofing.tests.powerdns.com."), SpoofAction({"192.0.2.1", "2001:DB8::1"}, {ad=true}))
    addAction(SuffixMatchNodeRule("spoofaction-ra.spoofing.tests.powerdns.com."), SpoofAction({"192.0.2.1", "2001:DB8::1"}, {ra=true}))
    addAction(SuffixMatchNodeRule("spoofaction-nora.spoofing.tests.powerdns.com."), SpoofAction({"192.0.2.1", "2001:DB8::1"}, {ra=false}))
    addAction(SuffixMatchNodeRule("spoofaction-ttl.spoofing.tests.powerdns.com."), SpoofAction({"192.0.2.1", "2001:DB8::1"}, {ttl=1500}))
    addAction(SuffixMatchNodeRule("cnamespoofaction.spoofing.tests.powerdns.com."), SpoofCNAMEAction("cnameaction.spoofing.tests.powerdns.com."))
    addAction("multispoof.spoofing.tests.powerdns.com", SpoofAction({"192.0.2.1", "192.0.2.2", "2001:DB8::1", "2001:DB8::2"}))
    addAction(AndRule{SuffixMatchNodeRule("raw.spoofing.tests.powerdns.com"), QTypeRule(DNSQType.A)}, SpoofRawAction("\\192\\000\\002\\001"))
    addAction(AndRule{SuffixMatchNodeRule("raw.spoofing.tests.powerdns.com"), QTypeRule(DNSQType.TXT)}, SpoofRawAction("\\003aaa\\004bbbb\\011ccccccccccc"))
    addAction(AndRule{SuffixMatchNodeRule("raw.spoofing.tests.powerdns.com"), QTypeRule(DNSQType.SRV)}, SpoofRawAction("\\000\\000\\000\\000\\255\\255\\003srv\\008powerdns\\003com\\000", { aa=true, ttl=3600 }))
    addAction(AndRule{SuffixMatchNodeRule("rawchaos.spoofing.tests.powerdns.com"), QTypeRule(DNSQType.TXT), QClassRule(DNSClass.CHAOS)}, SpoofRawAction("\\005chaos"))
    addAction(AndRule{SuffixMatchNodeRule("multiraw.spoofing.tests.powerdns.com"), QTypeRule(DNSQType.TXT)}, SpoofRawAction({"\\003aaa\\004bbbb", "\\011ccccccccccc"}))
    addAction(AndRule{SuffixMatchNodeRule("multiraw.spoofing.tests.powerdns.com"), QTypeRule(DNSQType.A)}, SpoofRawAction({"\\192\\000\\002\\001", "\\192\\000\\002\\002"}))
    -- rfc8482
    addAction(AndRule{SuffixMatchNodeRule("raw-any.spoofing.tests.powerdns.com"), QTypeRule(DNSQType.ANY)}, SpoofRawAction("\\007rfc\\056\\052\\056\\050\\000", { typeForAny=DNSQType.HINFO }))
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
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)

    def testSpoofActionAWithEDNS(self):
        """
        Spoofing: Spoof A via Action (EDNS)

        Send an A query to "spoofaction.spoofing.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'spoofaction.spoofing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.use_edns(edns=True, payload=1232)
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
            self.checkMessageEDNSWithoutOptions(expectedResponse, receivedResponse)

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
            self.assertEqual(expectedResponse, receivedResponse)

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
            self.assertEqual(expectedResponse, receivedResponse)

    def testSpoofActionMultiA(self):
        """
        Spoofing: Spoof multiple IPv4 addresses

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
            self.assertEqual(expectedResponse, receivedResponse)

    def testSpoofActionMultiAAAA(self):
        """
        Spoofing: Spoof multiple IPv6 addresses

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
            self.assertEqual(expectedResponse, receivedResponse)

    def testSpoofActionMultiANY(self):
        """
        Spoofing: Spoof multiple addresses

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
            self.assertEqual(expectedResponse, receivedResponse)

    def testSpoofActionSetAA(self):
        """
        Spoofing: Spoof via Action, setting AA=1
        """
        name = 'spoofaction-aa.spoofing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags |= dns.flags.AA
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
            self.assertEqual(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

    def testSpoofActionSetAD(self):
        """
        Spoofing: Spoof via Action, setting AD=1
        """
        name = 'spoofaction-ad.spoofing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags |= dns.flags.AD
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
            self.assertEqual(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

    def testSpoofActionSetRA(self):
        """
        Spoofing: Spoof via Action, setting RA=1
        """
        name = 'spoofaction-ra.spoofing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags |= dns.flags.RA
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
            self.assertEqual(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

    def testSpoofActionSetNoRA(self):
        """
        Spoofing: Spoof via Action, setting RA=0
        """
        name = 'spoofaction-nora.spoofing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags &= ~dns.flags.RA
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
            self.assertEqual(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

    def testSpoofActionSetTTL(self):
        """
        Spoofing: Spoof via Action, setting the TTL to 1500
        """
        name = 'spoofaction-ttl.spoofing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags |= dns.flags.RA
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
            self.assertEqual(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 1500)

    def testSpoofRawAction(self):
        """
        Spoofing: Spoof a response from raw bytes
        """
        name = 'raw.spoofing.tests.powerdns.com.'

        # A
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags &= ~dns.flags.AA
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
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

        # A with EDNS
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.use_edns(edns=True, payload=1232)
        expectedResponse.flags &= ~dns.flags.AA
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
            self.checkMessageEDNSWithoutOptions(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

        # TXT
        query = dns.message.make_query(name, 'TXT', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags &= ~dns.flags.AA
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    '"aaa" "bbbb" "ccccccccccc"')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

        # SRV
        query = dns.message.make_query(name, 'SRV', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        # this one should have the AA flag set
        expectedResponse.flags |= dns.flags.AA
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.SRV,
                                    '0 0 65535 srv.powerdns.com.')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 3600)

    def testSpoofRawChaosAction(self):
        """
        Spoofing: Spoof a response from several raw bytes in QCLass CH
        """
        name = 'rawchaos.spoofing.tests.powerdns.com.'

        # TXT CH
        query = dns.message.make_query(name, 'TXT', 'CH')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags &= ~dns.flags.AA
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.CH,
                                    dns.rdatatype.TXT,
                                    '"chaos"')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

    def testSpoofRawANYAction(self):
        """
        Spoofing: Spoof a HINFO response for ANY queries
        """
        name = 'raw-any.spoofing.tests.powerdns.com.'

        query = dns.message.make_query(name, 'ANY', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags &= ~dns.flags.AA
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.HINFO,
                                    '"rfc8482" ""')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

    def testSpoofRawActionMulti(self):
        """
        Spoofing: Spoof a response from several raw bytes
        """
        name = 'multiraw.spoofing.tests.powerdns.com.'

        # A
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags &= ~dns.flags.AA
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
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

        # TXT
        query = dns.message.make_query(name, 'TXT', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags &= ~dns.flags.AA
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    '"aaa" "bbbb"', '"ccccccccccc"')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

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

    addAction(AndRule{SuffixMatchNodeRule("raw.spoofing.tests.powerdns.com"), QTypeRule(DNSQType.TXT)}, SpoofRawAction("\\003aaa\\004bbbb\\011ccccccccccc"))
    addAction(AndRule{SuffixMatchNodeRule("raw.spoofing.tests.powerdns.com"), QTypeRule(DNSQType.SRV)}, SpoofRawAction("\\000\\000\\000\\000\\255\\255\\003srv\\008powerdns\\003com\\000", { aa=true, ttl=3600 }))

    function spoofrawrule(dq)
        if dq.qtype == DNSQType.A then
             return DNSAction.SpoofRaw, "\\192\\000\\002\\001"
        elseif dq.qtype == DNSQType.TXT then
             return DNSAction.SpoofRaw, "\\003aaa\\004bbbb\\011ccccccccccc"
        elseif dq.qtype == DNSQType.SRV then
            dq.dh:setAA(true)
            return DNSAction.SpoofRaw, "\\000\\000\\000\\000\\255\\255\\003srv\\008powerdns\\003com\\000"
        end
        return DNSAction.None, ""
    end

    addAction("luaspoof1.spoofing.tests.powerdns.com.", LuaAction(spoof1rule))
    addAction("luaspoof2.spoofing.tests.powerdns.com.", LuaAction(spoof2rule))
    addAction("lua-raw.spoofing.tests.powerdns.com.", LuaAction(spoofrawrule))
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
            self.assertEqual(expectedResponse, receivedResponse)

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
            self.assertEqual(expectedResponse, receivedResponse)

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
            self.assertEqual(expectedResponse, receivedResponse)

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
            self.assertEqual(expectedResponse, receivedResponse)

    def testLuaSpoofRawAction(self):
        """
        Spoofing: Spoof a response from raw bytes via Lua
        """
        name = 'lua-raw.spoofing.tests.powerdns.com.'

        # A
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags &= ~dns.flags.AA
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
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

        # TXT
        query = dns.message.make_query(name, 'TXT', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags &= ~dns.flags.AA
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    '"aaa" "bbbb" "ccccccccccc"')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

        # SRV
        query = dns.message.make_query(name, 'SRV', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        # this one should have the AA flag set
        expectedResponse.flags |= dns.flags.AA
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.SRV,
                                    '0 0 65535 srv.powerdns.com.')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)
            # sorry, we can't set the TTL from the Lua API right now
            #self.assertEqual(receivedResponse.answer[0].ttl, 3600)

class TestSpoofingLuaSpoofMulti(DNSDistTest):

    _config_template = """
    function spoof1multirule(dq)
        if(dq.qtype==1) -- A
        then
                dq:spoof({ newCA("192.0.2.1"), newCA("192.0.2.2") })
                return DNSAction.HeaderModify
        elseif(dq.qtype == 28) -- AAAA
        then
				dq:spoof({ newCA("2001:DB8::1"), newCA("2001:DB8::2") })
                return DNSAction.HeaderModify
        else
                return DNSAction.None, ""
        end
    end

    function spoofrawmultirule(dq)
        if dq.qtype == DNSQType.A then
            dq:spoof({ "\\192\\000\\002\\001", "\\192\\000\\002\\002" })
            return DNSAction.HeaderModify
        elseif dq.qtype == DNSQType.TXT then
            dq:spoof({ "\\003aaa\\004bbbb", "\\011ccccccccccc" })
            return DNSAction.HeaderModify
        elseif dq.qtype == DNSQType.SRV then
            dq.dh:setAA(true)
            dq:spoof({ "\\000\\000\\000\\000\\255\\255\\004srv1\\008powerdns\\003com\\000","\\000\\000\\000\\000\\255\\255\\004srv2\\008powerdns\\003com\\000" })
            return DNSAction.HeaderModify
        end
        return DNSAction.None, ""
    end

    addAction("luaspoof1multi.spoofing.tests.powerdns.com.", LuaAction(spoof1multirule))
    addAction("lua-raw-multi.spoofing.tests.powerdns.com.", LuaAction(spoofrawmultirule))
    newServer{address="127.0.0.1:%s"}
    """

    def testLuaSpoofMultiA(self):
        """
        Spoofing: Spoofing multiple A via Lua dq:spoof

        Send an A query to "luaspoof1multi.spoofing.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'luaspoof1multi.spoofing.tests.powerdns.com.'
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
            self.assertEqual(expectedResponse, receivedResponse)

    def testLuaSpoofMultiAAAA(self):
        """
        Spoofing: Spoofing multiple AAAA via Lua dq:spoof

        Send an AAAA query to "luaspoof1.spoofing.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'luaspoof1multi.spoofing.tests.powerdns.com.'
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
            self.assertEqual(expectedResponse, receivedResponse)

    def testLuaSpoofMultiRawAction(self):
        """
        Spoofing: Spoof responses from raw bytes via Lua dq:spoof
        """
        name = 'lua-raw-multi.spoofing.tests.powerdns.com.'

        # A
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags &= ~dns.flags.AA
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
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

        # TXT
        query = dns.message.make_query(name, 'TXT', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags &= ~dns.flags.AA
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    '"aaa" "bbbb"', '"ccccccccccc"')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

        # SRV
        query = dns.message.make_query(name, 'SRV', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        # this one should have the AA flag set
        expectedResponse.flags |= dns.flags.AA
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.SRV,
                                    '0 0 65535 srv1.powerdns.com.', '0 0 65535 srv2.powerdns.com.')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)
            # sorry, we can't set the TTL from the Lua API right now
            #self.assertEqual(receivedResponse.answer[0].ttl, 3600)

class TestSpoofingLuaFFISpoofMulti(DNSDistTest):

    _config_template = """
    local ffi = require("ffi")

    function spoofrawmultirule(dq)
        local qtype = ffi.C.dnsdist_ffi_dnsquestion_get_qtype(dq)

        if qtype == DNSQType.A then
            local records = ffi.new("dnsdist_ffi_raw_value_t [2]")

            local str = "\\192\\000\\002\\001"
            records[0].size = #str
            records[0].value = str

            local str = "\\192\\000\\002\\255"
            records[1].value = str
            records[1].size = #str

            ffi.C.dnsdist_ffi_dnsquestion_spoof_raw(dq, records, 2)
            return DNSAction.HeaderModify
        elseif qtype == DNSQType.TXT then
            local records = ffi.new("dnsdist_ffi_raw_value_t [2]")

            local str = "\\033this text has a comma at the end,"
            records[0].size = #str
            records[0].value = str

            local str = "\\003aaa\\004bbbb"
            records[1].size = #str
            records[1].value = str

            ffi.C.dnsdist_ffi_dnsquestion_spoof_raw(dq, records, 2)
            return DNSAction.HeaderModify
        end

        return DNSAction.None, ""
    end

    addAction("lua-raw-multi.ffi-spoofing.tests.powerdns.com.", LuaFFIAction(spoofrawmultirule))
    newServer{address="127.0.0.1:%s"}
    """
    _verboseMode = True

    def testLuaSpoofMultiRawAction(self):
        """
        Spoofing via Lua FFI: Spoof responses from raw bytes via Lua FFI
        """
        name = 'lua-raw-multi.ffi-spoofing.tests.powerdns.com.'

        # A
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags &= ~dns.flags.AA
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1', '192.0.2.255')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

        # TXT
        query = dns.message.make_query(name, 'TXT', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags &= ~dns.flags.AA
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    '"this text has a comma at the end,"', '"aaa" "bbbb"')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)
            self.assertEqual(receivedResponse.answer[0].ttl, 60)

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
        self.assertEqual(expectedResponse1, receivedResponse)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEqual(expectedResponse2, receivedResponse)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponseAfterwards, receivedResponse)

class TestSpoofingLuaSpoofPacket(DNSDistTest):

    _config_template = """

    function spoofpacket(dq)
        if dq.qtype == DNSQType.A then
             return DNSAction.SpoofPacket, "\\000\\000\\129\\133\\000\\001\\000\\000\\000\\000\\000\\000\\014lua\\045raw\\045packet\\008spoofing\\005tests\\008powerdns\\003com\\000\\000\\001\\000\\001"
        end
        return DNSAction.None, ""
    end

    addAction("lua-raw-packet.spoofing.tests.powerdns.com.", LuaAction(spoofpacket))
    -- this answer has a EDNS OPT record, with a NSID set to dnsdist-1, and we intend to receive it!
    local rawResponse="\\000\\000\\129\\133\\000\\001\\000\\000\\000\\000\\000\\001\\019rule\\045lua\\045raw\\045packet\\008spoofing\\005tests\\008powerdns\\003com\\000\\000\\001\\000\\001\\000\\000\\041\\004\\208\\000\\000\\000\\000\\000\\013\\000\\003\\000\\009dnsdist\\045\\049"
    addAction(AndRule{QTypeRule(DNSQType.A), SuffixMatchNodeRule("rule-lua-raw-packet.spoofing.tests.powerdns.com.")}, SpoofPacketAction(rawResponse, string.len(rawResponse)))

    local ffi = require("ffi")

    function spoofpacketffi(dq)
        local qtype = ffi.C.dnsdist_ffi_dnsquestion_get_qtype(dq)
        if qtype == DNSQType.A then
            -- REFUSED answer
            local refusedResponse="\\000\\000\\129\\133\\000\\001\\000\\000\\000\\000\\000\\000\\014lua\\045raw\\045packet\\012ffi\\045spoofing\\005tests\\008powerdns\\003com\\000\\000\\001\\000\\001"

            ffi.C.dnsdist_ffi_dnsquestion_spoof_packet(dq, refusedResponse, string.len(refusedResponse))
            return DNSAction.HeaderModify
        end
        return DNSAction.None, ""
    end

    addAction("lua-raw-packet.ffi-spoofing.tests.powerdns.com.", LuaFFIAction(spoofpacketffi))
    newServer{address="127.0.0.1:%s"}
    """
    _verboseMode = True

    def testLuaSpoofPacket(self):
        """
        Spoofing via Lua FFI: Spoof raw response via Lua
        """
        for name in ('lua-raw-packet.spoofing.tests.powerdns.com.', 'rule-lua-raw-packet.spoofing.tests.powerdns.com.'):

            query = dns.message.make_query(name, 'A', 'IN')
            expectedResponse = dns.message.make_response(query)
            expectedResponse.flags |= dns.flags.RA
            expectedResponse.set_rcode(dns.rcode.REFUSED)

            if name == 'rule-lua-raw-packet.spoofing.tests.powerdns.com.':
                nsid_opt = dns.edns.GenericOption(dns.edns.NSID, 'dnsdist-1'.encode())
                expectedResponse.use_edns(options=[nsid_opt])

            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                (_, receivedResponse) = sender(query, response=None, useQueue=False)
                self.assertTrue(receivedResponse)
                self.assertEqual(expectedResponse, receivedResponse)
                if name == 'rule-lua-raw-packet.spoofing.tests.powerdns.com.':
                    self.checkMessageEDNS(expectedResponse, receivedResponse)

    def testLuaFFISpoofPacket(self):
        """
        Spoofing via Lua FFI: Spoof raw response via Lua FFI
        """
        name = 'lua-raw-packet.ffi-spoofing.tests.powerdns.com.'

        #
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags |= dns.flags.RA
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)
