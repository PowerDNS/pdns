#!/usr/bin/env python
import extendederrors
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort

class TestBasics(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)

    local ffi = require("ffi")
    function ffiAction(dq)
      local extraText = 'Synthesized from Lua'
      ffi.C.dnsdist_ffi_dnsquestion_set_extended_dns_error(dq, 29, extraText, #extraText)
      local str = "192.0.2.2"
      local buf = ffi.new("char[?]", #str + 1)
      ffi.copy(buf, str)
      ffi.C.dnsdist_ffi_dnsquestion_set_result(dq, buf, #str)
      return DNSAction.Spoof
    end

    addAction("self-answered.ede.tests.powerdns.com.", SpoofAction("192.0.2.1"))
    addAction("self-answered-ffi.ede.tests.powerdns.com.", LuaFFIAction(ffiAction))
    addSelfAnsweredResponseAction("self-answered.ede.tests.powerdns.com.", SetExtendedDNSErrorResponseAction(42, "my self-answered extended error status"))
    addAction(AllRule(), SetExtendedDNSErrorAction(16, "my extended error status"))

    """

    def testExtendedErrorNoEDNS(self):
        """
        EDE: No EDNS
        """
        name = 'no-edns.ede.tests.powerdns.com.'
        # no EDNS
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
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
            self.assertEqual(query, receivedQuery)
            self.checkResponseNoEDNS(response, receivedResponse)

    def testExtendedErrorBackendResponse(self):
        """
        EDE: Backend response
        """
        name = 'backend-response.ede.tests.powerdns.com.'
        ede = extendederrors.ExtendedErrorOption(16, b'my extended error status')
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)

        backendResponse = dns.message.make_response(query)
        backendResponse.use_edns(edns=True, payload=4096, options=[])
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        backendResponse.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.use_edns(edns=True, payload=4096, options=[ede])
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, backendResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.checkMessageEDNS(expectedResponse, receivedResponse)

        # testing the cache
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageEDNS(expectedResponse, receivedResponse)

    def testExtendedErrorBackendResponse(self):
        """
        EDE: Backend response (DO)
        """
        name = 'backend-response-do.ede.tests.powerdns.com.'
        ede = extendederrors.ExtendedErrorOption(16, b'my extended error status')
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, want_dnssec=True)

        backendResponse = dns.message.make_response(query)
        backendResponse.use_edns(edns=True, payload=4096, options=[])
        backendResponse.want_dnssec(True)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        backendResponse.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.use_edns(edns=True, payload=4096, options=[ede])
        expectedResponse.want_dnssec(True)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, backendResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.checkMessageEDNS(expectedResponse, receivedResponse)

        # testing the cache
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageEDNS(expectedResponse, receivedResponse)

    def testExtendedErrorBackendResponseWithExistingEDE(self):
        """
        EDE: Backend response with existing EDE
        """
        name = 'backend-response-existing-ede.ede.tests.powerdns.com.'
        ede = extendederrors.ExtendedErrorOption(16, b'my extended error status')
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)

        backendResponse = dns.message.make_response(query)
        backendEDE = extendederrors.ExtendedErrorOption(3, b'Stale answer')
        backendResponse.use_edns(edns=True, payload=4096, options=[backendEDE])
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        backendResponse.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.use_edns(edns=True, payload=4096, options=[ede])
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, backendResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.checkMessageEDNS(expectedResponse, receivedResponse)

        # testing the cache
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageEDNS(expectedResponse, receivedResponse)

    def testExtendedErrorSelfAnswered(self):
        """
        EDE: Self-answered
        """
        name = 'self-answered.ede.tests.powerdns.com.'
        ede = extendederrors.ExtendedErrorOption(42, b'my self-answered extended error status')
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        # dnsdist sets RA = RD for self-generated responses
        query.flags &= ~dns.flags.RD

        expectedResponse = dns.message.make_response(query)
        expectedResponse.use_edns(edns=True, payload=1232, options=[ede])
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageEDNS(expectedResponse, receivedResponse)

    def testExtendedErrorLuaFFI(self):
        """
        EDE: Self-answered via Lua FFI
        """
        name = 'self-answered-ffi.ede.tests.powerdns.com.'
        ede = extendederrors.ExtendedErrorOption(29, b'Synthesized from Lua')
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        # dnsdist sets RA = RD for self-generated responses
        query.flags &= ~dns.flags.RD

        expectedResponse = dns.message.make_response(query)
        expectedResponse.use_edns(edns=True, payload=1232, options=[ede])
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.2')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageEDNS(expectedResponse, receivedResponse)
