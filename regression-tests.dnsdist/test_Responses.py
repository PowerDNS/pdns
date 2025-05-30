#!/usr/bin/env python
from datetime import datetime, timedelta
import time
import dns
import cookiesoption
from dnsdisttests import DNSDistTest

class TestResponseRuleNXDelayed(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
    addResponseAction(RCodeRule(DNSRCode.NXDOMAIN), DelayResponseAction(1000))
    """

    def testNXDelayed(self):
        """
        Responses: Delayed on NXDomain

        Send an A query to "delayed.responses.tests.powerdns.com.",
        check that the response delay is longer than 1000 ms
        for a NXDomain response over UDP, shorter for a NoError one.
        """
        name = 'delayed.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        # NX over UDP
        response.set_rcode(dns.rcode.NXDOMAIN)
        begin = datetime.now()
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        end = datetime.now()
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.assertTrue((end - begin) > timedelta(0, 1))

        # NoError over UDP
        response.set_rcode(dns.rcode.NOERROR)
        begin = datetime.now()
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        end = datetime.now()
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.assertTrue((end - begin) < timedelta(0, 1))

        # NX over TCP
        response.set_rcode(dns.rcode.NXDOMAIN)
        begin = datetime.now()
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        end = datetime.now()
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.assertTrue((end - begin) < timedelta(0, 1))

class TestResponseRuleERCode(DNSDistTest):

    _extraStartupSleep = 1
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    addResponseAction(ERCodeRule(DNSRCode.BADVERS), DelayResponseAction(1000))
    """

    def testBADVERSDelayed(self):
        """
        Responses: Delayed on BADVERS

        Send an A query to "delayed.responses.tests.powerdns.com.",
        check that the response delay is longer than 1000 ms
        for a BADVERS response over UDP, shorter for BADKEY and NoError.
        """
        name = 'delayed.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.use_edns(edns=True)

        # BADVERS over UDP
        # BADVERS == 16, so rcode==0, ercode==1
        response.set_rcode(dns.rcode.BADVERS)
        begin = datetime.now()
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        end = datetime.now()
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.assertTrue((end - begin) > timedelta(0, 1))

        # BADKEY (17, an ERCode) over UDP
        response.set_rcode(17)
        begin = datetime.now()
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        end = datetime.now()
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.assertTrue((end - begin) < timedelta(0, 1))

        # NoError (non-ERcode, basic RCode bits match BADVERS) over UDP
        response.set_rcode(dns.rcode.NOERROR)
        begin = datetime.now()
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        end = datetime.now()
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.assertTrue((end - begin) < timedelta(0, 1))

class TestResponseRuleQNameDropped(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
    addResponseAction("drop.responses.tests.powerdns.com.", DropResponseAction())
    """

    def testDropped(self):
        """
        Responses: Dropped on QName

        Send an A query to "drop.responses.tests.powerdns.com.",
        check that the response (not the query) is dropped.
        """
        name = 'drop.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, None)

    def testNotDropped(self):
        """
        Responses: NOT Dropped on QName

        Send an A query to "dontdrop.responses.tests.powerdns.com.",
        check that the response is not dropped.
        """
        name = 'dontdrop.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

class TestResponseRuleQNameAllowed(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
    addResponseAction("allow.responses.tests.powerdns.com.", AllowResponseAction())
    addResponseAction(AllRule(), DropResponseAction())
    """

    def testAllowed(self):
        """
        Responses: Allowed on QName

        Send an A query to "allow.responses.tests.powerdns.com.",
        check that the response is allowed.
        """
        name = 'allow.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

    def testNotAllowed(self):
        """
        Responses: Not allowed on QName

        Send an A query to "dontallow.responses.tests.powerdns.com.",
        check that the response is dropped.
        """
        name = 'dontallow.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, None)

class TestResponseRuleEditTTL(DNSDistTest):

    _ttl = 5
    _config_params = ['_testServerPort', '_ttl']
    _config_template = """
    newServer{address="127.0.0.1:%s"}

    function editTTLCallback(section, class, type, ttl)
      return %d
    end

    function editTTLFunc(dr)
      dr:editTTLs(editTTLCallback)
      return DNSAction.None, ""
    end

    addResponseAction(AllRule(), LuaResponseAction(editTTLFunc))
    """

    def testTTLEdited(self):
        """
        Responses: Alter the TTLs
        """
        name = 'editttl.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)
            self.assertNotEqual(response.answer[0].ttl, receivedResponse.answer[0].ttl)
            self.assertEqual(receivedResponse.answer[0].ttl, self._ttl)

class TestResponseRuleLimitTTL(DNSDistTest):

    _lowttl = 60
    _defaulttl = 3600
    _highttl = 18000
    _config_params = ['_lowttl', '_highttl', '_testServerPort']
    _config_template = """
    local ffi = require("ffi")
    local lowttl = %d
    local highttl = %d

    function luaFFISetMinTTL(dr)
      ffi.C.dnsdist_ffi_dnsresponse_set_min_ttl(dr, highttl)
      return DNSResponseAction.None, ""
    end
    function luaFFISetMaxTTL(dr)
      ffi.C.dnsdist_ffi_dnsresponse_set_max_ttl(dr, lowttl)
      return DNSResponseAction.None, ""
    end

    newServer{address="127.0.0.1:%s"}

    addResponseAction("min.responses.tests.powerdns.com.", SetMinTTLResponseAction(highttl))
    addResponseAction("max.responses.tests.powerdns.com.", SetMaxTTLResponseAction(lowttl))
    addResponseAction("ffi.min.limitttl.responses.tests.powerdns.com.", LuaFFIResponseAction(luaFFISetMinTTL))
    addResponseAction("ffi.max.limitttl.responses.tests.powerdns.com.", LuaFFIResponseAction(luaFFISetMaxTTL))
    """

    def testLimitTTL(self):
        """
        Responses: Alter the TTLs via Limiter
        """
        name = 'min.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)
            self.assertNotEqual(response.answer[0].ttl, receivedResponse.answer[0].ttl)
            self.assertEqual(receivedResponse.answer[0].ttl, self._highttl)

        name = 'max.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)
            self.assertNotEqual(response.answer[0].ttl, receivedResponse.answer[0].ttl)
            self.assertEqual(receivedResponse.answer[0].ttl, self._lowttl)

    def testLimitTTLFFI(self):
        """
        Responses: Alter the TTLs via Limiter
        """
        name = 'ffi.min.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)
            self.assertNotEqual(response.answer[0].ttl, receivedResponse.answer[0].ttl)
            self.assertEqual(receivedResponse.answer[0].ttl, self._highttl)

        name = 'ffi.max.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)
            self.assertNotEqual(response.answer[0].ttl, receivedResponse.answer[0].ttl)
            self.assertEqual(receivedResponse.answer[0].ttl, self._lowttl)

class TestSetReducedTTL(DNSDistTest):

    _percentage = 42
    _initialTTL = 100
    _config_params = ['_percentage', '_testServerPort']
    _config_template = """
    addResponseAction(AllRule(), SetReducedTTLResponseAction(%d))
    newServer{address="127.0.0.1:%s"}
    """

    def testLimitTTL(self):
        """
        Responses: Reduce TTL to 42%
        """
        name = 'reduced-ttl.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    self._initialTTL,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)
            self.assertNotEqual(response.answer[0].ttl, receivedResponse.answer[0].ttl)
            self.assertEqual(receivedResponse.answer[0].ttl, self._percentage)

class TestResponseLuaActionReturnSyntax(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
    function customDelay(dr)
      return DNSResponseAction.Delay, "1000"
    end
    function customDrop(dr)
      return DNSResponseAction.Drop
    end
    addResponseAction("drop.responses.tests.powerdns.com.", LuaResponseAction(customDrop))
    addResponseAction(RCodeRule(DNSRCode.NXDOMAIN), LuaResponseAction(customDelay))
    """

    def testResponseActionDelayed(self):
        """
        Responses: Delayed via LuaResponseAction

        Send an A query to "delayed.responses.tests.powerdns.com.",
        check that the response delay is longer than 1000 ms
        for a NXDomain response over UDP, shorter for a NoError one.
        """
        name = 'delayed.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        # NX over UDP
        response.set_rcode(dns.rcode.NXDOMAIN)
        begin = datetime.now()
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        end = datetime.now()
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.assertTrue((end - begin) > timedelta(0, 1))

    def testDropped(self):
        """
        Responses: Dropped via user defined LuaResponseAction

        Send an A query to "drop.responses.tests.powerdns.com.",
        check that the response (not the query) is dropped.
        """
        name = 'drop.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, None)

class TestResponseClearRecordsType(DNSDistTest):

    _config_params = ['_testServerPort']
    _config_template = """
    local ffi = require("ffi")

    function luafct(dr)
      ffi.C.dnsdist_ffi_dnsresponse_clear_records_type(dr, DNSQType.AAAA)
      return DNSResponseAction.HeaderModify, ""
    end

    newServer{address="127.0.0.1:%s"}

    addResponseAction("ffi.clear-records-type.responses.tests.powerdns.com.", LuaFFIResponseAction(luafct))
    addResponseAction("clear-records-type.responses.tests.powerdns.com.", ClearRecordTypesResponseAction(DNSQType.AAAA))
    """

    def testClearedFFI(self):
        """
        Responses: Removes records of a given type (FFI API)
        """
        name = 'ffi.clear-records-type.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)
        expectedResponse.answer.append(rrset)
        rrset = dns.rrset.from_text(name,
                                    3660,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '2001:DB8::1', '2001:DB8::2')
        response.answer.append(rrset)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(expectedResponse, receivedResponse)

    def testCleared(self):
        """
        Responses: Removes records of a given type
        """
        name = 'clear-records-type.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)
        expectedResponse.answer.append(rrset)
        rrset = dns.rrset.from_text(name,
                                    3660,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '2001:DB8::1', '2001:DB8::2')
        response.answer.append(rrset)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(expectedResponse, receivedResponse)

class TestResponseRewriteServFail(DNSDistTest):

    _config_params = ['_testServerPort']
    _config_template = """
    newServer{address="127.0.0.1:%s"}

    function rewriteServFail(dq)
      if dq.rcode == DNSRCode.SERVFAIL then
         dq.rcode = DNSRCode.NOERROR
        return DNSResponseAction.HeaderModify
      end
      return DNSResponse.None
    end
    addResponseAction(AndRule({QTypeRule(DNSQType.AAAA),RCodeRule(DNSRCode.SERVFAIL)}), LuaResponseAction(rewriteServFail))
    """

    def testRewriteServFail(self):
        """
        Responses: Rewrite AAAA ServFails as NoError (don't ask)
        """
        name = 'rewrite-servfail.responses.tests.powerdns.com.'

        query = dns.message.make_query(name, 'AAAA', 'IN')
        response = dns.message.make_response(query)
        expectedResponse = dns.message.make_response(query)

        response.set_rcode(dns.rcode.SERVFAIL)
        expectedResponse.set_rcode(dns.rcode.NOERROR)

        rrset = dns.rrset.from_text(name,
                                    3660,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '2001:DB8::1', '2001:DB8::2')
        response.answer.append(rrset)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(expectedResponse, receivedResponse)

        # but ServFail for a different type should stay the same
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.SERVFAIL)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

class TestAdvancedSetEDNSOptionResponseAction(DNSDistTest):
    _config_template = """
    addResponseAction(AllRule(), SetEDNSOptionResponseAction(10, "deadbeefdeadc0de"))
    newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedSetEDNSOptionResponse(self):
        """
        Responses: Set EDNS Option in response
        """
        name = 'setednsoptionresponse.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=512)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        eco = cookiesoption.CookiesOption(b'deadbeef', b'deadc0de')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.use_edns(edns=True, payload=512, options=[eco])
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.checkResponseEDNSWithoutECS(expectedResponse, receivedResponse, 1)

    def testAdvancedSetEDNSOptionResponseOverwrite(self):
        """
        Responses: Set EDNS Option in response overwrites existing option
        """
        name = 'setednsoptionresponse-overwrite.responses.tests.powerdns.com.'
        initialECO = cookiesoption.CookiesOption(b'aaaaaaaa', b'bbbbbbbb')
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=512, options=[initialECO])
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        overWrittenECO = cookiesoption.CookiesOption(b'deadbeef', b'deadc0de')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.use_edns(edns=True, payload=512, options=[overWrittenECO])
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.checkResponseEDNSWithoutECS(expectedResponse, receivedResponse, 1)

    def testAdvancedSetEDNSOptionResponseWithDOSet(self):
        """
        Responses: Set EDNS Option in response (DO bit set)
        """
        name = 'setednsoptionresponse-do.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, want_dnssec=True, payload=4096)
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=1024)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        eco = cookiesoption.CookiesOption(b'deadbeef', b'deadc0de')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.use_edns(edns=True, payload=1024, options=[eco])
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.checkResponseEDNSWithoutECS(expectedResponse, receivedResponse, 1)
