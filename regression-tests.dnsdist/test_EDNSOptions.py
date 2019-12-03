#!/usr/bin/env python
import dns
import clientsubnetoption
import cookiesoption
from dnsdisttests import DNSDistTest

class EDNSOptionsBase(DNSDistTest):
    _ednsTestFunction = """
    function testEDNSOptions(dq)
      local options = dq:getEDNSOptions()
      local qname = dq.qname:toString()

      if string.match(qname, 'noedns') then
        if next(options) ~= nil then
          return DNSAction.Spoof, "192.0.2.255"
        end
      end

      if string.match(qname, 'multiplecookies') then
        if options[EDNSOptionCode.COOKIE] == nil then
          return DNSAction.Spoof, "192.0.2.1"
        end
        if options[EDNSOptionCode.COOKIE]:count() ~= 2 then
          return DNSAction.Spoof, "192.0.2.2"
        end
        if options[EDNSOptionCode.COOKIE]:getValues()[1]:len() ~= 16 then
          return DNSAction.Spoof, "192.0.2.3"
        end
        if options[EDNSOptionCode.COOKIE]:getValues()[2]:len() ~= 16 then
          return DNSAction.Spoof, "192.0.2.4"
        end
      elseif string.match(qname, 'cookie') then
        if options[EDNSOptionCode.COOKIE] == nil then
          return DNSAction.Spoof, "192.0.2.1"
        end
        if options[EDNSOptionCode.COOKIE]:count() ~= 1 or options[EDNSOptionCode.COOKIE]:getValues()[1]:len() ~= 16 then
          return DNSAction.Spoof, "192.0.2.2"
        end
      end

      if string.match(qname, 'ecs4') then
        if options[EDNSOptionCode.ECS] == nil then
          return DNSAction.Spoof, "192.0.2.51"
        end
        if options[EDNSOptionCode.ECS]:count() ~= 1 or options[EDNSOptionCode.ECS]:getValues()[1]:len() ~= 8 then
          return DNSAction.Spoof, "192.0.2.52"
        end
      end

      if string.match(qname, 'ecs6') then
        if options[EDNSOptionCode.ECS] == nil then
          return DNSAction.Spoof, "192.0.2.101"
        end
        if options[EDNSOptionCode.ECS]:count() ~= 1 or options[EDNSOptionCode.ECS]:getValues()[1]:len() ~= 20 then
          return DNSAction.Spoof, "192.0.2.102"
        end
      end

      return DNSAction.None, ""

    end
    """

class TestEDNSOptions(EDNSOptionsBase):

    _config_template = """
    %s

    addAction(AllRule(), LuaAction(testEDNSOptions))

    newServer{address="127.0.0.1:%s"}
    """
    _config_params = ['_ednsTestFunction', '_testServerPort']

    def testWithoutEDNS(self):
        """
        EDNS Options: No EDNS
        """
        name = 'noedns.ednsoptions.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.255')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(receivedQuery, query)
            self.assertEquals(receivedResponse, response)

    def testCookie(self):
        """
        EDNS Options: Cookie
        """
        name = 'cookie.ednsoptions.tests.powerdns.com.'
        eco = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[eco])
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
            self.assertEquals(receivedQuery, query)
            self.assertEquals(receivedResponse, response)

    def testECS4(self):
        """
        EDNS Options: ECS4
        """
        name = 'ecs4.ednsoptions.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('1.2.3.4', 32)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
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
            self.assertEquals(receivedQuery, query)
            self.assertEquals(receivedResponse, response)

    def testECS6(self):
        """
        EDNS Options: ECS6
        """
        name = 'ecs6.ednsoptions.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('2001:DB8::1', 128)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
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
            self.assertEquals(receivedQuery, query)
            self.assertEquals(receivedResponse, response)

    def testECS6Cookie(self):
        """
        EDNS Options: Cookie + ECS6
        """
        name = 'cookie-ecs6.ednsoptions.tests.powerdns.com.'
        eco = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        ecso = clientsubnetoption.ClientSubnetOption('2001:DB8::1', 128)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso,eco])
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
            self.assertEquals(receivedQuery, query)
            self.assertEquals(receivedResponse, response)

    def testMultiCookiesECS6(self):
        """
        EDNS Options: Two Cookies + ECS6
        """
        name = 'multiplecookies-ecs6.ednsoptions.tests.powerdns.com.'
        eco1 = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        ecso = clientsubnetoption.ClientSubnetOption('2001:DB8::1', 128)
        eco2 = cookiesoption.CookiesOption(b'deadc0de', b'deadc0de')
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[eco1, ecso, eco2])
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
            self.assertEquals(receivedQuery, query)
            self.assertEquals(receivedResponse, response)

class TestEDNSOptionsAddingECS(EDNSOptionsBase):

    _config_template = """
    %s

    addAction(AllRule(), LuaAction(testEDNSOptions))

    newServer{address="127.0.0.1:%s", useClientSubnet=true}
    """
    _config_params = ['_ednsTestFunction', '_testServerPort']

    def testWithoutEDNS(self):
        """
        EDNS Options: No EDNS (adding ECS)
        """
        name = 'noedns.ednsoptions-ecs.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, options=[ecso], payload=512)
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
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseNoEDNS(response, receivedResponse)

    def testCookie(self):
        """
        EDNS Options: Cookie (adding ECS)
        """
        name = 'cookie.ednsoptions-ecs.tests.powerdns.com.'
        eco = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=512, options=[eco])
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, options=[eco,ecso], payload=512)
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
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery, 1)
            self.checkResponseEDNSWithoutECS(response, receivedResponse)

    def testECS4(self):
        """
        EDNS Options: ECS4 (adding ECS)
        """
        name = 'ecs4.ednsoptions-ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('1.2.3.4', 32)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        ecsoResponse = clientsubnetoption.ClientSubnetOption('1.2.3.4', 24, scope=24)
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=4096, options=[ecsoResponse])
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
            self.checkQueryEDNSWithECS(query, receivedQuery)
            self.checkResponseEDNSWithECS(response, receivedResponse)

    def testECS6(self):
        """
        EDNS Options: ECS6 (adding ECS)
        """
        name = 'ecs6.ednsoptions-ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('2001:DB8::1', 128)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        ecsoResponse = clientsubnetoption.ClientSubnetOption('2001:DB8::1', 128, scope=56)
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=4096, options=[ecsoResponse])
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
            self.checkQueryEDNSWithECS(query, receivedQuery)
            self.checkResponseEDNSWithECS(response, receivedResponse)

    def testECS6Cookie(self):
        """
        EDNS Options: Cookie + ECS6 (adding ECS)
        """
        name = 'cookie-ecs6.ednsoptions-ecs.tests.powerdns.com.'
        eco = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        ecso = clientsubnetoption.ClientSubnetOption('2001:DB8::1', 128)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso,eco])
        ecsoResponse = clientsubnetoption.ClientSubnetOption('2001:DB8::1', 128, scope=56)
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=4096, options=[ecsoResponse])
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
            self.checkQueryEDNSWithECS(query, receivedQuery, 1)
            self.checkResponseEDNSWithECS(response, receivedResponse)

    def testMultiCookiesECS6(self):
        """
        EDNS Options: Two Cookies + ECS6
        """
        name = 'multiplecookies-ecs6.ednsoptions.tests.powerdns.com.'
        eco1 = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        ecso = clientsubnetoption.ClientSubnetOption('2001:DB8::1', 128)
        eco2 = cookiesoption.CookiesOption(b'deadc0de', b'deadc0de')
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[eco1, ecso, eco2])
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
            self.assertEquals(receivedQuery, query)
            self.assertEquals(receivedResponse, response)

class TestEDNSOptionsLuaFFI(DNSDistTest):

    _config_template = """
    local ffi = require("ffi")

    function testEDNSOptions(dq)
      local options_ptr = ffi.new("const dnsdist_ednsoption_t *[1]")
      local ret_ptr_param = ffi.cast("const dnsdist_ednsoption_t **", options_ptr)

      local options_count = tonumber(ffi.C.dnsdist_ffi_dnsquestion_get_edns_options(dq, ret_ptr_param))

      local qname_ptr = ffi.new("const char *[1]")
      local qname_ptr_param = ffi.cast("const char **", qname_ptr)
      local qname_size = ffi.new("size_t[1]")
      local qname_size_param = ffi.cast("size_t*", qname_size)
      ffi.C.dnsdist_ffi_dnsquestion_get_qname_raw(dq, qname_ptr_param, qname_size_param)
      local qname = ffi.string(qname_ptr[0])

      if string.match(qname, 'noedns') then
        if options_count ~= 0 then
          local str = "192.0.2.255"
          local buf = ffi.new("char[?]", #str + 1)
          ffi.copy(buf, str)
          ffi.C.dnsdist_ffi_dnsquestion_set_result(dq, buf, #str)
          return DNSAction.Spoof
        end
      end

      local cookies_count = 0
      local ecs_count = 0
      local ecs_index = -1
      local first_cookie_index = -1
      local last_cookie_index = -1
      if options_count > 0 then
        for idx = 0, options_count-1 do
          if options_ptr[0][idx].optionCode == EDNSOptionCode.COOKIE then
            cookies_count = cookies_count + 1
            if first_cookie_index == -1 then
              first_cookie_index = idx
            end
            last_cookie_index = idx
          elseif options_ptr[0][idx].optionCode == EDNSOptionCode.ECS then
            ecs_count = ecs_count + 1
            ecs_index = idx
          end
        end
      end

      if string.match(qname, 'multiplecookies') then
        if cookies_count == 0 then
          local str = "192.0.2.1"
          local buf = ffi.new("char[?]", #str + 1)
          ffi.copy(buf, str)
          ffi.C.dnsdist_ffi_dnsquestion_set_result(dq, buf, #str)
          return DNSAction.Spoof
        end
        if cookies_count ~= 2 then
          local str = "192.0.2.2"
          local buf = ffi.new("char[?]", #str + 1)
          ffi.copy(buf, str)
          ffi.C.dnsdist_ffi_dnsquestion_set_result(dq, buf, #str)
          return DNSAction.Spoof
        end
        if options_ptr[0][first_cookie_index].len ~= 16 then
          local str = "192.0.2.3"
          local buf = ffi.new("char[?]", #str + 1)
          ffi.copy(buf, str)
          ffi.C.dnsdist_ffi_dnsquestion_set_result(dq, buf, #str)
          return DNSAction.Spoof
        end
        if options_ptr[0][last_cookie_index].len ~= 16 then
          local str = "192.0.2.4"
          local buf = ffi.new("char[?]", #str + 1)
          ffi.copy(buf, str)
          ffi.C.dnsdist_ffi_dnsquestion_set_result(dq, buf, #str)
          return DNSAction.Spoof
        end
      elseif string.match(qname, 'cookie') then

        if cookies_count == 0 then
          local str = "192.0.2.1"
          local buf = ffi.new("char[?]", #str + 1)
          ffi.copy(buf, str)
          ffi.C.dnsdist_ffi_dnsquestion_set_result(dq, buf, #str)
          return DNSAction.Spoof
        end
        if cookies_count ~= 1 or options_ptr[0][first_cookie_index].len ~= 16 then
          local str = "192.0.2.2"
          local buf = ffi.new("char[?]", #str + 1)
          ffi.copy(buf, str)
          ffi.C.dnsdist_ffi_dnsquestion_set_result(dq, buf, #str)
          return DNSAction.Spoof
        end
      end

      if string.match(qname, 'ecs4') then
        if ecs_count == 0 then
          local str = "192.0.2.51"
          local buf = ffi.new("char[?]", #str + 1)
          ffi.copy(buf, str)
          ffi.C.dnsdist_ffi_dnsquestion_set_result(dq, buf, #str)
          return DNSAction.Spoof
        end

        if ecs_count ~= 1 or options_ptr[0][ecs_index].len ~= 8 then
          local str = "192.0.2.52"
          local buf = ffi.new("char[?]", #str + 1)
          ffi.copy(buf, str)
          ffi.C.dnsdist_ffi_dnsquestion_set_result(dq, buf, #str)
          return DNSAction.Spoof
        end
      end

      if string.match(qname, 'ecs6') then
        if ecs_count == 0 then
          local str = "192.0.2.101"
          local buf = ffi.new("char[?]", #str + 1)
          ffi.copy(buf, str)
          ffi.C.dnsdist_ffi_dnsquestion_set_result(dq, buf, #str)
          return DNSAction.Spoof
        end
        if ecs_count ~= 1 or options_ptr[0][ecs_index].len ~= 20 then
          local str = "192.0.2.102"
          local buf = ffi.new("char[?]", #str + 1)
          ffi.copy(buf, str)
          ffi.C.dnsdist_ffi_dnsquestion_set_result(dq, buf, #str)
          return DNSAction.Spoof
        end
      end

      return DNSAction.None

    end

    addAction(AllRule(), LuaFFIAction(testEDNSOptions))

    newServer{address="127.0.0.1:%s"}
    """

    def testWithoutEDNSFFI(self):
        """
        EDNS Options: No EDNS (FFI)
        """
        name = 'noedns.ednsoptions.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.255')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(receivedQuery, query)
            self.assertEquals(receivedResponse, response)

    def testCookieFFI(self):
        """
        EDNS Options: Cookie (FFI)
        """
        name = 'cookie.ednsoptions.tests.powerdns.com.'
        eco = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[eco])
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
            self.assertEquals(receivedQuery, query)
            self.assertEquals(receivedResponse, response)

    def testECS4FFI(self):
        """
        EDNS Options: ECS4 (FFI)
        """
        name = 'ecs4.ednsoptions.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('1.2.3.4', 32)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
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
            self.assertEquals(receivedQuery, query)
            self.assertEquals(receivedResponse, response)

    def testECS6FFI(self):
        """
        EDNS Options: ECS6 (FFI)
        """
        name = 'ecs6.ednsoptions.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('2001:DB8::1', 128)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
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
            self.assertEquals(receivedQuery, query)
            self.assertEquals(receivedResponse, response)

    def testECS6CookieFFI(self):
        """
        EDNS Options: Cookie + ECS6 (FFI)
        """
        name = 'cookie-ecs6.ednsoptions.tests.powerdns.com.'
        eco = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        ecso = clientsubnetoption.ClientSubnetOption('2001:DB8::1', 128)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso,eco])
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
            self.assertEquals(receivedQuery, query)
            self.assertEquals(receivedResponse, response)

    def testMultiCookiesECS6FFI(self):
        """
        EDNS Options: Two Cookies + ECS6 (FFI)
        """
        name = 'multiplecookies-ecs6.ednsoptions.tests.powerdns.com.'
        eco1 = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        ecso = clientsubnetoption.ClientSubnetOption('2001:DB8::1', 128)
        eco2 = cookiesoption.CookiesOption(b'deadc0de', b'deadc0de')
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[eco1, ecso, eco2])
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
            self.assertEquals(receivedQuery, query)
            self.assertEquals(receivedResponse, response)
