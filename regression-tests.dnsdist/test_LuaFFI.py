#!/usr/bin/env python

import unittest
import dns
from dnsdisttests import DNSDistTest

class TestAdvancedLuaFFI(DNSDistTest):

    _config_template = """
    local ffi = require("ffi")

    local expectingUDP = true

    function luaffirulefunction(dq)
      local qtype = ffi.C.dnsdist_ffi_dnsquestion_get_qtype(dq)
      if qtype ~= DNSQType.A and qtype ~= DNSQType.SOA then
        print('invalid qtype')
        return false
      end

      local qclass = ffi.C.dnsdist_ffi_dnsquestion_get_qclass(dq)
      if qclass ~= DNSClass.IN then
        print('invalid qclass')
        return false
      end

      local ret_ptr = ffi.new("char *[1]")
      local ret_ptr_param = ffi.cast("const char **", ret_ptr)
      local ret_size = ffi.new("size_t[1]")
      local ret_size_param = ffi.cast("size_t*", ret_size)
      ffi.C.dnsdist_ffi_dnsquestion_get_qname_raw(dq, ret_ptr_param, ret_size_param)
      if ret_size[0] ~= 36 then
        print('invalid length for the qname ')
        print(ret_size[0])
        return false
      end

      local expectedQname = string.char(6)..'luaffi'..string.char(8)..'advanced'..string.char(5)..'tests'..string.char(8)..'powerdns'..string.char(3)..'com'
      if ffi.string(ret_ptr[0]) ~= expectedQname then
        print('invalid qname')
        print(ffi.string(ret_ptr[0]))
        return false
      end

      local rcode = ffi.C.dnsdist_ffi_dnsquestion_get_rcode(dq)
      if rcode ~= 0 then
        print('invalid rcode')
        return false
      end

      local opcode = ffi.C.dnsdist_ffi_dnsquestion_get_opcode(dq)
      if qtype == DNSQType.A and opcode ~= DNSOpcode.Query then
        print('invalid opcode')
        return false
      elseif qtype == DNSQType.SOA and opcode ~= DNSOpcode.Update then
        print('invalid opcode')
        return false
      end

      local tcp = ffi.C.dnsdist_ffi_dnsquestion_get_tcp(dq)
      if expectingUDP == tcp then
        print('invalid tcp')
        return false
      end
      expectingUDP = expectingUDP == false

      local dnssecok = ffi.C.dnsdist_ffi_dnsquestion_get_do(dq)
      if dnssecok ~= false then
        print('invalid DNSSEC OK')
        return false
      end

      local len = ffi.C.dnsdist_ffi_dnsquestion_get_len(dq)
      if len ~= 52 then
        print('invalid length')
        print(len)
        return false
      end

      local tag = ffi.C.dnsdist_ffi_dnsquestion_get_tag(dq, 'a-tag')
      if ffi.string(tag) ~= 'a-value' then
        print('invalid tag value')
        print(ffi.string(tag))
        return false
      end

      local raw_tag_buf_size = 255
      local raw_tag_buf = ffi.new("char [?]", raw_tag_buf_size)
      local raw_tag_size = ffi.C.dnsdist_ffi_dnsquestion_get_tag_raw(dq, 'raw-tag', raw_tag_buf, raw_tag_buf_size)
      if ffi.string(raw_tag_buf, raw_tag_size) ~= 'a\0b' then
        print('invalid raw tag value')
        print(ffi.string(raw_tag_buf,  raw_tag_size))
        return false
      end

      return true
    end

    function luaffiactionfunction(dq)
      local qtype = ffi.C.dnsdist_ffi_dnsquestion_get_qtype(dq)
      if qtype == DNSQType.A then
        local str = "192.0.2.1"
        local buf = ffi.new("char[?]", #str + 1)
        ffi.copy(buf, str)
        ffi.C.dnsdist_ffi_dnsquestion_set_result(dq, buf, #str)
        return DNSAction.Spoof
      elseif qtype == DNSQType.SOA then
        ffi.C.dnsdist_ffi_dnsquestion_set_rcode(dq, DNSRCode.REFUSED)
        return DNSAction.Refused
      end
    end

    function luaffiactionsettag(dq)
      ffi.C.dnsdist_ffi_dnsquestion_set_tag(dq, 'a-tag', 'a-value')
      return DNSAction.None
    end

    function luaffiactionsettagraw(dq)
      local value = "a\0b"
      ffi.C.dnsdist_ffi_dnsquestion_set_tag_raw(dq, 'raw-tag', value, #value)
      return DNSAction.None
    end

    addAction(AllRule(), LuaFFIAction(luaffiactionsettag))
    addAction(AllRule(), LuaFFIAction(luaffiactionsettagraw))
    addAction(LuaFFIRule(luaffirulefunction), LuaFFIAction(luaffiactionfunction))
    -- newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedLuaFFI(self):
        """
        Lua FFI: Test the Lua FFI interface
        """
        name = 'luaffi.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, response)

    def testAdvancedLuaFFIUpdate(self):
        """
        Lua FFI: Test the Lua FFI interface via an update
        """
        name = 'luaffi.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'SOA', 'IN')
        query.set_opcode(dns.opcode.UPDATE)
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, response)

class TestAdvancedLuaFFIPerThread(DNSDistTest):

    _config_template = """

    local rulefunction = [[
      local ffi = require("ffi")

      return function(dq)
        local qtype = ffi.C.dnsdist_ffi_dnsquestion_get_qtype(dq)
        if qtype ~= DNSQType.A and qtype ~= DNSQType.SOA then
          print('invalid qtype')
          return false
        end

        local qclass = ffi.C.dnsdist_ffi_dnsquestion_get_qclass(dq)
        if qclass ~= DNSClass.IN then
          print('invalid qclass')
          return false
        end

        local ret_ptr = ffi.new("char *[1]")
        local ret_ptr_param = ffi.cast("const char **", ret_ptr)
        local ret_size = ffi.new("size_t[1]")
        local ret_size_param = ffi.cast("size_t*", ret_size)
        ffi.C.dnsdist_ffi_dnsquestion_get_qname_raw(dq, ret_ptr_param, ret_size_param)
        if ret_size[0] ~= 45 then
          print('invalid length for the qname ')
          print(ret_size[0])
          return false
        end

        local expectedQname = string.char(15)..'luaffiperthread'..string.char(8)..'advanced'..string.char(5)..'tests'..string.char(8)..'powerdns'..string.char(3)..'com'
        if ffi.string(ret_ptr[0]) ~= expectedQname then
          print('invalid qname')
          print(ffi.string(ret_ptr[0]))
          return false
        end

        local rcode = ffi.C.dnsdist_ffi_dnsquestion_get_rcode(dq)
        if rcode ~= 0 then
          print('invalid rcode')
          return false
        end

        local opcode = ffi.C.dnsdist_ffi_dnsquestion_get_opcode(dq)
        if qtype == DNSQType.A and opcode ~= DNSOpcode.Query then
          print('invalid opcode')
          return false
        elseif qtype == DNSQType.SOA and opcode ~= DNSOpcode.Update then
          print('invalid opcode')
          return false
        end

        local dnssecok = ffi.C.dnsdist_ffi_dnsquestion_get_do(dq)
        if dnssecok ~= false then
          print('invalid DNSSEC OK')
          return false
        end

        local len = ffi.C.dnsdist_ffi_dnsquestion_get_len(dq)
        if len ~= 61 then
          print('invalid length')
          print(len)
          return false
        end

        local tag = ffi.C.dnsdist_ffi_dnsquestion_get_tag(dq, 'a-tag')
        if ffi.string(tag) ~= 'a-value' then
          print('invalid tag value')
          print(ffi.string(tag))
          return false
        end

        return true
      end
    ]]

    local actionfunction = [[
      local ffi = require("ffi")

      return function(dq)
        local qtype = ffi.C.dnsdist_ffi_dnsquestion_get_qtype(dq)
        if qtype == DNSQType.A then
          local str = "192.0.2.1"
          local buf = ffi.new("char[?]", #str + 1)
          ffi.copy(buf, str)
          ffi.C.dnsdist_ffi_dnsquestion_set_result(dq, buf, #str)
          return DNSAction.Spoof
        elseif qtype == DNSQType.SOA then
          ffi.C.dnsdist_ffi_dnsquestion_set_rcode(dq, DNSRCode.REFUSED)
          return DNSAction.Refused
        end
      end
    ]]

    local settagfunction = [[
      local ffi = require("ffi")

      return function(dq)
        ffi.C.dnsdist_ffi_dnsquestion_set_tag(dq, 'a-tag', 'a-value')
        return DNSAction.None
      end
    ]]

    addAction(AllRule(), LuaFFIPerThreadAction(settagfunction))
    addAction(LuaFFIPerThreadRule(rulefunction), LuaFFIPerThreadAction(actionfunction))
    -- newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedLuaPerthreadFFI(self):
        """
        Lua FFI: Test the Lua FFI per-thread interface
        """
        name = 'luaffiperthread.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, response)

    def testAdvancedLuaFFIPerThreadUpdate(self):
        """
        Lua FFI: Test the Lua FFI per-thread interface via an update
        """
        name = 'luaffiperthread.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'SOA', 'IN')
        query.set_opcode(dns.opcode.UPDATE)
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, response)
