#!/usr/bin/env python

import base64
import dns
import time
import unittest
from dnsdisttests import DNSDistTest

class TestLuaThread(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')

    _config_params = ['_consoleKeyB64', '_consolePort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")

    counter = 0
    function threadmessage(cmd, data)
        print("counter says", cmd, data.i)
        counter = tonumber(data.i)
    end

    newThread([==[
      local socket = require'socket'
      local i=1
      while true
      do
          socket.sleep(1)
          submitToMainThread("setCounter", {i=i})
          i = i + 1
      end
    ]==])
    """

    def testLuaThreadCounter(self):
        """
        LuaThread: Test the lua newThread interface
        """
        count1 = self.sendConsoleCommand('counter')
        time.sleep(3)
        count2 = self.sendConsoleCommand('counter')
        self.assertTrue(count2 > count1)

class TestLuaDNSHeaderBindings(DNSDistTest):
    _config_template = """
    newServer{address="127.0.0.1:%s"}

    function checkTCSet(dq)
      local tc = dq.dh:getTC()
      if not tc then
        return DNSAction.Spoof, 'tc-not-set.check-tc.lua-dnsheaders.tests.powerdns.com.'
      end
      return DNSAction.Allow
    end

    addAction('check-tc.lua-dnsheaders.tests.powerdns.com.', LuaAction(checkTCSet))
    """

    def testLuaGetTC(self):
        """
        LuaDNSHeaders: TC
        """
        name = 'notset.check-tc.lua-dnsheaders.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'tc-not-set.check-tc.lua-dnsheaders.tests.powerdns.com.')
        response.answer.append(rrset)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(response, receivedResponse)

        name = 'set.check-tc.lua-dnsheaders.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        query.flags |= dns.flags.TC
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

class TestLuaFrontendBindings(DNSDistTest):
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    -- check that all these methods return nil on a non-existing entry
    functions = { 'getServer', 'getDNSCryptBind', 'getBind', 'getDOQFrontend', 'getDOH3Frontend', 'getDOHFrontend', 'getTLSFrontend'}
    for _, func in ipairs(functions) do
      assert(_G[func](42) == nil, "function "..func.." did not return nil as expected")
    end

    addAction('basic.lua-frontend-bindings.tests.powerdns.com.', RCodeAction(DNSRCode.REFUSED))
    -- also test that getSelectedBackend() returns nil on self-answered responses
    function checkSelectedBackend(dr)
      local backend = dr:getSelectedBackend()
      assert(backend == nil, "DNSResponse::getSelectedBackend() should return nil on self-answered responses")
      return DNSResponseAction.None
    end
    addSelfAnsweredResponseAction(AllRule(), LuaResponseAction(checkSelectedBackend))
    """
    _checkConfigExpectedOutput = b"Error: trying to get DOQ frontend with index 42 but we only have 0 frontend(s)\n\nError: trying to get DOH3 frontend with index 42 but we only have 0 frontend(s)\n\nError: trying to get DOH frontend with index 42 but we only have 0 frontend(s)\n\nError: trying to get TLS frontend with index 42 but we only have 0 frontends\n\nConfiguration 'configs/dnsdist_TestLuaFrontendBindings.conf' OK!\n"

    def testLuaBindings(self):
        """
        LuaFrontendBindings: Test Lua frontend bindings
        """
        name = 'basic.lua-frontend-bindings.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)
