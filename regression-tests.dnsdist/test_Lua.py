#!/usr/bin/env python

import base64
import dns
import time
from dnsdisttests import DNSDistTest

class TestLuaThread(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')

    _config_params = ['_consoleKeyB64', '_consolePort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")

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
        self.assertGreater(count2, count1)

class TestLuaDNSHeaderBindings(DNSDistTest):
    _config_template = """
    newServer{address="127.0.0.1:%d"}

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
    setStructuredLogging(false)
    newServer{address="127.0.0.1:%d"}

    -- check that all these methods return nil on a non-existing entry
    functions = { 'getServer', 'getDNSCryptBind', 'getBind', 'getDOQFrontend', 'getDOH3Frontend', 'getDOHFrontend', 'getTLSFrontend'}
    for _, func in ipairs(functions) do
      assert(_G[func] ~= nil, "function "..func.." not compiled in, cannot test")
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

class TestLuaPoolBindings(DNSDistTest):
    _config_template = """
    local serverPort = %d
    newServer{address="127.0.0.1:" .. serverPort}
    local pc = newPacketCache(1000, {maxTTL=86400, minTTL=1})
    -- at the moment getCache() does not return nil but an empty
    -- shared_pointer when there is not cache, which is annoying
    -- but necessary to prevent the client mode from failing,
    -- so we test the result of :toString() instead
    if getPool(""):getCache():toString() ~= "" then
      print("The default pool should not have a cache")
      os.exit(1)
    end
    getPool(""):setCache(pc)
    if getPool(""):getCache():toString() == "" then
      print("The default pool should have a cache")
      os.exit(2)
    end
    getPool(""):unsetCache()
    if getPool(""):getCache():toString() ~= "" then
      print("The default pool should no longer have a cache")
      os.exit(3)
    end
    local servers = getPoolServers("")
    if #servers ~= 1 then
      print("The default pool should have only one server")
      os.exit(4)
    end
    if getPool(""):getECS() ~= false then
      print("The default pool should not have ECS set")
      os.exit(5)
    end
    rmServer(0)
    newServer{address="127.0.0.1:" .. serverPort, useClientSubnet=true}
    getPool(""):setECS(true)
    if getPool(""):getECS() ~= true then
      print("The default pool should now have ECS set")
      os.exit(6)
    end
    """

    def testLuaBindings(self):
        """
        LuaPoolBindings: Test Lua pool bindings
        """
        name = 'basic.lua-pool-bindings.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=response)
            self.assertEqual(receivedResponse, response)

class TestLuaError(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')

    _config_params = ['_consoleKeyB64', '_consolePort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    debug = nil
    """

    def testLuaError(self):
        """
        LuaError: Test exception handling while debug module is obscured
        """
        res = self.sendConsoleCommand('error("expected" .. " " .. "error")')
        self.assertIn('expected error', res)
