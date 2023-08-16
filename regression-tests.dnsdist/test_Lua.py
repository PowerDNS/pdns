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
