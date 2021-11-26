#!/usr/bin/env python
import base64
import os
import time
import unittest
import dns
from dnsdisttests import DNSDistTest

class TestAdvancedFixupCase(DNSDistTest):

    _config_template = """
    truncateTC(true)
    fixupCase(true)
    newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedFixupCase(self):
        """
        Advanced: Fixup Case

        Send a query with lower and upper chars,
        make the backend return a lowercase version,
        check that dnsdist fixes the response.
        """
        name = 'fiXuPCasE.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        lowercasequery = dns.message.make_query(name.lower(), 'A', 'IN')
        response = dns.message.make_response(lowercasequery)
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(expectedResponse, receivedResponse)

class TestAdvancedACL(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
    """
    _acl = ['192.0.2.1/32']

    def testACLBlocked(self):
        """
        Advanced: ACL blocked

        Send an A query to "tests.powerdns.com.",
        we expect no response since 127.0.0.1 is not on the
        ACL.
        """
        name = 'tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, None)

class TestAdvancedStringOnlyServer(DNSDistTest):

    _config_template = """
    newServer("127.0.0.1:%s")
    """

    def testAdvancedStringOnlyServer(self):
        """
        Advanced: "string-only" server is placed in the default pool
        """
        name = 'string-only-server.advanced.tests.powerdns.com.'
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
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

@unittest.skipIf('SKIP_INCLUDEDIR_TESTS' in os.environ, 'IncludeDir tests are disabled')
class TestAdvancedIncludeDir(DNSDistTest):

    _config_template = """
    -- this directory contains a file allowing includedir.advanced.tests.powerdns.com.
    includeDirectory('test-include-dir')
    newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedIncludeDirAllowed(self):
        """
        Advanced: includeDirectory()
        """
        name = 'includedir.advanced.tests.powerdns.com.'
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
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        # this one should be refused
        name = 'notincludedir.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

class TestStatNodeRespRingSince(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")
    s1 = newServer{address="127.0.0.1:%s"}
    s1:setUp()
    function visitor(node, self, childstat)
        table.insert(nodesSeen, node.fullname)
    end
    """

    def testStatNodeRespRingSince(self):
        """
        Advanced: StatNodeRespRing with optional since parameter

        """
        name = 'statnodesince.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    1,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        self.sendConsoleCommand("nodesSeen = {}")
        self.sendConsoleCommand("statNodeRespRing(visitor)")
        nodes = self.sendConsoleCommand("str = '' for key,value in pairs(nodesSeen) do str = str..value..\"\\n\" end return str")
        nodes = nodes.strip("\n")
        self.assertEqual(nodes, """statnodesince.advanced.tests.powerdns.com.
advanced.tests.powerdns.com.
tests.powerdns.com.
powerdns.com.
com.""")

        self.sendConsoleCommand("nodesSeen = {}")
        self.sendConsoleCommand("statNodeRespRing(visitor, 0)")
        nodes = self.sendConsoleCommand("str = '' for key,value in pairs(nodesSeen) do str = str..value..\"\\n\" end return str")
        nodes = nodes.strip("\n")
        self.assertEqual(nodes, """statnodesince.advanced.tests.powerdns.com.
advanced.tests.powerdns.com.
tests.powerdns.com.
powerdns.com.
com.""")

        time.sleep(5)

        self.sendConsoleCommand("nodesSeen = {}")
        self.sendConsoleCommand("statNodeRespRing(visitor)")
        nodes = self.sendConsoleCommand("str = '' for key,value in pairs(nodesSeen) do str = str..value..\"\\n\" end return str")
        nodes = nodes.strip("\n")
        self.assertEqual(nodes, """statnodesince.advanced.tests.powerdns.com.
advanced.tests.powerdns.com.
tests.powerdns.com.
powerdns.com.
com.""")

        self.sendConsoleCommand("nodesSeen = {}")
        self.sendConsoleCommand("statNodeRespRing(visitor, 5)")
        nodes = self.sendConsoleCommand("str = '' for key,value in pairs(nodesSeen) do str = str..value..\"\\n\" end return str")
        nodes = nodes.strip("\n")
        self.assertEqual(nodes, """""")

        self.sendConsoleCommand("nodesSeen = {}")
        self.sendConsoleCommand("statNodeRespRing(visitor, 10)")
        nodes = self.sendConsoleCommand("str = '' for key,value in pairs(nodesSeen) do str = str..value..\"\\n\" end return str")
        nodes = nodes.strip("\n")
        self.assertEqual(nodes, """statnodesince.advanced.tests.powerdns.com.
advanced.tests.powerdns.com.
tests.powerdns.com.
powerdns.com.
com.""")

class TestAdvancedGetLocalPort(DNSDistTest):

    _config_template = """
    function answerBasedOnLocalPort(dq)
      local port = dq.localaddr:getPort()
      return DNSAction.Spoof, "port-was-"..port..".local-port.advanced.tests.powerdns.com."
    end
    addAction("local-port.advanced.tests.powerdns.com.", LuaAction(answerBasedOnLocalPort))
    newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedGetLocalPort(self):
        """
        Advanced: Return CNAME containing the local port
        """
        name = 'local-port.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'port-was-{}.local-port.advanced.tests.powerdns.com.'.format(self._dnsDistPort))
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, response)

class TestAdvancedGetLocalPortOnAnyBind(DNSDistTest):

    _config_template = """
    function answerBasedOnLocalPort(dq)
      local port = dq.localaddr:getPort()
      return DNSAction.Spoof, "port-was-"..port..".local-port-any.advanced.tests.powerdns.com."
    end
    addAction("local-port-any.advanced.tests.powerdns.com.", LuaAction(answerBasedOnLocalPort))
    newServer{address="127.0.0.1:%s"}
    """
    _dnsDistListeningAddr = "0.0.0.0"

    def testAdvancedGetLocalPortOnAnyBind(self):
        """
        Advanced: Return CNAME containing the local port for an ANY bind
        """
        name = 'local-port-any.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'port-was-{}.local-port-any.advanced.tests.powerdns.com.'.format(self._dnsDistPort))
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, response)

class TestAdvancedGetLocalAddressOnAnyBind(DNSDistTest):

    _config_template = """
    function answerBasedOnLocalAddress(dq)
      local dest = tostring(dq.localaddr)
      local i, j = string.find(dest, "[0-9.]+")
      local addr = string.sub(dest, i, j)
      local dashAddr = string.gsub(addr, "[.]", "-")
      return DNSAction.Spoof, "address-was-"..dashAddr..".local-address-any.advanced.tests.powerdns.com."
    end
    addAction("local-address-any.advanced.tests.powerdns.com.", LuaAction(answerBasedOnLocalAddress))
    newServer{address="127.0.0.1:%s"}
    """
    _dnsDistListeningAddr = "0.0.0.0"

    def testAdvancedGetLocalAddressOnAnyBind(self):
        """
        Advanced: Return CNAME containing the local address for an ANY bind
        """
        name = 'local-address-any.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'address-was-127-0-0-1.local-address-any.advanced.tests.powerdns.com.')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, response)

class TestAdvancedAllowHeaderOnly(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
    setAllowEmptyResponse(true)
    """

    def testHeaderOnlyRefused(self):
        """
        Advanced: Header-only refused response
        """
        name = 'header-only-refused-response.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)
        response.question = []

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)

    def testHeaderOnlyNoErrorResponse(self):
        """
        Advanced: Header-only NoError response should be allowed
        """
        name = 'header-only-noerror-response.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.question = []

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)

    def testHeaderOnlyNXDResponse(self):
        """
        Advanced: Header-only NXD response should be allowed
        """
        name = 'header-only-nxd-response.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)
        response.question = []

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)

class TestAdvancedDropEmptyQueries(DNSDistTest):

    _config_template = """
    setDropEmptyQueries(true)
    newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedDropEmptyQueries(self):
        """
        Advanced: Drop empty queries
        """
        name = 'drop-empty-queries.advanced.tests.powerdns.com.'
        query = dns.message.Message()

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, None)

class TestProtocols(DNSDistTest):
    _config_template = """
    function checkUDP(dq)
      if dq:getProtocol() ~= "Do53 UDP" then
        return DNSAction.Spoof, '1.2.3.4'
      end
      return DNSAction.None
    end

    function checkTCP(dq)
      if dq:getProtocol() ~= "Do53 TCP" then
        return DNSAction.Spoof, '1.2.3.4'
      end
      return DNSAction.None
    end

    addAction("udp.protocols.advanced.tests.powerdns.com.", LuaAction(checkUDP))
    addAction("tcp.protocols.advanced.tests.powerdns.com.", LuaAction(checkTCP))
    newServer{address="127.0.0.1:%s"}
    """

    def testProtocolUDP(self):
        """
        Advanced: Test DNSQuestion.Protocol over UDP
        """
        name = 'udp.protocols.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)

    def testProtocolTCP(self):
        """
        Advanced: Test DNSQuestion.Protocol over TCP
        """
        name = 'tcp.protocols.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)
