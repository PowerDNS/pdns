#!/usr/bin/env python

import os
import socket
import threading
import unittest
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort

def AsyncResponder(listenPath, responsePath):
    # Make sure the socket does not already exist
    try:
        os.unlink(listenPath)
    except OSError:
        if os.path.exists(listenPath):
            raise

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.bind(listenPath)
    except socket.error as e:
        print("Error binding in the Asynchronous responder: %s" % str(e))
        sys.exit(1)

    while True:
        data, addr = sock.recvfrom(65535)
        print("Got message [%d] '%s' from %s" % (len(data), data, addr))
        if not data:
            break

        request = dns.message.from_wire(data)
        reply = str(request.id) + ' '
        if str(request.question[0].name).startswith('accept-then-refuse'):
            if request.flags & dns.flags.QR:
                reply = reply + 'refuse'
            else:
                reply = reply + 'accept'
        elif str(request.question[0].name).startswith('accept-then-drop'):
            if request.flags & dns.flags.QR:
                reply = reply + 'drop'
            else:
                reply = reply + 'accept'
        elif str(request.question[0].name).startswith('accept-then-custom'):
            if request.flags & dns.flags.QR:
                reply = reply + 'custom'
            else:
                reply = reply + 'accept'
        elif str(request.question[0].name).startswith('timeout-then-accept'):
            if request.flags & dns.flags.QR:
                reply = reply + 'accept'
            else:
                # no response
                continue
        elif str(request.question[0].name).startswith('accept-then-timeout'):
            if request.flags & dns.flags.QR:
                # no response
                continue
            else:
                reply = reply + 'accept'
        elif str(request.question[0].name).startswith('accept'):
            reply = reply + 'accept'
        elif str(request.question[0].name).startswith('refuse'):
            reply = reply + 'refuse'
        elif str(request.question[0].name).startswith('drop'):
            reply = reply + 'drop'
        elif str(request.question[0].name).startswith('custom'):
            reply = reply + 'custom'
        elif str(request.question[0].name).startswith('timeout'):
            # no response
            continue
        else:
            reply = reply + 'invalid'

        remote = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        remote.connect(responsePath)
        remote.send(reply.encode())
        print("Sent [%d] '%s' to %s" % (len(reply), reply, responsePath))

    sock.close()

asyncResponderSocketPath = '/tmp/async-responder.sock'
dnsdistSocketPath = '/tmp/dnsdist.sock'
asyncResponder = threading.Thread(name='Asynchronous Responder', target=AsyncResponder, args=[asyncResponderSocketPath, dnsdistSocketPath])
asyncResponder.daemon = True
asyncResponder.start()

class AsyncTests(object):
    def testPass(self):
        """
        Async: Accept
        """
        for name in ['accept.async.tests.powerdns.com.', 'accept.tcp-only.async.tests.powerdns.com.']:
            query = dns.message.make_query(name, 'A', 'IN')

            response = dns.message.make_response(query)
            rrset = dns.rrset.from_text(name,
                                        60,
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

            (receivedQuery, receivedResponse) = self.sendDOTQuery(self._tlsServerPort, self._serverName, query, response=response, caFile=self._caCert)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

            (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

    def testPassCached(self):
        """
        Async: Accept (cached)
        """
        name = 'accept.cache.async.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            # first time to fill the cache
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)
            # second time from the cache
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(response, receivedResponse)

        (_, receivedResponse) = self.sendDOTQuery(self._tlsServerPort, self._serverName, query, response=None, useQueue=False, caFile=self._caCert)
        self.assertEqual(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=None, useQueue=False, caFile=self._caCert)
        self.assertEqual(response, receivedResponse)

    def testTimeoutThenAccept(self):
        """
        Async: Timeout then accept
        """
        for name in ['timeout-then-accept.async.tests.powerdns.com.', 'timeout-then-accept.tcp-only.async.tests.powerdns.com.']:
            query = dns.message.make_query(name, 'A', 'IN')

            response = dns.message.make_response(query)
            rrset = dns.rrset.from_text(name,
                                        60,
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

            (receivedQuery, receivedResponse) = self.sendDOTQuery(self._tlsServerPort, self._serverName, query, response=response, caFile=self._caCert)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

            (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

    def testAcceptThenTimeout(self):
        """
        Async: Accept then timeout
        """
        for name in ['accept-then-timeout.async.tests.powerdns.com.', 'accept-then-timeout.tcp-only.async.tests.powerdns.com.']:
            query = dns.message.make_query(name, 'A', 'IN')

            response = dns.message.make_response(query)
            rrset = dns.rrset.from_text(name,
                                        60,
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

            (receivedQuery, receivedResponse) = self.sendDOTQuery(self._tlsServerPort, self._serverName, query, response=response, caFile=self._caCert)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

            (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

    def testAcceptThenRefuse(self):
        """
        Async: Accept then refuse
        """
        for name in ['accept-then-refuse.async.tests.powerdns.com.', 'accept-then-refuse.tcp-only.async.tests.powerdns.com.']:
            query = dns.message.make_query(name, 'A', 'IN')

            response = dns.message.make_response(query)
            rrset = dns.rrset.from_text(name,
                                        60,
                                        dns.rdataclass.IN,
                                        dns.rdatatype.A,
                                        '192.0.2.1')
            response.answer.append(rrset)

            expectedResponse = dns.message.make_response(query)
            expectedResponse.flags |= dns.flags.RA
            expectedResponse.set_rcode(dns.rcode.REFUSED)

            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                (receivedQuery, receivedResponse) = sender(query, response)
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(expectedResponse, receivedResponse)

            (receivedQuery, receivedResponse) = self.sendDOTQuery(self._tlsServerPort, self._serverName, query, response=response, caFile=self._caCert)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(expectedResponse, receivedResponse)

            (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(expectedResponse, receivedResponse)

    def testAcceptThenCustom(self):
        """
        Async: Accept then custom
        """
        for name in ['accept-then-custom.async.tests.powerdns.com.', 'accept-then-custom.tcp-only.async.tests.powerdns.com.']:
            query = dns.message.make_query(name, 'A', 'IN')

            response = dns.message.make_response(query)
            rrset = dns.rrset.from_text(name,
                                        60,
                                        dns.rdataclass.IN,
                                        dns.rdatatype.A,
                                        '192.0.2.1')
            response.answer.append(rrset)

            # easier to get the same custom response to everyone, sorry!
            expectedQuery = dns.message.make_query('custom.async.tests.powerdns.com.', 'A', 'IN')
            expectedQuery.id = query.id
            expectedResponse = dns.message.make_response(expectedQuery)
            expectedResponse.flags |= dns.flags.RA
            expectedResponse.set_rcode(dns.rcode.FORMERR)

            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                (receivedQuery, receivedResponse) = sender(query, response)
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(expectedResponse, receivedResponse)

            (receivedQuery, receivedResponse) = self.sendDOTQuery(self._tlsServerPort, self._serverName, query, response=response, caFile=self._caCert)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(expectedResponse, receivedResponse)

            (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(expectedResponse, receivedResponse)

    def testAcceptThenDrop(self):
        """
        Async: Accept then drop
        """
        for name in ['accept-then-drop.async.tests.powerdns.com.', 'accept-then-drop.tcp-only.async.tests.powerdns.com.']:
            query = dns.message.make_query(name, 'A', 'IN')

            response = dns.message.make_response(query)
            rrset = dns.rrset.from_text(name,
                                        60,
                                        dns.rdataclass.IN,
                                        dns.rdatatype.A,
                                        '192.0.2.1')
            response.answer.append(rrset)

            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                (receivedQuery, receivedResponse) = sender(query, response)
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(receivedResponse, None)

            (receivedQuery, receivedResponse) = self.sendDOTQuery(self._tlsServerPort, self._serverName, query, response=response, caFile=self._caCert)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, None)

            (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, None)

    def testRefused(self):
        """
        Async: Refused
        """
        name = 'refused.async.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags |= dns.flags.RA
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        (_, receivedResponse) = self.sendDOTQuery(self._tlsServerPort, self._serverName, query, response=None, caFile=self._caCert, useQueue=False)
        self.assertEqual(expectedResponse, receivedResponse)

        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=None, caFile=self._caCert, useQueue=False)
        self.assertEqual(expectedResponse, receivedResponse)

    def testDrop(self):
        """
        Async: Drop
        """
        name = 'drop.async.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, None)

        (_, receivedResponse) = self.sendDOTQuery(self._tlsServerPort, self._serverName, query, response=None, caFile=self._caCert, useQueue=False)
        self.assertEqual(receivedResponse, None)

        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=None, caFile=self._caCert, useQueue=False)
        self.assertEqual(receivedResponse, None)

    def testCustom(self):
        """
        Async: Custom answer
        """
        name = 'custom.async.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags |= dns.flags.RA
        expectedResponse.set_rcode(dns.rcode.FORMERR)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        (_, receivedResponse) = self.sendDOTQuery(self._tlsServerPort, self._serverName, query, response=None, caFile=self._caCert, useQueue=False)
        self.assertEqual(expectedResponse, receivedResponse)

        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=None, caFile=self._caCert, useQueue=False)
        self.assertEqual(expectedResponse, receivedResponse)

    def testTruncation(self):
        """
        Async: DoH query, timeout then truncated answer over UDP, then valid over TCP and accept
        """
        # the query is first forwarded over UDP, leading to a TC=1 answer from the
        # backend, then over TCP
        name = 'timeout-then-accept.tc.async.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.id = 42
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 42
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        # first response is a TC=1
        tcResponse = dns.message.make_response(query)
        tcResponse.flags |= dns.flags.TC
        self._toResponderQueue.put(tcResponse, True, 2.0)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, response=response)
        # first query, received by the responder over UDP
        self.assertTrue(receivedQuery)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)

        # check the response
        self.assertTrue(receivedResponse)
        self.assertEqual(response, receivedResponse)

        # check the second query, received by the responder over TCP
        receivedQuery = self._fromResponderQueue.get(True, 2.0)
        self.assertTrue(receivedQuery)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)

@unittest.skipIf('SKIP_DOH_TESTS' in os.environ, 'DNS over HTTPS tests are disabled')
class TestAsyncFFI(DNSDistTest, AsyncTests):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _tlsServerPort = pickAvailablePort()
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))

    _config_template = """
    newServer{address="127.0.0.1:%s", pool={'', 'cache'}}
    newServer{address="127.0.0.1:%s", pool="tcp-only", tcpOnly=true }

    addTLSLocal("127.0.0.1:%s", "%s", "%s", { provider="openssl" })
    addDOHLocal("127.0.0.1:%s", "%s", "%s", { "/"})

    local ffi = require("ffi")
    local C = ffi.C

    local filteringTagName = 'filtering'
    local filteringTagValue = 'pass'
    local asyncID = 0

    pc = newPacketCache(100)
    getPool('cache'):setCache(pc)

    function gotAsyncResponse(endpointID, message, from)

      print('Got async response '..message)
      local parts = {}
      for part in message:gmatch("%%S+") do table.insert(parts, part) end
      if #parts ~= 2 then
        print('Invalid message')
        return
      end
      local queryID = tonumber(parts[1])
      if parts[2] == 'accept' then
        print('accepting')
        C.dnsdist_ffi_resume_from_async(asyncID, queryID, filteringTagName, #filteringTagName, filteringTagValue, #filteringTagValue, true)
        return
      end
      if parts[2] == 'refuse' then
        print('refusing')
        C.dnsdist_ffi_set_rcode_from_async(asyncID, queryID, DNSRCode.REFUSED, true)
        return
      end
      if parts[2] == 'drop' then
        print('dropping')
        C.dnsdist_ffi_drop_from_async(asyncID, queryID)
        return
      end
      if parts[2] == 'custom' then
        print('sending a custom response')
        local raw = '\\000\\000\\128\\129\\000\\001\\000\\000\\000\\000\\000\\001\\006custom\\005async\\005tests\\008powerdns\\003com\\000\\000\\001\\000\\001\\000\\000\\041\\002\\000\\000\\000\\128\\000\\000\\000'
        C.dnsdist_ffi_set_answer_from_async(asyncID, queryID, raw, #raw)
        return
      end
    end

    local asyncResponderEndpoint = newNetworkEndpoint('%s')
    local listener = newNetworkListener()
    listener:addUnixListeningEndpoint('%s', 0, gotAsyncResponse)
    listener:start()

    function passQueryToAsyncFilter(dq)
      print('in passQueryToAsyncFilter')
      local timeout = 500 -- 500 ms

      local queryPtr = C.dnsdist_ffi_dnsquestion_get_header(dq)
      local querySize = C.dnsdist_ffi_dnsquestion_get_len(dq)

      -- we need to take a copy, as we can no longer touch that data after calling set_async
      local buffer = ffi.string(queryPtr, querySize)

      print(C.dnsdist_ffi_dnsquestion_set_async(dq, asyncID, C.dnsdist_ffi_dnsquestion_get_id(dq), timeout))
      asyncResponderEndpoint:send(buffer)

      return DNSAction.Allow
    end

    function passResponseToAsyncFilter(dr)
      print('in passResponseToAsyncFilter')
      local timeout = 500 -- 500 ms

      local responsePtr = C.dnsdist_ffi_dnsquestion_get_header(dr)
      local responseSize = C.dnsdist_ffi_dnsquestion_get_len(dr)

      -- we need to take a copy, as we can no longer touch that data after calling set_async
      local buffer = ffi.string(responsePtr, responseSize)

      print(C.dnsdist_ffi_dnsresponse_set_async(dr, asyncID, C.dnsdist_ffi_dnsquestion_get_id(dr), timeout))
      asyncResponderEndpoint:send(buffer)

      return DNSResponseAction.Allow
    end

    -- this only matters for tests actually reaching the backend
    addAction('tcp-only.async.tests.powerdns.com', PoolAction('tcp-only', false))
    addAction('cache.async.tests.powerdns.com', PoolAction('cache', false))
    addAction(AllRule(), LuaFFIAction(passQueryToAsyncFilter))
    addCacheHitResponseAction(AllRule(), LuaFFIResponseAction(passResponseToAsyncFilter))
    addResponseAction(AllRule(), LuaFFIResponseAction(passResponseToAsyncFilter))
    """
    _asyncResponderSocketPath = asyncResponderSocketPath
    _dnsdistSocketPath = dnsdistSocketPath
    _config_params = ['_testServerPort', '_testServerPort', '_tlsServerPort', '_serverCert', '_serverKey', '_dohServerPort', '_serverCert', '_serverKey', '_asyncResponderSocketPath', '_dnsdistSocketPath']
    _verboseMode = True

@unittest.skipIf('SKIP_DOH_TESTS' in os.environ, 'DNS over HTTPS tests are disabled')
class TestAsyncLua(DNSDistTest, AsyncTests):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _tlsServerPort = pickAvailablePort()
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))

    _config_template = """
    newServer{address="127.0.0.1:%s", pool={'', 'cache'}}
    newServer{address="127.0.0.1:%s", pool="tcp-only", tcpOnly=true }

    addTLSLocal("127.0.0.1:%s", "%s", "%s", { provider="openssl" })
    addDOHLocal("127.0.0.1:%s", "%s", "%s", { "/"})

    local filteringTagName = 'filtering'
    local filteringTagValue = 'pass'
    local asyncID = 0

    pc = newPacketCache(100)
    getPool('cache'):setCache(pc)

    function gotAsyncResponse(endpointID, message, from)

      print('Got async response '..message)
      local parts = {}
      for part in message:gmatch("%%S+") do
        table.insert(parts, part)
      end
      if #parts ~= 2 then
        print('Invalid message')
        return
      end
      local queryID = tonumber(parts[1])
      local asyncObject = getAsynchronousObject(asyncID, queryID)
      if parts[2] == 'accept' then
        print('accepting')
        local dq = asyncObject:getDQ()
        dq:setTag(filteringTagName, filteringTagValue)
        asyncObject:resume()
        return
      end
      if parts[2] == 'refuse' then
        print('refusing')
        local dq = asyncObject:getDQ()
        asyncObject:setRCode(DNSRCode.REFUSED, true)
        asyncObject:resume()
        return
      end
      if parts[2] == 'drop' then
        print('dropping')
        asyncObject:drop()
        return
      end
      if parts[2] == 'custom' then
        print('sending a custom response')
        local raw = '\\000\\000\\128\\129\\000\\001\\000\\000\\000\\000\\000\\001\\006custom\\005async\\005tests\\008powerdns\\003com\\000\\000\\001\\000\\001\\000\\000\\041\\002\\000\\000\\000\\128\\000\\000\\000'
        local dq = asyncObject:getDQ()
        dq:setContent(raw)
        asyncObject:resume()
        return
      end
    end

    local asyncResponderEndpoint = newNetworkEndpoint('%s')
    local listener = newNetworkListener()
    listener:addUnixListeningEndpoint('%s', 0, gotAsyncResponse)
    listener:start()

    function passQueryToAsyncFilter(dq)
      print('in passQueryToAsyncFilter')
      local timeout = 500 -- 500 ms

      local buffer = dq:getContent()
      local id = dq.dh:getID()
      dq:suspend(asyncID, id, timeout)
      asyncResponderEndpoint:send(buffer)

      return DNSAction.Allow
    end

    function passResponseToAsyncFilter(dr)
      print('in passResponseToAsyncFilter')
      local timeout = 500 -- 500 ms

      local buffer = dr:getContent()
      local id = dr.dh:getID()
      dr:suspend(asyncID, id, timeout)
      asyncResponderEndpoint:send(buffer)

      return DNSResponseAction.Allow
    end

    -- this only matters for tests actually reaching the backend
    addAction('tcp-only.async.tests.powerdns.com', PoolAction('tcp-only', false))
    addAction('cache.async.tests.powerdns.com', PoolAction('cache', false))
    addAction(AllRule(), LuaAction(passQueryToAsyncFilter))
    addCacheHitResponseAction(AllRule(), LuaResponseAction(passResponseToAsyncFilter))
    addResponseAction(AllRule(), LuaResponseAction(passResponseToAsyncFilter))
    """
    _asyncResponderSocketPath = asyncResponderSocketPath
    _dnsdistSocketPath = dnsdistSocketPath
    _config_params = ['_testServerPort', '_testServerPort', '_tlsServerPort', '_serverCert', '_serverKey', '_dohServerPort', '_serverCert', '_serverKey', '_asyncResponderSocketPath', '_dnsdistSocketPath']
    _verboseMode = True
