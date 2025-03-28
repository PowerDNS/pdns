#!/usr/bin/env python

import os
import socket
import sys
import threading
import unittest
import dns
import dns.message
import doqclient

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
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _tlsServerPort = pickAvailablePort()
    _dohWithNGHTTP2ServerPort = pickAvailablePort()
    _dohWithH2OServerPort = pickAvailablePort()
    _dohWithNGHTTP2BaseURL = ("https://%s:%d/" % (_serverName, _dohWithNGHTTP2ServerPort))
    _dohWithH2OBaseURL = ("https://%s:%d/" % (_serverName, _dohWithH2OServerPort))
    _doqServerPort = pickAvailablePort()

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

            for method in ("sendUDPQuery", "sendTCPQuery", "sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper", "sendDOHWithH2OQueryWrapper", "sendDOQQueryWrapper"):
                sender = getattr(self, method)
                (receivedQuery, receivedResponse) = sender(query, response)
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                if method == 'sendDOQQueryWrapper':
                    # dnspython sets the ID to 0
                    receivedResponse.id = response.id
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

        for method in ("sendUDPQuery", "sendTCPQuery", "sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper", "sendDOHWithH2OQueryWrapper", "sendDOQQueryWrapper"):
            sender = getattr(self, method)
            if method != 'sendDOTQueryWrapper' and method != 'sendDOHWithH2OQueryWrapper' and method != 'sendDOQQueryWrapper':
                # first time to fill the cache
                # disabled for DoT since it was already filled via TCP
                (receivedQuery, receivedResponse) = sender(query, response)
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(response, receivedResponse)

            # second time from the cache
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            if method == 'sendDOQQueryWrapper':
                # dnspython sets the ID to 0
                receivedResponse.id = response.id
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

            for method in ("sendUDPQuery", "sendTCPQuery", "sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper", "sendDOHWithH2OQueryWrapper", "sendDOQQueryWrapper"):
                sender = getattr(self, method)
                (receivedQuery, receivedResponse) = sender(query, response)
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                if method == 'sendDOQQueryWrapper':
                    # dnspython sets the ID to 0
                    receivedResponse.id = response.id
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

            for method in ("sendUDPQuery", "sendTCPQuery", "sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper", "sendDOHWithH2OQueryWrapper", "sendDOQQueryWrapper"):
                sender = getattr(self, method)
                (receivedQuery, receivedResponse) = sender(query, response)
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                if method == 'sendDOQQueryWrapper':
                    # dnspython sets the ID to 0
                    receivedResponse.id = response.id
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

            for method in ("sendUDPQuery", "sendTCPQuery", "sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper", "sendDOHWithH2OQueryWrapper", "sendDOQQueryWrapper"):
                sender = getattr(self, method)
                (receivedQuery, receivedResponse) = sender(query, response)
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                if method == 'sendDOQQueryWrapper':
                    # dnspython sets the ID to 0
                    receivedResponse.id = expectedResponse.id
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

            expectedQuery = dns.message.make_query(name, 'A', 'IN')
            expectedQuery.id = query.id
            expectedResponse = dns.message.make_response(expectedQuery)
            expectedResponse.flags |= dns.flags.RA
            expectedResponse.set_rcode(dns.rcode.FORMERR)

            for method in ("sendUDPQuery", "sendTCPQuery", "sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper", "sendDOHWithH2OQueryWrapper", "sendDOQQueryWrapper"):
                sender = getattr(self, method)
                (receivedQuery, receivedResponse) = sender(query, response)
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                if method == 'sendDOQQueryWrapper':
                    # dnspython sets the ID to 0
                    receivedResponse.id = expectedResponse.id
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

            for method in ("sendUDPQuery", "sendTCPQuery", "sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper", "sendDOHWithH2OQueryWrapper", "sendDOQQueryWrapper"):
                sender = getattr(self, method)
                try:
                    (receivedQuery, receivedResponse) = sender(query, response)
                except doqclient.StreamResetError:
                    if not self._fromResponderQueue.empty():
                        receivedQuery = self._fromResponderQueue.get(True, 1.0)
                    receivedResponse = None
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

        for method in ("sendUDPQuery", "sendTCPQuery", "sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper", "sendDOHWithH2OQueryWrapper", "sendDOQQueryWrapper"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            if method == 'sendDOQQueryWrapper':
                # dnspython sets the ID to 0
                receivedResponse.id = expectedResponse.id
            self.assertEqual(expectedResponse, receivedResponse)

    def testDrop(self):
        """
        Async: Drop
        """
        name = 'drop.async.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        for method in ("sendUDPQuery", "sendTCPQuery", "sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper", "sendDOHWithH2OQueryWrapper", "sendDOQQueryWrapper"):
            sender = getattr(self, method)
            try:
                (_, receivedResponse) = sender(query, response=None, useQueue=False)
            except doqclient.StreamResetError:
                receivedResponse = None
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

        for method in ("sendUDPQuery", "sendTCPQuery", "sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper", "sendDOHWithH2OQueryWrapper", "sendDOQQueryWrapper"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            if method == 'sendDOQQueryWrapper':
                # dnspython sets the ID to 0
                receivedResponse.id = expectedResponse.id
            self.assertEqual(expectedResponse, receivedResponse)

    def testTruncation(self):
        """
        Async: DoH query, timeout then truncated answer over UDP, then valid over TCP and accept
        """
        # the query is first forwarded over UDP, leading to a TC=1 answer from the
        # backend, then over TCP

        for method in ("sendDOHWithNGHTTP2QueryWrapper", "sendDOHWithH2OQueryWrapper"):
            sender = getattr(self, method)
            name = 'timeout-then-accept.' + method + '.tc.async.tests.powerdns.com.'
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

            # first query, received by the responder over UDP
            (receivedQuery, receivedResponse) = sender(query, response=response)
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
    _config_template = """
    newServer{address="127.0.0.1:%d", pool={'', 'cache'}}
    newServer{address="127.0.0.1:%d", pool="tcp-only", tcpOnly=true }

    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="openssl" })
    addDOHLocal("127.0.0.1:%d", "%s", "%s", {"/"}, {library="h2o"})
    addDOHLocal("127.0.0.1:%d", "%s", "%s", {"/"}, {library="nghttp2"})
    addDOQLocal("127.0.0.1:%d", "%s", "%s")

    local ffi = require("ffi")
    local C = ffi.C

    local filteringTagName = 'filtering'
    local filteringTagValue = 'pass'
    local asyncID = 0

    pc = newPacketCache(100)
    getPool('cache'):setCache(pc)

    local asyncObjectsMap = {}

    function gotAsyncResponse(endpointID, message, from)

      print('Got async response '..message)
      local parts = {}
      for part in message:gmatch("%%S+") do table.insert(parts, part) end
      if #parts ~= 2 then
        print('Invalid message')
        return
      end
      local queryID = tonumber(parts[1])
      local qname = asyncObjectsMap[queryID]
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
        local raw = nil
        if qname == string.char(6)..'custom'..string.char(5)..'async'..string.char(5)..'tests'..string.char(8)..'powerdns'..string.char(3)..'com' then
          raw = '\\000\\000\\128\\129\\000\\001\\000\\000\\000\\000\\000\\001\\006custom\\005async\\005tests\\008powerdns\\003com\\000\\000\\001\\000\\001\\000\\000\\041\\002\\000\\000\\000\\128\\000\\000\\000'
        elseif qname == string.char(18)..'accept-then-custom'..string.char(5)..'async'..string.char(5)..'tests'..string.char(8)..'powerdns'..string.char(3)..'com' then
          raw = '\\000\\000\\128\\129\\000\\001\\000\\000\\000\\000\\000\\001\\018accept-then-custom\\005async\\005tests\\008powerdns\\003com\\000\\000\\001\\000\\001\\000\\000\\041\\002\\000\\000\\000\\128\\000\\000\\000'
        elseif qname == string.char(18)..'accept-then-custom'..string.char(8)..'tcp-only'..string.char(5)..'async'..string.char(5)..'tests'..string.char(8)..'powerdns'..string.char(3)..'com' then
          raw = '\\000\\000\\128\\129\\000\\001\\000\\000\\000\\000\\000\\001\\018accept-then-custom\\008tcp-only\\005async\\005tests\\008powerdns\\003com\\000\\000\\001\\000\\001\\000\\000\\041\\002\\000\\000\\000\\128\\000\\000\\000'
        end

        C.dnsdist_ffi_set_answer_from_async(asyncID, queryID, raw, #raw)
        return
      end
    end

    asyncResponderEndpoint = newNetworkEndpoint('%s')
    listener = newNetworkListener()
    listener:addUnixListeningEndpoint('%s', 0, gotAsyncResponse)
    listener:start()

    function getQNameRaw(dq)
      local ret_ptr = ffi.new("char *[1]")
      local ret_ptr_param = ffi.cast("const char **", ret_ptr)
      local ret_size = ffi.new("size_t[1]")
      local ret_size_param = ffi.cast("size_t*", ret_size)
      C.dnsdist_ffi_dnsquestion_get_qname_raw(dq, ret_ptr_param, ret_size_param)
      return ffi.string(ret_ptr[0])
    end

    function passQueryToAsyncFilter(dq)
      print('in passQueryToAsyncFilter')
      local timeout = 500 -- 500 ms

      local queryPtr = C.dnsdist_ffi_dnsquestion_get_header(dq)
      local querySize = C.dnsdist_ffi_dnsquestion_get_len(dq)

      -- we need to take a copy, as we can no longer touch that data after calling set_async
      local buffer = ffi.string(queryPtr, querySize)

      asyncObjectsMap[C.dnsdist_ffi_dnsquestion_get_id(dq)] = getQNameRaw(dq)

      C.dnsdist_ffi_dnsquestion_set_async(dq, asyncID, C.dnsdist_ffi_dnsquestion_get_id(dq), timeout)
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

      asyncObjectsMap[C.dnsdist_ffi_dnsquestion_get_id(dr)] = getQNameRaw(dr)

      C.dnsdist_ffi_dnsresponse_set_async(dr, asyncID, C.dnsdist_ffi_dnsquestion_get_id(dr), timeout)
      asyncResponderEndpoint:send(buffer)

      return DNSResponseAction.Allow
    end

    function atExit()
      listener = nil
      collectgarbage()
    end

    addExitCallback(atExit)

    -- this only matters for tests actually reaching the backend
    addAction('tcp-only.async.tests.powerdns.com', PoolAction('tcp-only', false))
    addAction('cache.async.tests.powerdns.com', PoolAction('cache', false))
    addAction(AllRule(), LuaFFIAction(passQueryToAsyncFilter))
    addCacheHitResponseAction(AllRule(), LuaFFIResponseAction(passResponseToAsyncFilter))
    addResponseAction(AllRule(), LuaFFIResponseAction(passResponseToAsyncFilter))
    """
    _asyncResponderSocketPath = asyncResponderSocketPath
    _dnsdistSocketPath = dnsdistSocketPath
    _config_params = ['_testServerPort', '_testServerPort', '_tlsServerPort', '_serverCert', '_serverKey', '_dohWithH2OServerPort', '_serverCert', '_serverKey', '_dohWithNGHTTP2ServerPort', '_serverCert', '_serverKey', '_doqServerPort', '_serverCert', '_serverKey', '_asyncResponderSocketPath', '_dnsdistSocketPath']
    _verboseMode = True

@unittest.skipIf('SKIP_DOH_TESTS' in os.environ, 'DNS over HTTPS tests are disabled')
class TestAsyncLua(DNSDistTest, AsyncTests):
    _config_template = """
    newServer{address="127.0.0.1:%d", pool={'', 'cache'}}
    newServer{address="127.0.0.1:%d", pool="tcp-only", tcpOnly=true }

    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="openssl" })
    addDOHLocal("127.0.0.1:%d", "%s", "%s", {"/"}, {library="h2o"})
    addDOHLocal("127.0.0.1:%d", "%s", "%s", {"/"}, {library="nghttp2"})
    addDOQLocal("127.0.0.1:%d", "%s", "%s")

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
        local dq = asyncObject:getDQ()
        local raw
        if tostring(dq.qname) == 'custom.async.tests.powerdns.com.' then
          raw = '\\000\\000\\128\\129\\000\\001\\000\\000\\000\\000\\000\\001\\006custom\\005async\\005tests\\008powerdns\\003com\\000\\000\\001\\000\\001\\000\\000\\041\\002\\000\\000\\000\\128\\000\\000\\000'
        elseif tostring(dq.qname) == 'accept-then-custom.async.tests.powerdns.com.' then
          raw = '\\000\\000\\128\\129\\000\\001\\000\\000\\000\\000\\000\\001\\018accept-then-custom\\005async\\005tests\\008powerdns\\003com\\000\\000\\001\\000\\001\\000\\000\\041\\002\\000\\000\\000\\128\\000\\000\\000'
        elseif tostring(dq.qname) == 'accept-then-custom.tcp-only.async.tests.powerdns.com.' then
          raw = '\\000\\000\\128\\129\\000\\001\\000\\000\\000\\000\\000\\001\\018accept-then-custom\\008tcp-only\\005async\\005tests\\008powerdns\\003com\\000\\000\\001\\000\\001\\000\\000\\041\\002\\000\\000\\000\\128\\000\\000\\000'
        end
        dq:setContent(raw)
        asyncObject:resume()
        return
      end
    end

    asyncResponderEndpoint = newNetworkEndpoint('%s')
    listener = newNetworkListener()
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

    function atExit()
      listener = nil
      collectgarbage()
    end

    addExitCallback(atExit)

    -- this only matters for tests actually reaching the backend
    addAction('tcp-only.async.tests.powerdns.com', PoolAction('tcp-only', false))
    addAction('cache.async.tests.powerdns.com', PoolAction('cache', false))
    addAction(AllRule(), LuaAction(passQueryToAsyncFilter))
    addCacheHitResponseAction(AllRule(), LuaResponseAction(passResponseToAsyncFilter))
    addResponseAction(AllRule(), LuaResponseAction(passResponseToAsyncFilter))
    """
    _asyncResponderSocketPath = asyncResponderSocketPath
    _dnsdistSocketPath = dnsdistSocketPath
    _config_params = ['_testServerPort', '_testServerPort', '_tlsServerPort', '_serverCert', '_serverKey', '_dohWithH2OServerPort', '_serverCert', '_serverKey', '_dohWithNGHTTP2ServerPort', '_serverCert', '_serverKey', '_doqServerPort', '_serverCert', '_serverKey', '_asyncResponderSocketPath', '_dnsdistSocketPath']
    _verboseMode = True
