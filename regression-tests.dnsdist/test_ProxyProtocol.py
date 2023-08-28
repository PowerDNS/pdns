#!/usr/bin/env python

import copy
import dns
import socket
import struct
import sys
import threading
import time

from dnsdisttests import DNSDistTest, pickAvailablePort
from proxyprotocol import ProxyProtocol
from dnsdistdohtests import DNSDistDOHTest

# Python2/3 compatibility hacks
try:
  from queue import Queue
except ImportError:
  from Queue import Queue

def ProxyProtocolUDPResponder(port, fromQueue, toQueue):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    try:
        sock.bind(("127.0.0.1", port))
    except socket.error as e:
        print("Error binding in the Proxy Protocol UDP responder: %s" % str(e))
        sys.exit(1)

    while True:
        data, addr = sock.recvfrom(4096)

        proxy = ProxyProtocol()
        if len(data) < proxy.HEADER_SIZE:
            continue

        if not proxy.parseHeader(data):
            continue

        if proxy.local:
            # likely a healthcheck
            data = data[proxy.HEADER_SIZE:]
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)
            wire = response.to_wire()
            sock.settimeout(2.0)
            sock.sendto(wire, addr)
            sock.settimeout(None)

            continue

        payload = data[:(proxy.HEADER_SIZE + proxy.contentLen)]
        dnsData = data[(proxy.HEADER_SIZE + proxy.contentLen):]
        toQueue.put([payload, dnsData], True, 2.0)
        # computing the correct ID for the response
        request = dns.message.from_wire(dnsData)
        response = fromQueue.get(True, 2.0)
        response.id = request.id

        sock.settimeout(2.0)
        sock.sendto(response.to_wire(), addr)
        sock.settimeout(None)

    sock.close()

def ProxyProtocolTCPResponder(port, fromQueue, toQueue):
    # be aware that this responder will not accept a new connection
    # until the last one has been closed. This is done on purpose to
    # to check for connection reuse, making sure that a lot of connections
    # are not opened in parallel.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        sock.bind(("127.0.0.1", port))
    except socket.error as e:
        print("Error binding in the TCP responder: %s" % str(e))
        sys.exit(1)

    sock.listen(100)
    while True:
        (conn, _) = sock.accept()
        conn.settimeout(5.0)
        # try to read the entire Proxy Protocol header
        proxy = ProxyProtocol()
        header = conn.recv(proxy.HEADER_SIZE)
        if not header:
            conn.close()
            continue

        if not proxy.parseHeader(header):
            conn.close()
            continue

        proxyContent = conn.recv(proxy.contentLen)
        if not proxyContent:
            conn.close()
            continue

        payload = header + proxyContent
        while True:
          try:
            data = conn.recv(2)
          except socket.timeout:
            data = None

          if not data:
            conn.close()
            break

          (datalen,) = struct.unpack("!H", data)
          data = conn.recv(datalen)

          toQueue.put([payload, data], True, 2.0)

          response = copy.deepcopy(fromQueue.get(True, 2.0))
          if not response:
            conn.close()
            break

          # computing the correct ID for the response
          request = dns.message.from_wire(data)
          response.id = request.id

          wire = response.to_wire()
          conn.send(struct.pack("!H", len(wire)))
          conn.send(wire)

        conn.close()

    sock.close()

toProxyQueue = Queue()
fromProxyQueue = Queue()
proxyResponderPort = pickAvailablePort()

udpResponder = threading.Thread(name='UDP Proxy Protocol Responder', target=ProxyProtocolUDPResponder, args=[proxyResponderPort, toProxyQueue, fromProxyQueue])
udpResponder.daemon = True
udpResponder.start()
tcpResponder = threading.Thread(name='TCP Proxy Protocol Responder', target=ProxyProtocolTCPResponder, args=[proxyResponderPort, toProxyQueue, fromProxyQueue])
tcpResponder.daemon = True
tcpResponder.start()

class ProxyProtocolTest(DNSDistTest):
    _proxyResponderPort = proxyResponderPort
    _config_params = ['_proxyResponderPort']

class TestProxyProtocol(ProxyProtocolTest):
    """
    dnsdist is configured to prepend a Proxy Protocol header to the query
    """

    _config_template = """
    newServer{address="127.0.0.1:%d", useProxyProtocol=true}

    function addValues(dq)
      local values = { [0]="foo", [42]="bar" }
      dq:setProxyProtocolValues(values)
      return DNSAction.None
    end

    addAction("values-lua.proxy.tests.powerdns.com.", LuaAction(addValues))
    addAction("values-action.proxy.tests.powerdns.com.", SetProxyProtocolValuesAction({ ["1"]="dnsdist", ["255"]="proxy-protocol"}))
    """
    _config_params = ['_proxyResponderPort']
    _verboseMode = True

    def testProxyUDP(self):
        """
        Proxy Protocol: no value (UDP)
        """
        name = 'simple-udp.proxy.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        toProxyQueue.put(response, True, 2.0)

        data = query.to_wire()
        self._sock.send(data)
        receivedResponse = None
        try:
            self._sock.settimeout(2.0)
            data = self._sock.recv(4096)
        except socket.timeout:
            print('timeout')
            data = None
        if data:
            receivedResponse = dns.message.from_wire(data)

        (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
        self.assertTrue(receivedProxyPayload)
        self.assertTrue(receivedDNSData)
        self.assertTrue(receivedResponse)

        receivedQuery = dns.message.from_wire(receivedDNSData)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)
        self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', False)

    def testProxyTCP(self):
      """
        Proxy Protocol: no value (TCP)
      """
      name = 'simple-tcp.proxy.tests.powerdns.com.'
      query = dns.message.make_query(name, 'A', 'IN')
      response = dns.message.make_response(query)

      toProxyQueue.put(response, True, 2.0)

      conn = self.openTCPConnection(2.0)
      data = query.to_wire()
      self.sendTCPQueryOverConnection(conn, data, rawQuery=True)
      receivedResponse = None
      try:
        receivedResponse = self.recvTCPResponseOverConnection(conn)
      except socket.timeout:
            print('timeout')

      (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
      self.assertTrue(receivedProxyPayload)
      self.assertTrue(receivedDNSData)
      self.assertTrue(receivedResponse)

      receivedQuery = dns.message.from_wire(receivedDNSData)
      receivedQuery.id = query.id
      receivedResponse.id = response.id
      self.assertEqual(receivedQuery, query)
      self.assertEqual(receivedResponse, response)
      self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True)

    def testProxyUDPWithValuesFromLua(self):
        """
        Proxy Protocol: values from Lua (UDP)
        """
        name = 'values-lua.proxy.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        toProxyQueue.put(response, True, 2.0)

        data = query.to_wire()
        self._sock.send(data)
        receivedResponse = None
        try:
            self._sock.settimeout(2.0)
            data = self._sock.recv(4096)
        except socket.timeout:
            print('timeout')
            data = None
        if data:
            receivedResponse = dns.message.from_wire(data)

        (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
        self.assertTrue(receivedProxyPayload)
        self.assertTrue(receivedDNSData)
        self.assertTrue(receivedResponse)

        receivedQuery = dns.message.from_wire(receivedDNSData)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)
        self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', False, [ [0, b'foo'] , [ 42, b'bar'] ])

    def testProxyTCPWithValuesFromLua(self):
      """
        Proxy Protocol: values from Lua (TCP)
      """
      name = 'values-lua.proxy.tests.powerdns.com.'
      query = dns.message.make_query(name, 'A', 'IN')
      response = dns.message.make_response(query)

      toProxyQueue.put(response, True, 2.0)

      conn = self.openTCPConnection(2.0)
      data = query.to_wire()
      self.sendTCPQueryOverConnection(conn, data, rawQuery=True)
      receivedResponse = None
      try:
        receivedResponse = self.recvTCPResponseOverConnection(conn)
      except socket.timeout:
            print('timeout')

      (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
      self.assertTrue(receivedProxyPayload)
      self.assertTrue(receivedDNSData)
      self.assertTrue(receivedResponse)

      receivedQuery = dns.message.from_wire(receivedDNSData)
      receivedQuery.id = query.id
      receivedResponse.id = response.id
      self.assertEqual(receivedQuery, query)
      self.assertEqual(receivedResponse, response)
      self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True, [ [0, b'foo'] , [ 42, b'bar'] ])

    def testProxyUDPWithValuesFromAction(self):
        """
        Proxy Protocol: values from Action (UDP)
        """
        name = 'values-action.proxy.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        toProxyQueue.put(response, True, 2.0)

        data = query.to_wire()
        self._sock.send(data)
        receivedResponse = None
        try:
            self._sock.settimeout(2.0)
            data = self._sock.recv(4096)
        except socket.timeout:
            print('timeout')
            data = None
        if data:
            receivedResponse = dns.message.from_wire(data)

        (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
        self.assertTrue(receivedProxyPayload)
        self.assertTrue(receivedDNSData)
        self.assertTrue(receivedResponse)

        receivedQuery = dns.message.from_wire(receivedDNSData)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)
        self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', False, [ [1, b'dnsdist'] , [ 255, b'proxy-protocol'] ])

    def testProxyTCPWithValuesFromAction(self):
      """
        Proxy Protocol: values from Action (TCP)
      """
      name = 'values-action.proxy.tests.powerdns.com.'
      query = dns.message.make_query(name, 'A', 'IN')
      response = dns.message.make_response(query)

      toProxyQueue.put(response, True, 2.0)

      conn = self.openTCPConnection(2.0)
      data = query.to_wire()
      self.sendTCPQueryOverConnection(conn, data, rawQuery=True)
      receivedResponse = None
      try:
        receivedResponse = self.recvTCPResponseOverConnection(conn)
      except socket.timeout:
            print('timeout')

      (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
      self.assertTrue(receivedProxyPayload)
      self.assertTrue(receivedDNSData)
      self.assertTrue(receivedResponse)

      receivedQuery = dns.message.from_wire(receivedDNSData)
      receivedQuery.id = query.id
      receivedResponse.id = response.id
      self.assertEqual(receivedQuery, query)
      self.assertEqual(receivedResponse, response)
      self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True, [ [1, b'dnsdist'] , [ 255, b'proxy-protocol'] ])

    def testProxyTCPSeveralQueriesOnSameConnection(self):
      """
        Proxy Protocol: Several queries on the same TCP connection
      """
      name = 'several-queries-same-conn.proxy.tests.powerdns.com.'
      query = dns.message.make_query(name, 'A', 'IN')
      response = dns.message.make_response(query)

      conn = self.openTCPConnection(2.0)
      data = query.to_wire()

      for idx in range(10):
        toProxyQueue.put(response, True, 2.0)
        self.sendTCPQueryOverConnection(conn, data, rawQuery=True)
        receivedResponse = None
        try:
          receivedResponse = self.recvTCPResponseOverConnection(conn)
        except socket.timeout:
          print('timeout')

        (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
        self.assertTrue(receivedProxyPayload)
        self.assertTrue(receivedDNSData)
        self.assertTrue(receivedResponse)

        receivedQuery = dns.message.from_wire(receivedDNSData)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)
        self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True, [])

class TestProxyProtocolIncoming(ProxyProtocolTest):
    """
    dnsdist is configured to prepend a Proxy Protocol header to the query and expect one on incoming queries
    """

    _config_template = """
    setProxyProtocolACL( { "127.0.0.1/32" } )
    newServer{address="127.0.0.1:%d", useProxyProtocol=true}

    function addValues(dq)
      dq:addProxyProtocolValue(0, 'foo')
      dq:addProxyProtocolValue(42, 'bar')
      return DNSAction.None
    end

    -- refuse queries with no TLV value type 2
    addAction(NotRule(ProxyProtocolValueRule(2)), RCodeAction(DNSRCode.REFUSED))
    -- or with a TLV value type 3 different from "proxy"
    addAction(NotRule(ProxyProtocolValueRule(3, "proxy")), RCodeAction(DNSRCode.REFUSED))

    function answerBasedOnForwardedDest(dq)
      local port = dq.localaddr:getPort()
      local dest = dq.localaddr:toString()
      return DNSAction.Spoof, "address-was-"..dest.."-port-was-"..port..".proxy-protocol-incoming.tests.powerdns.com."
    end
    addAction("get-forwarded-dest.proxy-protocol-incoming.tests.powerdns.com.", LuaAction(answerBasedOnForwardedDest))

    function answerBasedOnForwardedSrc(dq)
      local port = dq.remoteaddr:getPort()
      local src = dq.remoteaddr:toString()
      return DNSAction.Spoof, "address-was-"..src.."-port-was-"..port..".proxy-protocol-incoming.tests.powerdns.com."
    end
    addAction("get-forwarded-src.proxy-protocol-incoming.tests.powerdns.com.", LuaAction(answerBasedOnForwardedSrc))

    -- add these values for all queries
    addAction("proxy-protocol-incoming.tests.powerdns.com.", LuaAction(addValues))
    addAction("proxy-protocol-incoming.tests.powerdns.com.", SetAdditionalProxyProtocolValueAction(1, "dnsdist"))
    addAction("proxy-protocol-incoming.tests.powerdns.com.", SetAdditionalProxyProtocolValueAction(255, "proxy-protocol"))

    -- override all existing values
    addAction("override.proxy-protocol-incoming.tests.powerdns.com.", SetProxyProtocolValuesAction({["50"]="overridden"}))
    """
    _config_params = ['_proxyResponderPort']
    _verboseMode = True

    def testNoHeader(self):
        """
        Incoming Proxy Protocol: no header
        """
        # no proxy protocol header while one is expected, should be dropped
        name = 'no-header.incoming-proxy-protocol.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        for method in ("sendUDPQuery", "sendTCPQuery"):
          sender = getattr(self, method)
          (_, receivedResponse) = sender(query, response=None)
          self.assertEqual(receivedResponse, None)

    def testIncomingProxyDest(self):
        """
        Incoming Proxy Protocol: values from Lua
        """
        name = 'get-forwarded-dest.proxy-protocol-incoming.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        destAddr = "2001:db8::9"
        destPort = 9999
        srcAddr = "2001:db8::8"
        srcPort = 8888
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    "address-was-{}-port-was-{}.proxy-protocol-incoming.tests.powerdns.com.".format(destAddr, destPort, self._dnsDistPort))
        response.answer.append(rrset)

        udpPayload = ProxyProtocol.getPayload(False, False, True, srcAddr, destAddr, srcPort, destPort, [ [ 2, b'foo'], [ 3, b'proxy'] ])
        (_, receivedResponse) = self.sendUDPQuery(udpPayload + query.to_wire(), response=None, useQueue=False, rawQuery=True)
        self.assertEqual(receivedResponse, response)

        tcpPayload = ProxyProtocol.getPayload(False, True, True, srcAddr, destAddr, srcPort, destPort, [ [ 2, b'foo'], [ 3, b'proxy'] ])
        wire = query.to_wire()

        receivedResponse = None
        try:
          conn = self.openTCPConnection(2.0)
          conn.send(tcpPayload)
          conn.send(struct.pack("!H", len(wire)))
          conn.send(wire)
          receivedResponse = self.recvTCPResponseOverConnection(conn)
        except socket.timeout:
          print('timeout')
        self.assertEqual(receivedResponse, response)

    def testProxyUDPWithValuesFromLua(self):
        """
        Incoming Proxy Protocol: values from Lua (UDP)
        """
        name = 'values-lua.proxy-protocol-incoming.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        destAddr = "2001:db8::9"
        destPort = 9999
        srcAddr = "2001:db8::8"
        srcPort = 8888
        response = dns.message.make_response(query)

        udpPayload = ProxyProtocol.getPayload(False, False, True, srcAddr, destAddr, srcPort, destPort, [ [ 2, b'foo'], [ 3, b'proxy'] ])
        toProxyQueue.put(response, True, 2.0)
        (_, receivedResponse) = self.sendUDPQuery(udpPayload + query.to_wire(), response=None, useQueue=False, rawQuery=True)

        (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
        self.assertTrue(receivedProxyPayload)
        self.assertTrue(receivedDNSData)
        self.assertTrue(receivedResponse)

        receivedQuery = dns.message.from_wire(receivedDNSData)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)
        self.checkMessageProxyProtocol(receivedProxyPayload, srcAddr, destAddr, False, [ [0, b'foo'], [1, b'dnsdist'], [ 2, b'foo'], [3, b'proxy'], [ 42, b'bar'], [255, b'proxy-protocol'] ], True, srcPort, destPort)

    def testProxyTCPWithValuesFromLua(self):
        """
        Incoming Proxy Protocol: values from Lua (TCP)
        """
        name = 'values-lua.proxy-protocol-incoming.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        destAddr = "2001:db8::9"
        destPort = 9999
        srcAddr = "2001:db8::8"
        srcPort = 8888
        response = dns.message.make_response(query)

        tcpPayload = ProxyProtocol.getPayload(False, True, True, srcAddr, destAddr, srcPort, destPort, [ [ 2, b'foo'], [ 3, b'proxy'] ])

        toProxyQueue.put(response, True, 2.0)

        wire = query.to_wire()

        receivedResponse = None
        try:
          conn = self.openTCPConnection(2.0)
          conn.send(tcpPayload)
          conn.send(struct.pack("!H", len(wire)))
          conn.send(wire)
          receivedResponse = self.recvTCPResponseOverConnection(conn)
        except socket.timeout:
          print('timeout')
        self.assertEqual(receivedResponse, response)

        (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
        self.assertTrue(receivedProxyPayload)
        self.assertTrue(receivedDNSData)
        self.assertTrue(receivedResponse)

        receivedQuery = dns.message.from_wire(receivedDNSData)
        receivedQuery.id = query.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)
        self.checkMessageProxyProtocol(receivedProxyPayload, srcAddr, destAddr, True, [ [0, b'foo'], [1, b'dnsdist'], [ 2, b'foo'], [3, b'proxy'], [ 42, b'bar'], [255, b'proxy-protocol'] ], True, srcPort, destPort)

    def testProxyUDPWithValueOverride(self):
        """
        Incoming Proxy Protocol: override existing value (UDP)
        """
        name = 'override.proxy-protocol-incoming.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        destAddr = "2001:db8::9"
        destPort = 9999
        srcAddr = "2001:db8::8"
        srcPort = 8888
        response = dns.message.make_response(query)

        udpPayload = ProxyProtocol.getPayload(False, False, True, srcAddr, destAddr, srcPort, destPort, [ [2, b'foo'], [3, b'proxy'], [ 50, b'initial-value']])
        toProxyQueue.put(response, True, 2.0)
        (_, receivedResponse) = self.sendUDPQuery(udpPayload + query.to_wire(), response=None, useQueue=False, rawQuery=True)

        (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
        self.assertTrue(receivedProxyPayload)
        self.assertTrue(receivedDNSData)
        self.assertTrue(receivedResponse)

        receivedQuery = dns.message.from_wire(receivedDNSData)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)
        self.checkMessageProxyProtocol(receivedProxyPayload, srcAddr, destAddr, False, [ [50, b'overridden'] ], True, srcPort, destPort)

    def testProxyTCPSeveralQueriesOverConnection(self):
        """
        Incoming Proxy Protocol: Several queries over the same connection (TCP)
        """
        name = 'several-queries.proxy-protocol-incoming.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        destAddr = "2001:db8::9"
        destPort = 9999
        srcAddr = "2001:db8::8"
        srcPort = 8888

        tcpPayload = ProxyProtocol.getPayload(False, True, True, srcAddr, destAddr, srcPort, destPort, [ [ 2, b'foo'], [ 3, b'proxy'] ])

        toProxyQueue.put(response, True, 2.0)

        wire = query.to_wire()

        receivedResponse = None
        conn = self.openTCPConnection(2.0)
        try:
          conn.send(tcpPayload)
          conn.send(struct.pack("!H", len(wire)))
          conn.send(wire)
          receivedResponse = self.recvTCPResponseOverConnection(conn)
        except socket.timeout:
          print('timeout')
        self.assertEqual(receivedResponse, response)

        (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
        self.assertTrue(receivedProxyPayload)
        self.assertTrue(receivedDNSData)
        self.assertTrue(receivedResponse)

        receivedQuery = dns.message.from_wire(receivedDNSData)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)
        self.checkMessageProxyProtocol(receivedProxyPayload, srcAddr, destAddr, True, [ [0, b'foo'], [1, b'dnsdist'], [ 2, b'foo'], [3, b'proxy'], [ 42, b'bar'], [255, b'proxy-protocol'] ], True, srcPort, destPort)

        for idx in range(5):
          receivedResponse = None
          toProxyQueue.put(response, True, 2.0)
          try:
            conn.send(struct.pack("!H", len(wire)))
            conn.send(wire)
            receivedResponse = self.recvTCPResponseOverConnection(conn)
          except socket.timeout:
            print('timeout')

          self.assertEqual(receivedResponse, response)

          (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
          self.assertTrue(receivedProxyPayload)
          self.assertTrue(receivedDNSData)
          self.assertTrue(receivedResponse)

          receivedQuery = dns.message.from_wire(receivedDNSData)
          receivedQuery.id = query.id
          self.assertEqual(receivedQuery, query)
          self.assertEqual(receivedResponse, response)
          self.checkMessageProxyProtocol(receivedProxyPayload, srcAddr, destAddr, True, [ [0, b'foo'], [1, b'dnsdist'], [ 2, b'foo'], [3, b'proxy'], [ 42, b'bar'], [255, b'proxy-protocol'] ], True, srcPort, destPort)

class TestProxyProtocolNotExpected(DNSDistTest):
    """
    dnsdist is configured to expect a Proxy Protocol header on incoming queries but not from 127.0.0.1
    """

    _config_template = """
    setProxyProtocolACL( { "192.0.2.1/32" } )
    newServer{address="127.0.0.1:%d"}
    """
    # NORMAL responder, does not expect a proxy protocol payload!
    _config_params = ['_testServerPort']
    _verboseMode = True

    def testNoHeader(self):
        """
        Unexpected Proxy Protocol: no header
        """
        # no proxy protocol header and none is expected from this source, should be passed on
        name = 'no-header.unexpected-proxy-protocol.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
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
          self.assertEqual(response, receivedResponse)

    def testIncomingProxyDest(self):
        """
        Unexpected Proxy Protocol: should be dropped
        """
        name = 'with-proxy-payload.unexpected-protocol-incoming.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        # Make sure that the proxy payload does NOT turn into a legal qname
        destAddr = "ff:db8::ffff"
        destPort = 65535
        srcAddr = "ff:db8::ffff"
        srcPort = 65535

        udpPayload = ProxyProtocol.getPayload(False, False, True, srcAddr, destAddr, srcPort, destPort, [ [ 2, b'foo'], [ 3, b'proxy'] ])
        (_, receivedResponse) = self.sendUDPQuery(udpPayload + query.to_wire(), response=None, useQueue=False, rawQuery=True)
        self.assertEqual(receivedResponse, None)

        tcpPayload = ProxyProtocol.getPayload(False, True, True, srcAddr, destAddr, srcPort, destPort, [ [ 2, b'foo'], [ 3, b'proxy'] ])
        wire = query.to_wire()

        receivedResponse = None
        try:
          conn = self.openTCPConnection(2.0)
          conn.send(tcpPayload)
          conn.send(struct.pack("!H", len(wire)))
          conn.send(wire)
          receivedResponse = self.recvTCPResponseOverConnection(conn)
        except socket.timeout:
          print('timeout')
        self.assertEqual(receivedResponse, None)

class TestDOHWithOutgoingProxyProtocol(DNSDistDOHTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/dns-query" % (_serverName, _dohServerPort))
    _proxyResponderPort = proxyResponderPort
    _config_template = """
    newServer{address="127.0.0.1:%s", useProxyProtocol=true}
    addDOHLocal("127.0.0.1:%s", "%s", "%s", { '/dns-query' }, { trustForwardedForHeader=true })
    setACL( { "::1/128", "127.0.0.0/8" } )
    """
    _config_params = ['_proxyResponderPort', '_dohServerPort', '_serverCert', '_serverKey']

    def testTruncation(self):
        """
        DOH: Truncation over UDP (with cache)
        """
        # the query is first forwarded over UDP, leading to a TC=1 answer from the
        # backend, then over TCP
        name = 'truncated-udp.doh-with-cache.tests.powerdns.com.'
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
        toProxyQueue.put(tcResponse, True, 2.0)

        ((receivedProxyPayload, receivedDNSData), receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, response=response, fromQueue=fromProxyQueue, toQueue=toProxyQueue)
        # first query, received by the responder over UDP
        self.assertTrue(receivedProxyPayload)
        self.assertTrue(receivedDNSData)
        receivedQuery = dns.message.from_wire(receivedDNSData)
        self.assertTrue(receivedQuery)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True, destinationPort=self._dohServerPort)

        # check the response
        self.assertTrue(receivedResponse)
        self.assertEqual(response, receivedResponse)

        # check the second query, received by the responder over TCP
        (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
        self.assertTrue(receivedDNSData)
        receivedQuery = dns.message.from_wire(receivedDNSData)
        self.assertTrue(receivedQuery)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True, destinationPort=self._dohServerPort)

        # make sure we consumed everything
        self.assertTrue(toProxyQueue.empty())
        self.assertTrue(fromProxyQueue.empty())

    def testAddressFamilyMismatch(self):
        """
        DOH with IPv6 X-Forwarded-For to an IPv4 endpoint
        """
        name = 'x-forwarded-for-af-mismatch.doh.outgoing-proxy-protocol.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        # the query should be dropped
        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, customHeaders=['x-forwarded-for: [::1]:8080'], useQueue=False)
        self.assertFalse(receivedQuery)
        self.assertFalse(receivedResponse)

        # make sure the timeout is detected, if any
        time.sleep(4)

        # this one should not
        ((receivedProxyPayload, receivedDNSData), receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, customHeaders=['x-forwarded-for: 127.0.0.42:8080'], response=response, fromQueue=fromProxyQueue, toQueue=toProxyQueue)
        self.assertTrue(receivedProxyPayload)
        self.assertTrue(receivedDNSData)
        receivedQuery = dns.message.from_wire(receivedDNSData)
        self.assertTrue(receivedQuery)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.42', '127.0.0.1', True, destinationPort=self._dohServerPort)
        # check the response
        self.assertTrue(receivedResponse)
        receivedResponse.id = response.id
        self.assertEqual(response, receivedResponse)
