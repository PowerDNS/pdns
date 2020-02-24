#!/usr/bin/env python

import dns
import socket
import struct
import sys
import threading

from dnsdisttests import DNSDistTest
from proxyprotocol import ProxyProtocol

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

        data = conn.recv(2)
        (datalen,) = struct.unpack("!H", data)

        data = conn.recv(datalen)

        toQueue.put([payload, data], True, 2.0)

        response = fromQueue.get(True, 2.0)
        if not response:
            conn.close()
            continue

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
proxyResponderPort = 5470

udpResponder = threading.Thread(name='UDP Proxy Protocol Responder', target=ProxyProtocolUDPResponder, args=[proxyResponderPort, toProxyQueue, fromProxyQueue])
udpResponder.setDaemon(True)
udpResponder.start()
tcpResponder = threading.Thread(name='TCP Proxy Protocol Responder', target=ProxyProtocolTCPResponder, args=[proxyResponderPort, toProxyQueue, fromProxyQueue])
tcpResponder.setDaemon(True)
tcpResponder.start()

class ProxyProtocolTest(DNSDistTest):
    _proxyResponderPort = proxyResponderPort
    _config_params = ['_proxyResponderPort']

    def checkMessageProxyProtocol(self, receivedProxyPayload, source, destination, isTCP, values=[]):
      proxy = ProxyProtocol()
      self.assertTrue(proxy.parseHeader(receivedProxyPayload))
      self.assertEquals(proxy.version, 0x02)
      self.assertEquals(proxy.command, 0x01)
      self.assertEquals(proxy.family, 0x01)
      if not isTCP:
        self.assertEquals(proxy.protocol, 0x02)
      else:
        self.assertEquals(proxy.protocol, 0x01)
      self.assertGreater(proxy.contentLen, 0)

      self.assertTrue(proxy.parseAddressesAndPorts(receivedProxyPayload))
      self.assertEquals(proxy.source, source)
      self.assertEquals(proxy.destination, destination)
      #self.assertEquals(proxy.sourcePort, sourcePort)
      self.assertEquals(proxy.destinationPort, self._dnsDistPort)

      self.assertTrue(proxy.parseAdditionalValues(receivedProxyPayload))
      proxy.values.sort()
      values.sort()
      self.assertEquals(proxy.values, values)

class TestProxyProtocol(ProxyProtocolTest):
    """
    dnsdist is configured to prepend a Proxy Protocol header to the query
    """

    _config_template = """
    newServer{address="127.0.0.1:%d", useProxyProtocol=true}

    function addValues(dq)
      local values = { ["0"]="foo", ["42"]="bar" }
      dq:setProxyProtocolValues(values)
      return DNSAction.None
    end

    addAction("values-lua.proxy.tests.powerdns.com.", LuaAction(addValues))
    addAction("values-action.proxy.tests.powerdns.com.", SetProxyProtocolValuesAction({ ["1"]="dnsdist", ["255"]="proxy-protocol"}))
    """
    _config_params = ['_proxyResponderPort']

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
        self.assertEquals(receivedQuery, query)
        self.assertEquals(receivedResponse, response)
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
      self.assertEquals(receivedQuery, query)
      self.assertEquals(receivedResponse, response)
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
        self.assertEquals(receivedQuery, query)
        self.assertEquals(receivedResponse, response)
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
      self.assertEquals(receivedQuery, query)
      self.assertEquals(receivedResponse, response)
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
        self.assertEquals(receivedQuery, query)
        self.assertEquals(receivedResponse, response)
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
      self.assertEquals(receivedQuery, query)
      self.assertEquals(receivedResponse, response)
      self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True, [ [1, b'dnsdist'] , [ 255, b'proxy-protocol'] ])
