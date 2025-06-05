#!/usr/bin/env python

import dns
import selectors
import socket
import ssl
import requests
import struct
import sys
import threading
import time

from dnsdisttests import DNSDistTest, pickAvailablePort
from proxyprotocol import ProxyProtocol
from proxyprotocolutils import ProxyProtocolUDPResponder, ProxyProtocolTCPResponder
from dnsdistdohtests import DNSDistDOHTest

# Python2/3 compatibility hacks
try:
  from queue import Queue
except ImportError:
  from Queue import Queue

toProxyQueue = Queue()
fromProxyQueue = Queue()
proxyResponderPort = pickAvailablePort()

udpResponder = threading.Thread(name='UDP Proxy Protocol Responder', target=ProxyProtocolUDPResponder, args=[proxyResponderPort, toProxyQueue, fromProxyQueue])
udpResponder.daemon = True
udpResponder.start()
tcpResponder = threading.Thread(name='TCP Proxy Protocol Responder', target=ProxyProtocolTCPResponder, args=[proxyResponderPort, toProxyQueue, fromProxyQueue])
tcpResponder.daemon = True
tcpResponder.start()

backgroundThreads = {}

def MockTCPReverseProxyAddingProxyProtocol(listeningPort, forwardingPort, serverCtx=None, ca=None, sni=None):
    # this responder accepts TCP connections on the listening port,
    # and relay the raw content to a second TCP connection to the
    # forwarding port, after adding a Proxy Protocol v2 payload
    # containing the initial source IP and port, destination IP
    # and port.
    backgroundThreads[threading.get_native_id()] = True

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    if serverCtx is not None:
        sock = serverCtx.wrap_socket(sock, server_side=True)

    try:
        sock.bind(("127.0.0.1", listeningPort))
    except socket.error as e:
        print("Error binding in the Mock TCP reverse proxy: %s" % str(e))
        sys.exit(1)
    sock.settimeout(0.5)
    sock.listen(100)

    while True:
        try:
            (incoming, _) = sock.accept()
        except socket.timeout:
            if backgroundThreads.get(threading.get_native_id(), False) == False:
                del backgroundThreads[threading.get_native_id()]
                break
            else:
              continue

        incoming.settimeout(5.0)
        payload = ProxyProtocol.getPayload(False, True, False, '127.0.0.1', '127.0.0.1', incoming.getpeername()[1], listeningPort, [ [ 2, b'foo'], [ 3, b'proxy'] ])

        outgoing = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        outgoing.settimeout(2.0)
        if sni:
            if hasattr(ssl, 'create_default_context'):
                sslctx = ssl.create_default_context(cafile=ca)
                if hasattr(sslctx, 'set_alpn_protocols'):
                    sslctx.set_alpn_protocols(['h2'])
                outgoing = sslctx.wrap_socket(outgoing, server_hostname=sni)
            else:
                outgoing = ssl.wrap_socket(outgoing, ca_certs=ca, cert_reqs=ssl.CERT_REQUIRED)

        outgoing.connect(('127.0.0.1', forwardingPort))

        outgoing.send(payload)

        sel = selectors.DefaultSelector()
        def readFromClient(conn):
            data = conn.recv(512)
            if not data or len(data) == 0:
              return False
            outgoing.send(data)
            return True

        def readFromBackend(conn):
            data = conn.recv(512)
            if not data or len(data) == 0:
              return False
            incoming.send(data)
            return True

        sel.register(incoming, selectors.EVENT_READ, readFromClient)
        sel.register(outgoing, selectors.EVENT_READ, readFromBackend)
        done = False
        while not done:
          try:
            events = sel.select()
            for key, mask in events:
              if not (key.data)(key.fileobj):
                done = True
                break
          except socket.timeout:
            break
          except:
            break

        incoming.close()
        outgoing.close()

    sock.close()

class ProxyProtocolTest(DNSDistTest):
    _proxyResponderPort = proxyResponderPort
    _config_params = ['_proxyResponderPort']

class TestProxyProtocol(ProxyProtocolTest):
    """
    dnsdist is configured to prepend a Proxy Protocol header to the query
    """

    _config_template = """
    newServer{address="127.0.0.1:%d", useProxyProtocol=true}

    webserver("127.0.0.1:%d")
    setWebserverConfig{password="%s", apiKey="%s"}

    function addValues(dq)
      local values = { [0]="foo", [42]="bar" }
      dq:setProxyProtocolValues(values)
      return DNSAction.None
    end

    local counter = 1
    function addRandomValue(dq)
      dq:addProxyProtocolValue(0xEE, tostring(counter))
      counter = counter + 1
      return DNSAction.None
    end

    addAction("values-lua.proxy.tests.powerdns.com.", LuaAction(addValues))
    addAction("values-action.proxy.tests.powerdns.com.", SetProxyProtocolValuesAction({ ["1"]="dnsdist", ["255"]="proxy-protocol"}))
    addAction("random-values.proxy.tests.powerdns.com.", LuaAction(addRandomValue))
    """
    _webServerPort = pickAvailablePort()
    _webServerBasicAuthPassword = 'secret'
    _webServerBasicAuthPasswordHashed = '$scrypt$ln=10,p=1,r=8$6DKLnvUYEeXWh3JNOd3iwg==$kSrhdHaRbZ7R74q3lGBqO1xetgxRxhmWzYJ2Qvfm7JM='
    _webServerAPIKey = 'apisecret'
    _webServerAPIKeyHashed = '$scrypt$ln=10,p=1,r=8$9v8JxDfzQVyTpBkTbkUqYg==$bDQzAOHeK1G9UvTPypNhrX48w974ZXbFPtRKS34+aso='
    _config_params = ['_proxyResponderPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']

    def getServerStats(self):
      headers = {'x-api-key': self._webServerAPIKey}
      url = 'http://127.0.0.1:' + str(self._webServerPort) + '/api/v1/servers/localhost'
      r = requests.get(url, headers=headers, timeout=1)
      self.assertTrue(r)
      self.assertEqual(r.status_code, 200)
      self.assertTrue(r.json())
      content = r.json()
      return content['servers']

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

      new_conn_before = self.getServerStats()[0]['tcpNewConnections']
      reused_conn_before = self.getServerStats()[0]['tcpReusedConnections']

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

      # check:
      # - only one concurrent connection to the backend
      # - no more than 1 new connection to the backend was opened
      server = self.getServerStats()[0]
      self.assertEqual(server['tcpNewConnections'], new_conn_before + 1)
      self.assertEqual(server['tcpReusedConnections'], reused_conn_before + 9)
      self.assertEqual(server['tcpMaxConcurrentConnections'], 1)

    def testProxyTCPSeveralQueriesWithRandomTLVOnSameConnection(self):
      """
        Proxy Protocol: Several queries with random TLV on the same TCP connection
      """
      name = 'random-values.proxy.tests.powerdns.com.'
      query = dns.message.make_query(name, 'A', 'IN')
      response = dns.message.make_response(query)

      stats = self.getServerStats()[0]
      max_conns_before = stats['tcpMaxConcurrentConnections']
      current_conns_before = stats['tcpCurrentConnections']
      new_conn_before = stats['tcpNewConnections']
      reused_conn_before = stats['tcpReusedConnections']

      conn = self.openTCPConnection(2.0)
      data = query.to_wire()

      number_of_queries = 10
      for idx in range(number_of_queries):
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
        self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True, [[238, str(idx + 1).encode('UTF-8')]])

      # check:
      # - only one concurrent connection to the backend
      # - no more than number_of_queries connections to the backend were opened
      server = self.getServerStats()[0]
      self.assertEqual(server['tcpNewConnections'], new_conn_before + number_of_queries)
      self.assertEqual(server['tcpReusedConnections'], reused_conn_before)
      # in some cases existing (established before this test) connections to the backend might still
      # exist, so we cannot enforce a strict "only 1 connection" check
      self.assertLessEqual(server['tcpMaxConcurrentConnections'], max_conns_before + 1)
      # but if we managed to add more than two connections to the existing ones, something is
      # wrong!
      # why two and not one? when a query arrives we retrieve the "owned" outgoing connection to the backend,
      # and we notice that the TLVs are different than the previous ones, so we discard the outgoing connection
      # and create a new one. This should lead to only one concurrent connection, except that if we read the
      # new query while being called from the function handling the response from the backend, we might still
      # hold a shared reference to the previous connection. It will be released when we come back to the calling
      # function, but for a short time we will have two concurrent connections.
      self.assertLessEqual(server['tcpMaxConcurrentConnections'], current_conns_before + 2)

class TestProxyProtocolIncoming(ProxyProtocolTest):
    """
    dnsdist is configured to prepend a Proxy Protocol header to the query and expect one on incoming queries
    """

    _config_template = """
    addDOHLocal("127.0.0.1:%d", "%s", "%s", {"/"}, {library='nghttp2', proxyProtocolOutsideTLS=true})
    addDOHLocal("127.0.0.1:%d", "%s", "%s", {"/"}, {library='nghttp2', proxyProtocolOutsideTLS=false})
    addTLSLocal("127.0.0.1:%d", "%s", "%s", {proxyProtocolOutsideTLS=true})
    addTLSLocal("127.0.0.1:%d", "%s", "%s", {proxyProtocolOutsideTLS=false})
    setProxyProtocolACL( { "127.0.0.1/32" } )
    newServer{address="127.0.0.1:%d", useProxyProtocol=true, proxyProtocolAdvertiseTLS=true}

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
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPPOutsidePort = pickAvailablePort()
    _dohServerPPInsidePort = pickAvailablePort()
    _dotServerPPOutsidePort = pickAvailablePort()
    _dotServerPPInsidePort = pickAvailablePort()
    _config_params = ['_dohServerPPOutsidePort', '_serverCert', '_serverKey', '_dohServerPPInsidePort', '_serverCert', '_serverKey', '_dotServerPPOutsidePort', '_serverCert', '_serverKey', '_dotServerPPInsidePort', '_serverCert', '_serverKey', '_proxyResponderPort']

    def testNoHeader(self):
        """
        Incoming Proxy Protocol: no header
        """
        # no proxy protocol header while one is expected, should be dropped
        name = 'no-header.incoming-proxy-protocol.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        for method in ("sendUDPQuery", "sendTCPQuery", "sendDOHQueryWrapper"):
          sender = getattr(self, method)
          try:
            (_, receivedResponse) = sender(query, response=None)
          except Exception:
            receivedResponse = None
          self.assertEqual(receivedResponse, None)

    def testIncomingProxyDest(self):
        """
        Incoming Proxy Protocol: get forwarded destination
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

    def testProxyDoHSeveralQueriesOverConnectionPPOutside(self):
        """
        Incoming Proxy Protocol: Several queries over the same connection (DoH, PP outside TLS)
        """
        name = 'several-queries.doh-outside.proxy-protocol-incoming.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        toProxyQueue.put(response, True, 2.0)

        wire = query.to_wire()

        reverseProxyPort = pickAvailablePort()
        reverseProxy = threading.Thread(name='Mock Proxy Protocol Reverse Proxy', target=MockTCPReverseProxyAddingProxyProtocol, args=[reverseProxyPort, self._dohServerPPOutsidePort])
        reverseProxy.start()
        time.sleep(1)

        receivedResponse = None
        conn = self.openDOHConnection(reverseProxyPort, self._caCert, timeout=2.0)

        reverseProxyBaseURL = ("https://%s:%d/" % (self._serverName, reverseProxyPort))
        (receivedQuery, receivedResponse) = self.sendDOHQuery(reverseProxyPort, self._serverName, reverseProxyBaseURL, query, response=response, caFile=self._caCert, conn=conn)
        (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
        self.assertTrue(receivedProxyPayload)
        self.assertTrue(receivedDNSData)
        self.assertTrue(receivedResponse)

        receivedQuery = dns.message.from_wire(receivedDNSData)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)
        self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True, [ [0, b'foo'], [1, b'dnsdist'], [ 2, b'foo'], [3, b'proxy'], [32, ''], [42, b'bar'], [255, b'proxy-protocol'] ], v6=False, sourcePort=None, destinationPort=reverseProxyPort)

        for idx in range(5):
          receivedResponse = None
          toProxyQueue.put(response, True, 2.0)
          (receivedQuery, receivedResponse) = self.sendDOHQuery(reverseProxyPort, self._serverName, reverseProxyBaseURL, query, response=response, caFile=self._caCert, conn=conn)
          (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
          self.assertTrue(receivedProxyPayload)
          self.assertTrue(receivedDNSData)
          self.assertTrue(receivedResponse)

          receivedQuery = dns.message.from_wire(receivedDNSData)
          receivedQuery.id = query.id
          receivedResponse.id = response.id
          self.assertEqual(receivedQuery, query)
          self.assertEqual(receivedResponse, response)
          self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True, [ [0, b'foo'], [1, b'dnsdist'], [ 2, b'foo'], [3, b'proxy'], [32, ''], [42, b'bar'], [255, b'proxy-protocol'] ], v6=False, sourcePort=None, destinationPort=reverseProxyPort)

    def testProxyDoHSeveralQueriesOverConnectionPPInside(self):
        """
        Incoming Proxy Protocol: Several queries over the same connection (DoH, PP inside TLS)
        """
        name = 'several-queries.doh-inside.proxy-protocol-incoming.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        toProxyQueue.put(response, True, 2.0)

        wire = query.to_wire()

        reverseProxyPort = pickAvailablePort()
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain(self._serverCert, self._serverKey)
        tlsContext.set_alpn_protocols(['h2'])
        reverseProxy = threading.Thread(name='Mock Proxy Protocol Reverse Proxy', target=MockTCPReverseProxyAddingProxyProtocol, args=[reverseProxyPort, self._dohServerPPInsidePort, tlsContext, self._caCert, self._serverName])
        reverseProxy.start()

        receivedResponse = None
        time.sleep(1)
        conn = self.openDOHConnection(reverseProxyPort, self._caCert, timeout=2.0)

        reverseProxyBaseURL = ("https://%s:%d/" % (self._serverName, reverseProxyPort))
        (receivedQuery, receivedResponse) = self.sendDOHQuery(reverseProxyPort, self._serverName, reverseProxyBaseURL, query, response=response, caFile=self._caCert, conn=conn)
        (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
        self.assertTrue(receivedProxyPayload)
        self.assertTrue(receivedDNSData)
        self.assertTrue(receivedResponse)

        receivedQuery = dns.message.from_wire(receivedDNSData)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)
        self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True, [ [0, b'foo'], [1, b'dnsdist'], [ 2, b'foo'], [3, b'proxy'], [32, ''], [ 42, b'bar'], [255, b'proxy-protocol'] ], v6=False, sourcePort=None, destinationPort=reverseProxyPort)

        for idx in range(5):
          receivedResponse = None
          toProxyQueue.put(response, True, 2.0)
          (receivedQuery, receivedResponse) = self.sendDOHQuery(reverseProxyPort, self._serverName, reverseProxyBaseURL, query, response=response, caFile=self._caCert, conn=conn)
          (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
          self.assertTrue(receivedProxyPayload)
          self.assertTrue(receivedDNSData)
          self.assertTrue(receivedResponse)

          receivedQuery = dns.message.from_wire(receivedDNSData)
          receivedQuery.id = query.id
          receivedResponse.id = response.id
          self.assertEqual(receivedQuery, query)
          self.assertEqual(receivedResponse, response)
          self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True, [ [0, b'foo'], [1, b'dnsdist'], [ 2, b'foo'], [3, b'proxy'], [32, ''], [ 42, b'bar'], [255, b'proxy-protocol'] ], v6=False, sourcePort=None, destinationPort=reverseProxyPort)

    def testProxyDoTSeveralQueriesOverConnectionPPOutside(self):
        """
        Incoming Proxy Protocol: Several queries over the same connection (DoT, PP outside TLS)
        """
        name = 'several-queries.dot-outside.proxy-protocol-incoming.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        toProxyQueue.put(response, True, 2.0)

        wire = query.to_wire()

        reverseProxyPort = pickAvailablePort()
        reverseProxy = threading.Thread(name='Mock Proxy Protocol Reverse Proxy', target=MockTCPReverseProxyAddingProxyProtocol, args=[reverseProxyPort, self._dotServerPPOutsidePort])
        reverseProxy.start()
        time.sleep(1)

        receivedResponse = None
        conn = self.openTLSConnection(reverseProxyPort, self._serverName, self._caCert, timeout=2.0)
        self.sendTCPQueryOverConnection(conn, query, response=response)
        receivedResponse = self.recvTCPResponseOverConnection(conn)
        (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
        self.assertTrue(receivedProxyPayload)
        self.assertTrue(receivedDNSData)
        self.assertTrue(receivedResponse)

        receivedQuery = dns.message.from_wire(receivedDNSData)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)
        self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True, [ [0, b'foo'], [1, b'dnsdist'], [ 2, b'foo'], [3, b'proxy'], [32, ''], [42, b'bar'], [255, b'proxy-protocol'] ], v6=False, sourcePort=None, destinationPort=reverseProxyPort)

        for idx in range(5):
          receivedResponse = None
          toProxyQueue.put(response, True, 2.0)
          self.sendTCPQueryOverConnection(conn, query, response=response)
          receivedResponse = self.recvTCPResponseOverConnection(conn)
          (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
          self.assertTrue(receivedProxyPayload)
          self.assertTrue(receivedDNSData)
          self.assertTrue(receivedResponse)

          receivedQuery = dns.message.from_wire(receivedDNSData)
          receivedQuery.id = query.id
          receivedResponse.id = response.id
          self.assertEqual(receivedQuery, query)
          self.assertEqual(receivedResponse, response)
          self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True, [ [0, b'foo'], [1, b'dnsdist'], [ 2, b'foo'], [3, b'proxy'], [32, ''], [42, b'bar'], [255, b'proxy-protocol'] ], v6=False, sourcePort=None, destinationPort=reverseProxyPort)

    def testProxyDoTSeveralQueriesOverConnectionPPInside(self):
        """
        Incoming Proxy Protocol: Several queries over the same connection (DoT, PP inside TLS)
        """
        name = 'several-queries.dot-inside.proxy-protocol-incoming.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        toProxyQueue.put(response, True, 2.0)

        wire = query.to_wire()

        reverseProxyPort = pickAvailablePort()
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain(self._serverCert, self._serverKey)
        tlsContext.set_alpn_protocols(['dot'])
        reverseProxy = threading.Thread(name='Mock Proxy Protocol Reverse Proxy', target=MockTCPReverseProxyAddingProxyProtocol, args=[reverseProxyPort, self._dotServerPPInsidePort, tlsContext, self._caCert, self._serverName])
        reverseProxy.start()

        receivedResponse = None
        time.sleep(1)
        conn = self.openTLSConnection(reverseProxyPort, self._serverName, self._caCert, timeout=2.0)

        self.sendTCPQueryOverConnection(conn, query, response=response)
        receivedResponse = self.recvTCPResponseOverConnection(conn)
        (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
        self.assertTrue(receivedProxyPayload)
        self.assertTrue(receivedDNSData)
        self.assertTrue(receivedResponse)

        receivedQuery = dns.message.from_wire(receivedDNSData)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)

        for idx in range(5):
          receivedResponse = None
          toProxyQueue.put(response, True, 2.0)
          self.sendTCPQueryOverConnection(conn, query, response=response)
          receivedResponse = self.recvTCPResponseOverConnection(conn)
          (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
          self.assertTrue(receivedProxyPayload)
          self.assertTrue(receivedDNSData)
          self.assertTrue(receivedResponse)

          receivedQuery = dns.message.from_wire(receivedDNSData)
          receivedQuery.id = query.id
          receivedResponse.id = response.id
          self.assertEqual(receivedQuery, query)
          self.assertEqual(receivedResponse, response)

    @classmethod
    def tearDownClass(cls):
        cls._sock.close()
        for backgroundThread in cls._backgroundThreads:
            cls._backgroundThreads[backgroundThread] = False
        for backgroundThread in backgroundThreads:
            backgroundThreads[backgroundThread] = False
        cls.killProcess(cls._dnsdist)

class TestProxyProtocolIncomingValuesViaLua(DNSDistTest):
    """
    Check that dnsdist can retrieve incoming Proxy Protocol TLV values via Lua
    """

    _config_template = """
    setProxyProtocolACL( { "127.0.0.1/32" } )

    function checkValues(dq)
      if dq.localaddr:toStringWithPort() ~= '[2001:db8::9]:9999' then
        return DNSAction.Spoof, "invalid.local.addr."
      end
      if dq.remoteaddr:toStringWithPort() ~= '[2001:db8::8]:8888' then
        return DNSAction.Spoof, "invalid.remote.addr."
      end
      local values = dq:getProxyProtocolValues()
      if #values ~= 3 then
        return DNSAction.Spoof, #values .. ".invalid.values.count."
      end
      if values[2] ~= 'foo' then
        return DNSAction.Spoof, "2.foo.value.missing."
      end
      if values[3] ~= 'proxy' then
        return DNSAction.Spoof, "3.proxy.value.missing."
      end
      return DNSAction.Spoof, "ok."
    end

    local ffi = require("ffi")
    local C = ffi.C
    ffi.cdef[[
      typedef unsigned int socklen_t;
      const char *inet_ntop(int af, const void *restrict src,
                      char *restrict dst, socklen_t size);
    ]]
    local ret_ptr = ffi.new("const char *[1]")
    local ret_ptr_param = ffi.cast("const void **", ret_ptr)
    local ret_size = ffi.new("size_t[1]")
    local ret_size_param = ffi.cast("size_t*", ret_size)
    local ret_pp_ptr = ffi.new("const dnsdist_ffi_proxy_protocol_value_t*[1]")
    local ret_pp_ptr_param = ffi.cast("const dnsdist_ffi_proxy_protocol_value_t**", ret_pp_ptr)
    local inet_buffer = ffi.new("char[?]", 256)

    function sendResult(dqffi, str)
      C.dnsdist_ffi_dnsquestion_set_result(dqffi, str, #str)
      return DNSAction.Spoof
    end

    function checkValuesFFI(dqffi)
      C.dnsdist_ffi_dnsquestion_get_localaddr(dqffi, ret_ptr_param, ret_size_param)
      local addr = C.inet_ntop(10, ret_ptr[0], inet_buffer, 256)
      if addr == nil or ffi.string(addr) ~= '2001:db8::9' then
        return sendResult(dqffi, "invalid.local.addr.")
      end
      C.dnsdist_ffi_dnsquestion_get_remoteaddr(dqffi, ret_ptr_param, ret_size_param)
      local addr = C.inet_ntop(10, ret_ptr[0], inet_buffer, 256)
      if addr == nil or ffi.string(addr) ~= '2001:db8::8' then
        return sendResult(dqffi, "invalid.remote.addr.")
      end

      local count = tonumber(C.dnsdist_ffi_dnsquestion_get_proxy_protocol_values(dqffi, ret_pp_ptr_param))
      if count ~= 2 then
        return sendResult(dqffi, count .. ".invalid.values.count.")
      end

      local foo_seen = false
      local proxy_seen = false
      for counter = 0, count - 1 do
        local entry = ret_pp_ptr[0][counter]
        if entry.type == 2 and ffi.string(entry.value, entry.size) == 'foo' then
          foo_seen = true
        elseif entry.type == 3 and ffi.string(entry.value, entry.size) == 'proxy' then
          proxy_seen = true
        end
      end
      if not foo_seen then
        return sendResult(dqffi, "2.foo.value.missing.")
      end
      if not proxy_seen then
        return sendResult(dqffi, "3.proxy.value.missing.")
      end

      return sendResult(dqffi, "ok.")
    end

    addAction("proxy-protocol-incoming-values-via-lua.tests.powerdns.com.", LuaAction(checkValues))
    addAction("proxy-protocol-incoming-values-via-lua-ffi.tests.powerdns.com.", LuaFFIAction(checkValuesFFI))

    newServer{address="127.0.0.1:%d"}
    """

    def testProxyUDPWithValuesFromLua(self):
        """
        Incoming Proxy Protocol: values from Lua
        """
        destAddr = "2001:db8::9"
        destPort = 9999
        srcAddr = "2001:db8::8"
        srcPort = 8888
        names = ['proxy-protocol-incoming-values-via-lua.tests.powerdns.com.',
                 'proxy-protocol-incoming-values-via-lua-ffi.tests.powerdns.com.'
                 ]
        for name in names:
            query = dns.message.make_query(name, 'A', 'IN')
            # dnsdist set RA = RD for spoofed responses
            query.flags &= ~dns.flags.RD
            response = dns.message.make_response(query)

            expectedResponse = dns.message.make_response(query)
            rrset = dns.rrset.from_text(name,
                                        60,
                                        dns.rdataclass.IN,
                                        dns.rdatatype.CNAME,
                                        'ok.')
            expectedResponse.answer.append(rrset)

            udpPayload = ProxyProtocol.getPayload(False, False, True, srcAddr, destAddr, srcPort, destPort, [ [ 2, b'foo'], [ 3, b'proxy'] ])
            (_, receivedResponse) = self.sendUDPQuery(udpPayload + query.to_wire(), response=None, useQueue=False, rawQuery=True)
            self.assertEqual(expectedResponse, receivedResponse)

            conn = self.openTCPConnection(2.0)
            try:
                conn.send(udpPayload)
                conn.send(struct.pack("!H", len(query.to_wire())))
                conn.send(query.to_wire())
                receivedResponse = self.recvTCPResponseOverConnection(conn)
            except socket.timeout:
                print('timeout')
            self.assertEqual(expectedResponse, receivedResponse)

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

class TestProxyProtocolNotAllowedOnBind(DNSDistTest):
    """
    dnsdist is configured to expect a Proxy Protocol header on incoming queries but not on the 127.0.0.1 bind
    """
    _skipListeningOnCL = True
    _config_template = """
    -- proxy protocol payloads are not allowed on this bind address!
    addLocal('127.0.0.1:%d', {enableProxyProtocol=false})
    setProxyProtocolACL( { "127.0.0.1/8" } )
    newServer{address="127.0.0.1:%d"}
    """
    # NORMAL responder, does not expect a proxy protocol payload!
    _config_params = ['_dnsDistPort', '_testServerPort']

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
    _dohWithNGHTTP2ServerPort = pickAvailablePort()
    _dohWithNGHTTP2BaseURL = ("https://%s:%d/dns-query" % (_serverName, _dohWithNGHTTP2ServerPort))
    _dohWithH2OServerPort = pickAvailablePort()
    _dohWithH2OBaseURL = ("https://%s:%d/dns-query" % (_serverName, _dohWithH2OServerPort))
    _proxyResponderPort = proxyResponderPort
    _config_template = """
    newServer{address="127.0.0.1:%s", useProxyProtocol=true}
    addDOHLocal("127.0.0.1:%d", "%s", "%s", { '/dns-query' }, { trustForwardedForHeader=true, library='nghttp2' })
    addDOHLocal("127.0.0.1:%d", "%s", "%s", { '/dns-query' }, { trustForwardedForHeader=true, library='h2o' })
    setACL( { "::1/128", "127.0.0.0/8" } )
    """
    _config_params = ['_proxyResponderPort', '_dohWithNGHTTP2ServerPort', '_serverCert', '_serverKey', '_dohWithH2OServerPort', '_serverCert', '_serverKey']

    def testTruncation(self):
        """
        DOH: Truncation over UDP
        """
        # the query is first forwarded over UDP, leading to a TC=1 answer from the
        # backend, then over TCP
        name = 'truncated-udp.doh.proxy-protocol.tests.powerdns.com.'
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

        for (port,url) in [(self._dohWithNGHTTP2ServerPort, self._dohWithNGHTTP2BaseURL), (self._dohWithH2OServerPort, self._dohWithH2OBaseURL)]:
          # first response is a TC=1
          tcResponse = dns.message.make_response(query)
          tcResponse.flags |= dns.flags.TC
          toProxyQueue.put(tcResponse, True, 2.0)

          ((receivedProxyPayload, receivedDNSData), receivedResponse) = self.sendDOHQuery(port, self._serverName, url, query, caFile=self._caCert, response=response, fromQueue=fromProxyQueue, toQueue=toProxyQueue)
          # first query, received by the responder over UDP
          self.assertTrue(receivedProxyPayload)
          self.assertTrue(receivedDNSData)
          receivedQuery = dns.message.from_wire(receivedDNSData)
          self.assertTrue(receivedQuery)
          receivedQuery.id = expectedQuery.id
          self.assertEqual(expectedQuery, receivedQuery)
          self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
          self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True, destinationPort=port)

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
          self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True, destinationPort=port)

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

        for (port,url) in [(self._dohWithNGHTTP2ServerPort, self._dohWithNGHTTP2BaseURL), (self._dohWithH2OServerPort, self._dohWithH2OBaseURL)]:
          # the query should be dropped
          (receivedQuery, receivedResponse) = self.sendDOHQuery(port, self._serverName, url, query, caFile=self._caCert, customHeaders=['x-forwarded-for: [::1]:8080'], useQueue=False)
          self.assertFalse(receivedQuery)
          self.assertFalse(receivedResponse)

          # make sure the timeout is detected, if any
          time.sleep(4)

          # this one should not
          ((receivedProxyPayload, receivedDNSData), receivedResponse) = self.sendDOHQuery(port, self._serverName, url, query, caFile=self._caCert, customHeaders=['x-forwarded-for: 127.0.0.42:8080'], response=response, fromQueue=fromProxyQueue, toQueue=toProxyQueue)
          self.assertTrue(receivedProxyPayload)
          self.assertTrue(receivedDNSData)
          receivedQuery = dns.message.from_wire(receivedDNSData)
          self.assertTrue(receivedQuery)
          receivedQuery.id = expectedQuery.id
          self.assertEqual(expectedQuery, receivedQuery)
          self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
          self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.42', '127.0.0.1', True, destinationPort=port)
          # check the response
          self.assertTrue(receivedResponse)
          receivedResponse.id = response.id
          self.assertEqual(response, receivedResponse)
