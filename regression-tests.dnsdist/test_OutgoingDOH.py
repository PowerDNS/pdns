#!/usr/bin/env python
import base64
import copy
import dns
import requests
import ssl
import threading
import time
import os

from dnsdisttests import DNSDistTest, pickAvailablePort

class OutgoingDOHTests(object):

    _webTimeout = 2.0
    _webServerPort = pickAvailablePort()
    _webServerBasicAuthPassword = 'secret'
    _webServerAPIKey = 'apisecret'
    _webServerBasicAuthPasswordHashed = '$scrypt$ln=10,p=1,r=8$6DKLnvUYEeXWh3JNOd3iwg==$kSrhdHaRbZ7R74q3lGBqO1xetgxRxhmWzYJ2Qvfm7JM='
    _webServerAPIKeyHashed = '$scrypt$ln=10,p=1,r=8$9v8JxDfzQVyTpBkTbkUqYg==$bDQzAOHeK1G9UvTPypNhrX48w974ZXbFPtRKS34+aso='

    def checkOnlyDOHResponderHit(self, numberOfDOHQueries=1):
        self.assertNotIn('UDP Responder', self._responsesCounter)
        self.assertNotIn('TCP Responder', self._responsesCounter)
        self.assertNotIn('TLS Responder', self._responsesCounter)
        self.assertEqual(self._responsesCounter['DoH Connection Handler'], numberOfDOHQueries)

    def getServerStat(self, key):
        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/api/v1/servers/localhost'
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        self.assertTrue(len(content['servers']), 1)
        server = content['servers'][0]
        self.assertIn(key, server)
        return server[key]

    def testUDP(self):
        """
        Outgoing DOH: UDP query is sent via DOH
        """
        name = 'udp.outgoing-doh.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        connsBefore = self.getServerStat('tcpReusedConnections')

        numberOfUDPQueries = 10
        for _ in range(numberOfUDPQueries):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, expectedResponse)
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, expectedResponse)

        # there was one TCP query in testTCP (below, but before in alphabetical order)
        numberOfQueries = numberOfUDPQueries + 1
        self.checkOnlyDOHResponderHit(numberOfUDPQueries)

        self.assertEqual(self.getServerStat('tcpNewConnections'), 1)
        self.assertEqual(self.getServerStat('tcpReusedConnections'), connsBefore + numberOfQueries - 1)
        self.assertEqual(self.getServerStat('tlsResumptions'), 0)

    def testTCP(self):
        """
        Outgoing DOH: TCP query is sent via DOH
        """
        name = 'tcp.outgoing-doh.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        connsBefore = self.getServerStat('tcpReusedConnections')

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, expectedResponse)
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, expectedResponse)
        self.checkOnlyDOHResponderHit()
        self.assertEqual(self.getServerStat('tcpNewConnections'), 1)
        self.assertEqual(self.getServerStat('tcpReusedConnections'), connsBefore)
        self.assertEqual(self.getServerStat('tlsResumptions'), 0)

    def testUDPCache(self):
        """
        Outgoing DOH: UDP query is sent via DOH, should be cached
        """
        name = 'udp.cached.outgoing-doh.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, expectedResponse)
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, expectedResponse)

        numberOfUDPQueries = 10
        for _ in range(numberOfUDPQueries):
            (_, receivedResponse) = self.sendUDPQuery(query, useQueue=False, response=None)
            self.assertEqual(receivedResponse, expectedResponse)

    def testTCPCache(self):
        """
        Outgoing DOH: TCP query is sent via DOH, should be cached
        """
        name = 'tcp.cached.outgoing-doh.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, expectedResponse)
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, expectedResponse)

        numberOfTCPQueries = 10
        for _ in range(numberOfTCPQueries):
            (_, receivedResponse) = self.sendTCPQuery(query, useQueue=False, response=None)
            self.assertEqual(receivedResponse, expectedResponse)

    def testZHealthChecks(self):
        # this test has to run last, as it will mess up the TCP connection counter,
        # hence the 'Z' in the name
        self.sendConsoleCommand("getServer(0):setAuto()")
        time.sleep(2)
        status = self.sendConsoleCommand("if getServer(0):isUp() then return 'up' else return 'down' end").strip("\n")
        self.assertEqual(status, 'up')

class BrokenOutgoingDOHTests(object):

    _webTimeout = 2.0
    _webServerPort = pickAvailablePort()
    _webServerBasicAuthPassword = 'secret'
    _webServerAPIKey = 'apisecret'
    _webServerBasicAuthPasswordHashed = '$scrypt$ln=10,p=1,r=8$6DKLnvUYEeXWh3JNOd3iwg==$kSrhdHaRbZ7R74q3lGBqO1xetgxRxhmWzYJ2Qvfm7JM='
    _webServerAPIKeyHashed = '$scrypt$ln=10,p=1,r=8$9v8JxDfzQVyTpBkTbkUqYg==$bDQzAOHeK1G9UvTPypNhrX48w974ZXbFPtRKS34+aso='

    def checkNoResponderHit(self):
        self.assertNotIn('UDP Responder', self._responsesCounter)
        self.assertNotIn('TCP Responder', self._responsesCounter)
        self.assertNotIn('TLS Responder', self._responsesCounter)
        self.assertNotIn('DOH Responder', self._responsesCounter)

    def testUDP(self):
        """
        Outgoing DOH (broken): UDP query is sent via DOH
        """
        name = 'udp.broken-outgoing-doh.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)
        self.checkNoResponderHit()

    def testTCP(self):
        """
        Outgoing DOH (broken): TCP query is sent via DOH
        """
        name = 'tcp.broken-outgoing-doh.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)
        self.checkNoResponderHit()

class OutgoingDOHBrokenResponsesTests(object):

    _webTimeout = 2.0
    _webServerPort = pickAvailablePort()
    _webServerBasicAuthPassword = 'secret'
    _webServerAPIKey = 'apisecret'
    _webServerBasicAuthPasswordHashed = '$scrypt$ln=10,p=1,r=8$6DKLnvUYEeXWh3JNOd3iwg==$kSrhdHaRbZ7R74q3lGBqO1xetgxRxhmWzYJ2Qvfm7JM='
    _webServerAPIKeyHashed = '$scrypt$ln=10,p=1,r=8$9v8JxDfzQVyTpBkTbkUqYg==$bDQzAOHeK1G9UvTPypNhrX48w974ZXbFPtRKS34+aso='

    def testUDP(self):
        """
        Outgoing DOH (broken responses): UDP query is sent via DOH
        """
        name = '500-status.broken-responses.outgoing-doh.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)

        name = 'invalid-dns-payload.broken-responses.outgoing-doh.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)

        name = 'closing-connection-id.broken-responses.outgoing-doh.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)

        # but a valid response should be successful
        name = 'valid.broken-responses.outgoing-doh.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        (_, receivedResponse) = self.sendUDPQuery(query, response)
        # we can't check the received query because the responder does not populate the queue..
        # self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

    def testTCP(self):
        """
        Outgoing DOH (broken responses): TCP query is sent via DOH
        """
        name = '500-status.broken-responses.outgoing-doh.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)

        name = 'invalid-dns-payload.broken-responses.outgoing-doh.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)

        name = 'closing-connection-id.broken-responses.outgoing-doh.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)

        # but a valid response should be successful
        name = 'valid.broken-responses.outgoing-doh.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        (_, receivedResponse) = self.sendTCPQuery(query, response)
        # we can't check the received query because the responder does not populate the queue..
        #self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

class TestOutgoingDOHOpenSSL(DNSDistTest, OutgoingDOHTests):
    if os.path.exists("/tmp/dohkeys"):
        os.remove("/tmp/dohkeys")
    _tlsBackendPort = pickAvailablePort()
    _tlsProvider = 'openssl'
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_tlsBackendPort', '_tlsProvider', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%d", tls='%s', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com', dohPath='/dns-query', pool={'', 'cache'}, keyLogFile="/tmp/dohkeys"}:setUp()
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})

    pc = newPacketCache(100)
    getPool('cache'):setCache(pc)
    smn = newSuffixMatchNode()
    smn:add('cached.outgoing-doh.test.powerdns.com.')
    addAction(SuffixMatchNodeRule(smn), PoolAction('cache'))
    """

    def testZNonEmptyKeyfile(self):
        self.assertTrue(os.path.exists("/tmp/dohkeys"))
        self.assertGreater(os.path.getsize("/tmp/dohkeys"), 0)

    @staticmethod
    def sniCallback(sslSocket, sni, sslContext):
        assert(sni == 'powerdns.com')
        return None

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.set_alpn_protocols(["h2"])
        tlsContext.load_cert_chain('server.chain', 'server.key')
        # requires Python 3.7+
        if hasattr(tlsContext, 'sni_callback'):
            tlsContext.sni_callback = cls.sniCallback

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._DOHResponder.daemon = True
        cls._DOHResponder.start()

class TestOutgoingDOHGnuTLS(DNSDistTest, OutgoingDOHTests):
    _tlsBackendPort = pickAvailablePort()
    _tlsProvider = 'gnutls'
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_tlsBackendPort', '_tlsProvider', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%d", tls='%s', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com', dohPath='/dns-query', pool={'', 'cache'}}:setUp()
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})

    pc = newPacketCache(100)
    getPool('cache'):setCache(pc)
    smn = newSuffixMatchNode()
    smn:add('cached.outgoing-doh.test.powerdns.com.')
    addAction(SuffixMatchNodeRule(smn), PoolAction('cache'))
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')
        tlsContext.keylog_filename = "/tmp/keys"

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._DOHResponder.daemon = True
        cls._DOHResponder.start()

class TestOutgoingDOHOpenSSLYaml(DNSDistTest, OutgoingDOHTests):
    _tlsBackendPort = pickAvailablePort()
    _tlsProvider = 'openssl'
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = []
    _config_template = ""
    _yaml_config_template = """---
console:
  key: "%s"
  listen_address: "127.0.0.1:%d"
  acl:
    - 127.0.0.0/8
backends:
  - address: "127.0.0.1:%d"
    protocol: "DoH"
    pools:
      - ""
      - "cache"
    tls:
      provider: "%s"
      validate_certificate: true
      ca_store: "ca.pem"
      subject_name: "powerdns.com"
    doh:
      path: "/dns-query"
    health_checks:
      mode: "UP"
webserver:
  listen_addresses:
    - "127.0.0.1:%d"
  password: "%s"
  api_key: "%s"
  acl:
    - 127.0.0.0/8
tuning:
  tcp:
    worker_threads: 1
pools:
  - name: "cache"
    packet_cache: "pc"
packet_caches:
  - name: "pc"
    size: 100
query_rules:
  - name: "suffix to pool"
    selector:
      type: "QNameSuffix"
      suffixes:
        - "cached.outgoing-doh.test.powerdns.com."
    action:
      type: "Pool"
      pool_name: "cache"
"""
    _yaml_config_params = ['_consoleKeyB64', '_consolePort', '_tlsBackendPort', '_tlsProvider', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']

    @staticmethod
    def sniCallback(sslSocket, sni, sslContext):
        assert(sni == 'powerdns.com')
        return None

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.set_alpn_protocols(["h2"])
        tlsContext.load_cert_chain('server.chain', 'server.key')
        # requires Python 3.7+
        if hasattr(tlsContext, 'sni_callback'):
            tlsContext.sni_callback = cls.sniCallback

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._DOHResponder.daemon = True
        cls._DOHResponder.start()

class TestOutgoingDOHOpenSSLWrongCertName(DNSDistTest, BrokenOutgoingDOHTests):
    _tlsBackendPort = pickAvailablePort()
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%d", tls='openssl', validateCertificates=true, caStore='ca.pem', subjectName='not-powerdns.com', dohPath='/dns-query'}:setUp()
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._DOHResponder.daemon = True
        cls._DOHResponder.start()

class TestOutgoingDOHGnuTLSWrongCertName(DNSDistTest, BrokenOutgoingDOHTests):
    _tlsBackendPort = pickAvailablePort()
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%d", tls='gnutls', validateCertificates=true, caStore='ca.pem', subjectName='not-powerdns.com', dohPath='/dns-query'}:setUp()
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._DOHResponder.daemon = True
        cls._DOHResponder.start()

class TestOutgoingDOHOpenSSLWrongCertNameButNoCheck(DNSDistTest, OutgoingDOHTests):
    _tlsBackendPort = pickAvailablePort()
    _tlsProvider = 'openssl'
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_tlsBackendPort', '_tlsProvider', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%d", tls='%s', validateCertificates=false, caStore='ca.pem', subjectName='not-powerdns.com', dohPath='/dns-query', pool={'', 'cache'}}:setUp()
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})

    pc = newPacketCache(100)
    getPool('cache'):setCache(pc)
    smn = newSuffixMatchNode()
    smn:add('cached.outgoing-doh.test.powerdns.com.')
    addAction(SuffixMatchNodeRule(smn), PoolAction('cache'))
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._DOHResponder.daemon = True
        cls._DOHResponder.start()

class TestOutgoingDOHGnuTLSWrongCertNameButNoCheck(DNSDistTest, OutgoingDOHTests):
    _tlsBackendPort = pickAvailablePort()
    _tlsProvider = 'gnutls'
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_tlsBackendPort', '_tlsProvider', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%d", tls='%s', validateCertificates=false, caStore='ca.pem', subjectName='not-powerdns.com', dohPath='/dns-query', pool={'', 'cache'}}:setUp()
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})

    pc = newPacketCache(100)
    getPool('cache'):setCache(pc)
    smn = newSuffixMatchNode()
    smn:add('cached.outgoing-doh.test.powerdns.com.')
    addAction(SuffixMatchNodeRule(smn), PoolAction('cache'))
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._DOHResponder.daemon = True
        cls._DOHResponder.start()

class TestOutgoingDOHBrokenResponsesOpenSSL(DNSDistTest, OutgoingDOHBrokenResponsesTests):
    _tlsBackendPort = pickAvailablePort()
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%d", tls='openssl', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com', dohPath='/dns-query', pool={'', 'cache'}}:setUp()
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})

    pc = newPacketCache(100)
    getPool('cache'):setCache(pc)
    smn = newSuffixMatchNode()
    smn:add('cached.outgoing-doh.test.powerdns.com.')
    addAction(SuffixMatchNodeRule(smn), PoolAction('cache'))
    """

    def callback(request, headers, fromQueue, toQueue):

        if str(request.question[0].name) == '500-status.broken-responses.outgoing-doh.test.powerdns.com.':
            print("returning 500")
            return 500, b'Server error'

        if str(request.question[0].name) == 'invalid-dns-payload.broken-responses.outgoing-doh.test.powerdns.com.':
            return 200, b'not DNS'

        if str(request.question[0].name) == 'closing-connection-id.broken-responses.outgoing-doh.test.powerdns.com.':
            return 200, None

        print("Returning default for %s" % (request.question[0].name))
        return 200, dns.message.make_response(request).to_wire()

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.set_alpn_protocols(["h2"])
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.callback, tlsContext])
        cls._DOHResponder.daemon = True
        cls._DOHResponder.start()

class TestOutgoingDOHBrokenResponsesGnuTLS(DNSDistTest, OutgoingDOHBrokenResponsesTests):
    _tlsBackendPort = pickAvailablePort()
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%d", tls='gnutls', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com', dohPath='/dns-query'}:setUp()
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})
    """
    _verboseMode = True

    def callback(request, headers, fromQueue, toQueue):

        if str(request.question[0].name) == '500-status.broken-responses.outgoing-doh.test.powerdns.com.':
            print("returning 500")
            return 500, b'Server error'

        if str(request.question[0].name) == 'invalid-dns-payload.broken-responses.outgoing-doh.test.powerdns.com.':
            return 200, b'not DNS'

        if str(request.question[0].name) == 'closing-connection-id.broken-responses.outgoing-doh.test.powerdns.com.':
            return 200, None

        print("Returning default for %s" % (request.question[0].name))
        return 200, dns.message.make_response(request).to_wire()

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.set_alpn_protocols(["h2"])
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.callback, tlsContext])
        cls._DOHResponder.daemon = True
        cls._DOHResponder.start()

class TestOutgoingDOHProxyProtocol(DNSDistTest):

    _tlsBackendPort = pickAvailablePort()
    _config_params = ['_tlsBackendPort']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%d", tls='gnutls', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com', dohPath='/dns-query', useProxyProtocol=true}:setUp()
    """
    _verboseMode = True

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.set_alpn_protocols(["h2"])
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching DOH woth Proxy Protocol responder..")
        cls._DOHResponder = threading.Thread(name='DOH with Proxy Protocol Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext, True])
        cls._DOHResponder.daemon = True
        cls._DOHResponder.start()

    def testPP(self):
        """
        Outgoing DOH with Proxy Protocol
        """
        name = 'proxy-protocol.outgoing-doh.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        (receivedProxyPayload, receivedResponse) = self.sendUDPQuery(query, expectedResponse)
        receivedQuery = self._fromResponderQueue.get(True, 1.0)
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, expectedResponse)
        self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', False)

        (receivedProxyPayload, receivedResponse) = self.sendTCPQuery(query, expectedResponse)
        receivedQuery = self._fromResponderQueue.get(True, 1.0)
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, expectedResponse)
        self.checkMessageProxyProtocol(receivedProxyPayload, '127.0.0.1', '127.0.0.1', True)

class TestOutgoingDOHXForwarded(DNSDistTest):
    _tlsBackendPort = pickAvailablePort()
    _config_params = ['_tlsBackendPort']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%d", tls='gnutls', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com', dohPath='/dns-query', addXForwardedHeaders=true}
    """
    _verboseMode = True

    def callback(self, headersList, fromQueue, toQueue):

        if str(self.question[0].name) == 'a.root-servers.net.':
            # do not check headers on health-check queries
            return 200, dns.message.make_response(self).to_wire()

        headers = {}
        if headersList:
            for k,v in headersList:
                headers[k] = v

        if not b'x-forwarded-for' in headers:
            print("missing X-Forwarded-For")
            return 406, b'Missing X-Forwarded-For header'
        if not b'x-forwarded-port' in headers:
            print("missing X-Forwarded-Port")
            return 406, b'Missing X-Forwarded-Port header'
        if not b'x-forwarded-proto' in headers:
            print("missing X-Forwarded-Proto")
            return 406, b'Missing X-Forwarded-Proto header'

        toQueue.put(self, True, 1.0)
        response = fromQueue.get(True, 1.0)
        if response:
            response = copy.copy(response)
            response.id = self.id

        return 200, response.to_wire()

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.set_alpn_protocols(["h2"])
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.callback, tlsContext])
        cls._DOHResponder.daemon = True
        cls._DOHResponder.start()

    def testXForwarded(self):
        """
        Outgoing DOH: X-Forwarded
        """
        name = 'x-forwarded-for.outgoing-doh.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, expectedResponse)
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, expectedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, expectedResponse)
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, expectedResponse)
