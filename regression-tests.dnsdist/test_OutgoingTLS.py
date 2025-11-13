#!/usr/bin/env python
import dns
import requests
import ssl
import threading
import time
import os

from dnsdisttests import DNSDistTest, pickAvailablePort

class OutgoingTLSTests(object):

    _webTimeout = 2.0
    _webServerPort = pickAvailablePort()
    _webServerBasicAuthPassword = 'secret'
    _webServerAPIKey = 'apisecret'
    _webServerBasicAuthPasswordHashed = '$scrypt$ln=10,p=1,r=8$6DKLnvUYEeXWh3JNOd3iwg==$kSrhdHaRbZ7R74q3lGBqO1xetgxRxhmWzYJ2Qvfm7JM='
    _webServerAPIKeyHashed = '$scrypt$ln=10,p=1,r=8$9v8JxDfzQVyTpBkTbkUqYg==$bDQzAOHeK1G9UvTPypNhrX48w974ZXbFPtRKS34+aso='

    def checkOnlyTLSResponderHit(self, numberOfTLSQueries=1):
        self.assertNotIn('UDP Responder', self._responsesCounter)
        self.assertNotIn('TCP Responder', self._responsesCounter)
        self.assertEqual(self._responsesCounter['TLS Responder'], numberOfTLSQueries)

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
        Outgoing TLS: UDP query is sent via TLS
        """
        name = 'udp.outgoing-tls.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        numberOfUDPQueries = 10
        for _ in range(numberOfUDPQueries):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, expectedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, expectedResponse)

        # there was one TCP query
        numberOfQueries = numberOfUDPQueries + 1
        self.checkOnlyTLSResponderHit(numberOfUDPQueries)
        # our TLS responder does only one query per connection, so we need one for the TCP
        # query and one for the UDP one (the TCP test is done first)
        self.assertEqual(self.getServerStat('tcpNewConnections'), numberOfQueries)
        # we tried to reuse the connection (and then it failed but hey)
        self.assertEqual(self.getServerStat('tcpReusedConnections'), numberOfQueries - 1)
        # we resumed the TLS session, though, but since we only learn about that
        # when the connection is closed, we might be off by one, except if a health check
        # allowed the first TCP connection to be resumed as well
        self.assertGreaterEqual(self.getServerStat('tlsResumptions'), numberOfUDPQueries - 1)
        self.assertLessEqual(self.getServerStat('tlsResumptions'), numberOfUDPQueries)

    def testTCP(self):
        """
        Outgoing TLS: TCP query is sent via TLS
        """
        name = 'tcp.outgoing-tls.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, expectedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, expectedResponse)
        self.checkOnlyTLSResponderHit()
        self.assertEqual(self.getServerStat('tcpNewConnections'), 1)
        self.assertEqual(self.getServerStat('tcpReusedConnections'), 0)
        self.assertEqual(self.getServerStat('tlsResumptions'), 0)

class BrokenOutgoingTLSTests(object):

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

    def testUDP(self):
        """
        Outgoing TLS (broken): UDP query is sent via TLS
        """
        name = 'udp.broken-outgoing-tls.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)
        self.checkNoResponderHit()

    def testTCP(self):
        """
        Outgoing TLS (broken): TCP query is sent via TLS
        """
        name = 'tcp.broken-outgoing-tls.test.powerdns.com.'
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

class TestOutgoingTLSOpenSSL(DNSDistTest, OutgoingTLSTests):
    if os.path.exists("/tmp/dotkeys"):
        os.remove("/tmp/dotkeys")
    _tlsBackendPort = pickAvailablePort()
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%d", tls='openssl', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com', keyLogFile="/tmp/dotkeys"}
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    def testZNonEmptyKeyfile(self):
        self.assertTrue(os.path.exists("/tmp/dotkeys"))
        self.assertGreater(os.path.getsize("/tmp/dotkeys"), 0)

    @staticmethod
    def sniCallback(sslSocket, sni, sslContext):
        assert(sni == 'powerdns.com')
        return None

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')
        # requires Python 3.7+
        if hasattr(tlsContext, 'sni_callback'):
            tlsContext.sni_callback = cls.sniCallback

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.daemon = True
        cls._TLSResponder.start()

class TestOutgoingTLSOpenSSLYaml(DNSDistTest, OutgoingTLSTests):
    _tlsBackendPort = pickAvailablePort()
    _config_params = []
    _config_template = ""
    _yaml_config_template = """---
backends:
  - address: "127.0.0.1:%d"
    protocol: "DoT"
    tls:
      provider: "openssl"
      validate_certificate: true
      ca_store: "ca.pem"
      subject_name: "powerdns.com"
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
    """
    _yaml_config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']

    @staticmethod
    def sniCallback(sslSocket, sni, sslContext):
        assert(sni == 'powerdns.com')
        return None

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')
        # requires Python 3.7+
        if hasattr(tlsContext, 'sni_callback'):
            tlsContext.sni_callback = cls.sniCallback

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.daemon = True
        cls._TLSResponder.start()

class TestOutgoingTLSGnuTLS(DNSDistTest, OutgoingTLSTests):
    _tlsBackendPort = pickAvailablePort()
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%d", tls='gnutls', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com'}
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')
        tlsContext.keylog_filename = "/tmp/keys"

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.daemon = True
        cls._TLSResponder.start()

class TestOutgoingTLSOpenSSLWrongCertName(DNSDistTest, BrokenOutgoingTLSTests):
    _tlsBackendPort = pickAvailablePort()
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%d", tls='openssl', validateCertificates=true, caStore='ca.pem', subjectName='not-powerdns.com'}
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.daemon = True
        cls._TLSResponder.start()

class TestOutgoingTLSGnuTLSWrongCertName(DNSDistTest, BrokenOutgoingTLSTests):
    _tlsBackendPort = pickAvailablePort()
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%d", tls='gnutls', validateCertificates=true, caStore='ca.pem', subjectName='not-powerdns.com'}
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.daemon = True
        cls._TLSResponder.start()

class TestOutgoingTLSOpenSSLWrongCertNameButNoCheck(DNSDistTest, OutgoingTLSTests):
    _tlsBackendPort = pickAvailablePort()
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%d", tls='openssl', validateCertificates=false, caStore='ca.pem', subjectName='not-powerdns.com'}
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.daemon = True
        cls._TLSResponder.start()

class TestOutgoingTLSGnuTLSWrongCertNameButNoCheck(DNSDistTest, OutgoingTLSTests):
    _tlsBackendPort = pickAvailablePort()
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%d", tls='gnutls', validateCertificates=false, caStore='ca.pem', subjectName='not-powerdns.com'}
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.daemon = True
        cls._TLSResponder.start()
