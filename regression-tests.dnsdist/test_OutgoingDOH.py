#!/usr/bin/env python
import dns
import requests
import ssl
import threading
import time

from dnsdisttests import DNSDistTest

class OutgoingDOHTests(object):

    _webTimeout = 2.0
    _webServerPort = 8083
    _webServerBasicAuthPassword = 'secret'
    _webServerAPIKey = 'apisecret'
    _webServerBasicAuthPasswordHashed = '$scrypt$ln=10,p=1,r=8$6DKLnvUYEeXWh3JNOd3iwg==$kSrhdHaRbZ7R74q3lGBqO1xetgxRxhmWzYJ2Qvfm7JM='
    _webServerAPIKeyHashed = '$scrypt$ln=10,p=1,r=8$9v8JxDfzQVyTpBkTbkUqYg==$bDQzAOHeK1G9UvTPypNhrX48w974ZXbFPtRKS34+aso='

    def checkOnlyDOHResponderHit(self, numberOfDOHQueries=1):
        self.assertNotIn('UDP Responder', self._responsesCounter)
        self.assertNotIn('TCP Responder', self._responsesCounter)
        self.assertNotIn('TLS Responder', self._responsesCounter)
        self.assertEqual(self._responsesCounter['DOH Responder'], numberOfDOHQueries)

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

        numberOfUDPQueries = 10
        for _ in range(numberOfUDPQueries):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, expectedResponse)
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, expectedResponse)

        # there was one TCP query in testTCP (below, but before in alphabetical order)
        numberOfQueries = numberOfUDPQueries + 1
        self.checkOnlyDOHResponderHit(numberOfUDPQueries)

        self.assertEqual(self.getServerStat('tcpNewConnections'), 1)
        self.assertEqual(self.getServerStat('tcpReusedConnections'), numberOfQueries - 1)
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

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, expectedResponse)
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, expectedResponse)
        self.checkOnlyDOHResponderHit()
        self.assertEqual(self.getServerStat('tcpNewConnections'), 1)
        self.assertEqual(self.getServerStat('tcpReusedConnections'), 0)
        self.assertEqual(self.getServerStat('tlsResumptions'), 0)

class BrokenOutgoingDOHTests(object):

    _webTimeout = 2.0
    _webServerPort = 8083
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
    _webServerPort = 8083
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
    _tlsBackendPort = 10543
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%s", tls='openssl', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com', dohPath='/dns-query'}:setUp()
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.set_alpn_protocols(["h2"])
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._DOHResponder.setDaemon(True)
        cls._DOHResponder.start()

class TestOutgoingDOHGnuTLS(DNSDistTest, OutgoingDOHTests):
    _tlsBackendPort = 10544
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%s", tls='gnutls', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com', dohPath='/dns-query'}:setUp()
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')
        tlsContext.keylog_filename = "/tmp/keys"

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._DOHResponder.setDaemon(True)
        cls._DOHResponder.start()

class TestOutgoingDOHOpenSSLWrongCertName(DNSDistTest, BrokenOutgoingDOHTests):
    _tlsBackendPort = 10545
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%s", tls='openssl', validateCertificates=true, caStore='ca.pem', subjectName='not-powerdns.com', dohPath='/dns-query'}:setUp()
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._DOHResponder.setDaemon(True)
        cls._DOHResponder.start()

class TestOutgoingDOHGnuTLSWrongCertName(DNSDistTest, BrokenOutgoingDOHTests):
    _tlsBackendPort = 10546
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%s", tls='gnutls', validateCertificates=true, caStore='ca.pem', subjectName='not-powerdns.com', dohPath='/dns-query'}:setUp()
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._DOHResponder.setDaemon(True)
        cls._DOHResponder.start()

class TestOutgoingDOHOpenSSLWrongCertNameButNoCheck(DNSDistTest, OutgoingDOHTests):
    _tlsBackendPort = 10547
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%s", tls='openssl', validateCertificates=false, caStore='ca.pem', subjectName='not-powerdns.com', dohPath='/dns-query'}:setUp()
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._DOHResponder.setDaemon(True)
        cls._DOHResponder.start()

class TestOutgoingDOHGnuTLSWrongCertNameButNoCheck(DNSDistTest, OutgoingDOHTests):
    _tlsBackendPort = 10548
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%s", tls='gnutls', validateCertificates=false, caStore='ca.pem', subjectName='not-powerdns.com', dohPath='/dns-query'}:setUp()
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._DOHResponder.setDaemon(True)
        cls._DOHResponder.start()

class TestOutgoingDOHBrokenResponsesOpenSSL(DNSDistTest, OutgoingDOHBrokenResponsesTests):
    _tlsBackendPort = 10549
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%s", tls='openssl', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com', dohPath='/dns-query'}:setUp()
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """

    def callback(request):

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
        cls._DOHResponder.setDaemon(True)
        cls._DOHResponder.start()

class TestOutgoingDOHBrokenResponsesGnuTLS(DNSDistTest, OutgoingDOHBrokenResponsesTests):
    _tlsBackendPort = 10550
    _config_params = ['_tlsBackendPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%s", tls='gnutls', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com', dohPath='/dns-query'}:setUp()
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """
    _verboseMode = True

    def callback(request):

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
        cls._DOHResponder.setDaemon(True)
        cls._DOHResponder.start()

class TestOutgoingDOHProxyProtocol(DNSDistTest):

    _tlsBackendPort = 10551
    _config_params = ['_tlsBackendPort']
    _config_template = """
    setMaxTCPClientThreads(1)
    newServer{address="127.0.0.1:%s", tls='gnutls', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com', dohPath='/dns-query', useProxyProtocol=true}:setUp()
    """
    _verboseMode = True

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.set_alpn_protocols(["h2"])
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching DOH woth Proxy Protocol responder..")
        cls._DOHResponder = threading.Thread(name='DOH with Proxy Protocol Responder', target=cls.DOHResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext, True])
        cls._DOHResponder.setDaemon(True)
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
