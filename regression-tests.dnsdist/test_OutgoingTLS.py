#!/usr/bin/env python
import dns
import ssl
import threading
import time

from dnsdisttests import DNSDistTest

class OutgoingTLSTests(object):

    def checkOnlyTLSResponderHit(self):
        self.assertNotIn('UDP Responder', self._responsesCounter)
        self.assertNotIn('TCP Responder', self._responsesCounter)
        self.assertEqual(self._responsesCounter['TLS Responder'], 1)
        
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

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, expectedResponse)
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, expectedResponse)
        self.checkOnlyTLSResponderHit()

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
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, expectedResponse)
        self.checkOnlyTLSResponderHit()

class BrokenOutgoingTLSTests(object):

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
    _tlsBackendPort = 10443
    _config_params = ['_tlsBackendPort']
    _config_template = """
    newServer{address="127.0.0.1:%s", tls='openssl', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com'}
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.setDaemon(True)
        cls._TLSResponder.start()

class TestOutgoingTLSGnuTLS(DNSDistTest, OutgoingTLSTests):
    _tlsBackendPort = 10444
    _config_params = ['_tlsBackendPort']
    _config_template = """
    newServer{address="127.0.0.1:%s", tls='gnutls', validateCertificates=true, caStore='ca.pem', subjectName='powerdns.com'}
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.setDaemon(True)
        cls._TLSResponder.start()

class TestOutgoingTLSOpenSSLWrongCertName(DNSDistTest, BrokenOutgoingTLSTests):
    _tlsBackendPort = 10445
    _config_params = ['_tlsBackendPort']
    _config_template = """
    newServer{address="127.0.0.1:%s", tls='openssl', validateCertificates=true, caStore='ca.pem', subjectName='not-powerdns.com'}
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.setDaemon(True)
        cls._TLSResponder.start()

class TestOutgoingTLSGnuTLSWrongCertName(DNSDistTest, BrokenOutgoingTLSTests):
    _tlsBackendPort = 10446
    _config_params = ['_tlsBackendPort']
    _config_template = """
    newServer{address="127.0.0.1:%s", tls='gnutls', validateCertificates=true, caStore='ca.pem', subjectName='not-powerdns.com'}
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.setDaemon(True)
        cls._TLSResponder.start()

class TestOutgoingTLSOpenSSLWrongCertNameButNoCheck(DNSDistTest, OutgoingTLSTests):
    _tlsBackendPort = 10447
    _config_params = ['_tlsBackendPort']
    _config_template = """
    newServer{address="127.0.0.1:%s", tls='openssl', validateCertificates=false, caStore='ca.pem', subjectName='not-powerdns.com'}
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.setDaemon(True)
        cls._TLSResponder.start()

class TestOutgoingTLSGnuTLSWrongCertNameButNoCheck(DNSDistTest, OutgoingTLSTests):
    _tlsBackendPort = 10448
    _config_params = ['_tlsBackendPort']
    _config_template = """
    newServer{address="127.0.0.1:%s", tls='gnutls', validateCertificates=false, caStore='ca.pem', subjectName='not-powerdns.com'}
    """

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.setDaemon(True)
        cls._TLSResponder.start()
