#!/usr/bin/env python
import base64
import dns
import socket
import ssl
import subprocess
import unittest
from dnsdisttests import DNSDistTest

class TLSTests(object):

    def getServerCertificate(self):
        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)
        return conn.getpeercert()

    def testTLSSimple(self):
        """
        TLS: Single query
        """
        name = 'single.tls.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)

        self.sendTCPQueryOverConnection(conn, query, response=response)
        (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        # check the certificate
        cert = self.getServerCertificate()
        self.assertIn('subject', cert)
        self.assertIn('serialNumber', cert)
        self.assertIn('subjectAltName', cert)
        subject = cert['subject']
        altNames = cert['subjectAltName']
        self.assertEquals(dict(subject[0])['commonName'], 'tls.tests.dnsdist.org')
        self.assertEquals(dict(subject[1])['organizationalUnitName'], 'PowerDNS.com BV')
        names = []
        for entry in altNames:
            names.append(entry[1])
        self.assertEquals(names, ['tls.tests.dnsdist.org', 'powerdns.com'])
        serialNumber = cert['serialNumber']

        self.generateNewCertificateAndKey()
        self.sendConsoleCommand("reloadAllCertificates()")

        # open a new connection
        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)

        self.sendTCPQueryOverConnection(conn, query, response=response)
        (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        # check that the certificate is OK
        cert = self.getServerCertificate()
        self.assertIn('subject', cert)
        self.assertIn('serialNumber', cert)
        self.assertIn('subjectAltName', cert)
        subject = cert['subject']
        altNames = cert['subjectAltName']
        self.assertEquals(dict(subject[0])['commonName'], 'tls.tests.dnsdist.org')
        self.assertEquals(dict(subject[1])['organizationalUnitName'], 'PowerDNS.com BV')
        names = []
        for entry in altNames:
            names.append(entry[1])
        self.assertEquals(names, ['tls.tests.dnsdist.org', 'powerdns.com'])

        # and that the serial is different
        self.assertNotEquals(serialNumber, cert['serialNumber'])

    def testTLKA(self):
        """
        TLS: Several queries over the same connection
        """
        name = 'ka.tls.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)

        for idx in range(5):
            self.sendTCPQueryOverConnection(conn, query, response=response)
            (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

    def testTLSPipelining(self):
        """
        TLS: Several queries over the same connection without waiting for the responses
        """
        name = 'pipelining.tls.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)

        for idx in range(100):
            self.sendTCPQueryOverConnection(conn, query, response=response)

        for idx in range(100):
            (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

    def testTLSSNIRouting(self):
        """
        TLS: SNI Routing
        """
        name = 'sni.tls.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '1.2.3.4')
        expectedResponse.answer.append(rrset)

        # this SNI should match so we should get a spoofed answer
        conn = self.openTLSConnection(self._tlsServerPort, 'powerdns.com', self._caCert)

        self.sendTCPQueryOverConnection(conn, query, response=None)
        receivedResponse = self.recvTCPResponseOverConnection(conn, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)

        # this one should not
        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)

        self.sendTCPQueryOverConnection(conn, query, response=response)
        (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testTLSSNIRoutingAfterResumption(self):
        # we have more complicated tests about session resumption itself,
        # but here we want to make sure the SNI is still present after resumption
        """
        TLS: SNI Routing after resumption
        """
        name = 'sni-resumed.tls.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '1.2.3.4')
        expectedResponse.answer.append(rrset)

        # this SNI should match so we should get a spoofed answer
        sslctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)
        sslctx.check_hostname = True
        sslctx.verify_mode = ssl.CERT_REQUIRED
        sslctx.load_verify_locations(self._caCert)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(2.0)
        sslsock = sslctx.wrap_socket(sock, server_hostname='powerdns.com')
        sslsock.connect(("127.0.0.1", self._tlsServerPort))

        self.sendTCPQueryOverConnection(sslsock, query, response=None)
        receivedResponse = self.recvTCPResponseOverConnection(sslsock, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)
        self.assertFalse(sslsock.session_reused)
        session = sslsock.session

        # this one should not (different SNI)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(2.0)
        sslsock = sslctx.wrap_socket(sock, server_hostname=self._serverName)
        sslsock.connect(("127.0.0.1", self._tlsServerPort))

        self.sendTCPQueryOverConnection(sslsock, query, response=response)
        (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(sslsock, useQueue=True)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        self.assertFalse(sslsock.session_reused)

        # and now we should be able to resume the session
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(2.0)
        sslsock = sslctx.wrap_socket(sock, server_hostname='powerdns.com')
        sslsock.session = session
        sslsock.connect(("127.0.0.1", self._tlsServerPort))

        self.sendTCPQueryOverConnection(sslsock, query, response=None)
        receivedResponse = self.recvTCPResponseOverConnection(sslsock, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)
        self.assertTrue(sslsock.session_reused)

class TestOpenSSL(DNSDistTest, TLSTests):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _tlsServerPort = 8453
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")

    newServer{address="127.0.0.1:%s"}
    addTLSLocal("127.0.0.1:%s", "%s", "%s", { provider="openssl" })
    addAction(SNIRule("powerdns.com"), SpoofAction("1.2.3.4"))
    """
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort', '_tlsServerPort', '_serverCert', '_serverKey']

class TestGnuTLS(DNSDistTest, TLSTests):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _tlsServerPort = 8453
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")

    newServer{address="127.0.0.1:%s"}
    addTLSLocal("127.0.0.1:%s", "%s", "%s", { provider="gnutls" })
    addAction(SNIRule("powerdns.com"), SpoofAction("1.2.3.4"))
    """
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort', '_tlsServerPort', '_serverCert', '_serverKey']

class TestDOTWithCache(DNSDistTest):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _tlsServerPort = 8453
    _config_template = """
    newServer{address="127.0.0.1:%s"}

    addTLSLocal("127.0.0.1:%s", "%s", "%s")

    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    """
    _config_params = ['_testServerPort', '_tlsServerPort', '_serverCert', '_serverKey']

    def testDOTCacheLargeAnswer(self):
        """
        DOT with cache: Check that we can cache (and retrieve) large answers
        """
        numberOfQueries = 10
        name = 'large.dot-with-cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        # we prepare a large answer
        content = ""
        for i in range(44):
            if len(content) > 0:
                content = content + ', '
            content = content + (str(i)*50)
        # pad up to 4096
        content = content + 'A'*40

        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    content)
        response.answer.append(rrset)
        self.assertEquals(len(response.to_wire()), 4096)

        # first query to fill the cache
        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)
        self.sendTCPQueryOverConnection(conn, query, response=response)
        (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True)

        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEquals(expectedQuery, receivedQuery)
        self.checkQueryNoEDNS(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

        for _ in range(numberOfQueries):
            conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)
            self.sendTCPQueryOverConnection(conn, query, response=None)
            receivedResponse = self.recvTCPResponseOverConnection(conn, useQueue=False)
            self.assertEquals(receivedResponse, response)
