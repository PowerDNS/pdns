#!/usr/bin/env python
import base64
import dns
import socket
import ssl
import subprocess
import time
import unittest
import random
import string

from dnsdisttests import DNSDistTest, pickAvailablePort


class TLSTests(object):
    def getServerCertificate(self):
        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)
        cert = conn.getpeercert()
        conn.close()
        return cert

    def getTLSProvider(self):
        return self.sendConsoleCommand("getBind(0):getEffectiveTLSProvider()").rstrip()

    def testTLSSimple(self):
        """
        TLS: Single query
        """
        name = "single.tls.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN", use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        response.answer.append(rrset)

        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)

        self.sendTCPQueryOverConnection(conn, query, response=response)
        (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # check the certificate
        cert = self.getServerCertificate()
        self.assertIn("subject", cert)
        self.assertIn("serialNumber", cert)
        self.assertIn("subjectAltName", cert)
        subject = cert["subject"]
        altNames = cert["subjectAltName"]
        self.assertEqual(dict(subject[0])["commonName"], "tls.tests.dnsdist.org")
        self.assertEqual(dict(subject[1])["organizationalUnitName"], "PowerDNS.com BV")
        names = []
        for entry in altNames:
            names.append(entry[1])
        self.assertEqual(names, ["tls.tests.dnsdist.org", "powerdns.com", "127.0.0.1"])
        serialNumber = cert["serialNumber"]

        self.generateNewCertificateAndKey("server-tls")
        self.sendConsoleCommand("reloadAllCertificates()")

        conn.close()
        # open a new connection
        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)

        self.sendTCPQueryOverConnection(conn, query, response=response)
        (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # check that the certificate is OK
        cert = self.getServerCertificate()
        self.assertIn("subject", cert)
        self.assertIn("serialNumber", cert)
        self.assertIn("subjectAltName", cert)
        subject = cert["subject"]
        altNames = cert["subjectAltName"]
        self.assertEqual(dict(subject[0])["commonName"], "tls.tests.dnsdist.org")
        self.assertEqual(dict(subject[1])["organizationalUnitName"], "PowerDNS.com BV")
        names = []
        for entry in altNames:
            names.append(entry[1])
        self.assertEqual(names, ["tls.tests.dnsdist.org", "powerdns.com", "127.0.0.1"])

        # and that the serial is different
        self.assertNotEqual(serialNumber, cert["serialNumber"])
        conn.close()

    def testTLKA(self):
        """
        TLS: Several queries over the same connection
        """
        name = "ka.tls.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN", use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        response.answer.append(rrset)

        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)

        for idx in range(5):
            self.sendTCPQueryOverConnection(conn, query, response=response)
            (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        conn.close()

    def testTLSPipelining(self):
        """
        TLS: Several queries over the same connection without waiting for the responses
        """
        name = "pipelining.tls.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN", use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        response.answer.append(rrset)

        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)

        for idx in range(100):
            self.sendTCPQueryOverConnection(conn, query, response=response)

        for idx in range(100):
            (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        conn.close()

    def testTLSSNIRouting(self):
        """
        TLS: SNI Routing
        """
        name = "sni.tls.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN", use_edns=False)
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.4")
        expectedResponse.answer.append(rrset)

        # this SNI should match so we should get a spoofed answer
        conn = self.openTLSConnection(self._tlsServerPort, "powerdns.com", self._caCert)

        self.sendTCPQueryOverConnection(conn, query, response=None)
        receivedResponse = self.recvTCPResponseOverConnection(conn, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEqual(expectedResponse, receivedResponse)

        conn.close()
        # this one should not
        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)

        self.sendTCPQueryOverConnection(conn, query, response=response)
        (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
        conn.close()

    def testTLSSNIRoutingAfterResumption(self):
        # we have more complicated tests about session resumption itself,
        # but here we want to make sure the SNI is still present after resumption
        """
        TLS: SNI Routing after resumption
        """
        name = "sni-resumed.tls.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN", use_edns=False)
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.4")
        expectedResponse.answer.append(rrset)

        # this SNI should match so we should get a spoofed answer
        sslctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)
        sslctx.check_hostname = True
        sslctx.verify_mode = ssl.CERT_REQUIRED
        sslctx.load_verify_locations(self._caCert)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(2.0)
        sslsock = sslctx.wrap_socket(sock, server_hostname="powerdns.com")
        sslsock.connect(("127.0.0.1", self._tlsServerPort))

        self.sendTCPQueryOverConnection(sslsock, query, response=None)
        receivedResponse = self.recvTCPResponseOverConnection(sslsock, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEqual(expectedResponse, receivedResponse)
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
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.assertFalse(sslsock.session_reused)

        # and now we should be able to resume the session
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(2.0)
        sslsock = sslctx.wrap_socket(sock, server_hostname="powerdns.com")
        sslsock.session = session
        sslsock.connect(("127.0.0.1", self._tlsServerPort))

        self.sendTCPQueryOverConnection(sslsock, query, response=None)
        receivedResponse = self.recvTCPResponseOverConnection(sslsock, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEqual(expectedResponse, receivedResponse)
        self.assertTrue(sslsock.session_reused)


class TestOpenSSL(DNSDistTest, TLSTests):
    _extraStartupSleep = 1
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")
    _serverKey = "server-tls.key"
    _serverCert = "server-tls.chain"
    _serverName = "tls.tests.dnsdist.org"
    _caCert = "ca.pem"
    _tlsServerPort = pickAvailablePort()
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    newServer{address="127.0.0.1:%d"}
    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="openssl" })
    addAction(SNIRule("powerdns.com"), SpoofAction("1.2.3.4"))
    """
    _config_params = [
        "_consoleKeyB64",
        "_consolePort",
        "_testServerPort",
        "_tlsServerPort",
        "_serverCert",
        "_serverKey",
    ]

    @classmethod
    def setUpClass(cls):
        cls.generateNewCertificateAndKey("server-tls")
        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

    def testProvider(self):
        self.assertEqual(self.getTLSProvider(), "openssl")


class TestGnuTLS(DNSDistTest, TLSTests):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")
    _serverKey = "server-tls.key"
    _serverCert = "server-tls.chain"
    _serverName = "tls.tests.dnsdist.org"
    _caCert = "ca.pem"
    _tlsServerPort = pickAvailablePort()
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    newServer{address="127.0.0.1:%d"}
    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="gnutls" })
    addAction(SNIRule("powerdns.com"), SpoofAction("1.2.3.4"))
    """
    _config_params = [
        "_consoleKeyB64",
        "_consolePort",
        "_testServerPort",
        "_tlsServerPort",
        "_serverCert",
        "_serverKey",
    ]

    @classmethod
    def setUpClass(cls):
        cls.generateNewCertificateAndKey("server-tls")
        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

    def testProvider(self):
        self.assertEqual(self.getTLSProvider(), "gnutls")


class TestOpenSSLYaml(DNSDistTest, TLSTests):
    _extraStartupSleep = 1
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")
    _serverKey = "server-tls.key"
    _serverCert = "server-tls.chain"
    _serverName = "tls.tests.dnsdist.org"
    _caCert = "ca.pem"
    _tlsServerPort = pickAvailablePort()
    _config_template = ""
    _config_params = []
    _yaml_config_template = """---
console:
  key: "%s"
  listen_address: "127.0.0.1:%d"
  acl:
    - 127.0.0.0/8
backends:
  - address: "127.0.0.1:%d"
    protocol: "Do53"
binds:
  - listen_address: "127.0.0.1:%d"
    reuseport: true
    protocol: "DoT"
    tls:
      certificates:
        - certificate: "%s"
          key: "%s"
      provider: "openssl"
query_rules:
  - name: "SNI"
    selector:
      type: "SNI"
      server_name: "powerdns.com"
    action:
      type: "Spoof"
      ips:
        - "1.2.3.4"
    """
    _yaml_config_params = [
        "_consoleKeyB64",
        "_consolePort",
        "_testServerPort",
        "_tlsServerPort",
        "_serverCert",
        "_serverKey",
    ]

    @classmethod
    def setUpClass(cls):
        cls.generateNewCertificateAndKey("server-tls")
        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

    def testProvider(self):
        self.assertEqual(self.getTLSProvider(), "openssl")


class TestDOTWithCache(DNSDistTest):
    _serverKey = "server.key"
    _serverCert = "server.chain"
    _serverName = "tls.tests.dnsdist.org"
    _caCert = "ca.pem"
    _tlsServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    addTLSLocal("127.0.0.1:%d", "%s", "%s")

    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    """
    _config_params = ["_testServerPort", "_tlsServerPort", "_serverCert", "_serverKey"]

    def testDOTCacheLargeAnswer(self):
        """
        DOT with cache: Check that we can cache (and retrieve) large answers
        """
        numberOfQueries = 10
        name = "large.dot-with-cache.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN", use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, "A", "IN", use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        # we prepare a large answer
        content = ""
        for i in range(44):
            if len(content) > 0:
                content = content + ", "
            content = content + (str(i) * 50)
        # pad up to 4096
        content = content + "A" * 40

        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.TXT, content)
        response.answer.append(rrset)
        self.assertEqual(len(response.to_wire()), 4096)

        # first query to fill the cache
        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)
        self.sendTCPQueryOverConnection(conn, query, response=response)
        (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True)

        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryNoEDNS(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)
        conn.close()

        for _ in range(numberOfQueries):
            conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)
            self.sendTCPQueryOverConnection(conn, query, response=None)
            receivedResponse = self.recvTCPResponseOverConnection(conn, useQueue=False)
            self.assertEqual(receivedResponse, response)
            conn.close()


class TestTLSFrontendLimits(DNSDistTest):
    # this test suite uses a different responder port
    # because it uses a different health check configuration
    _testServerPort = pickAvailablePort()
    _answerUnexpected = True

    _serverKey = "server.key"
    _serverCert = "server.chain"
    _serverName = "tls.tests.dnsdist.org"
    _caCert = "ca.pem"
    _tlsServerPort = pickAvailablePort()

    _skipListeningOnCL = True
    _tcpIdleTimeout = 2
    _maxTCPConnsPerTLSFrontend = 5
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="openssl", maxConcurrentTCPConnections=%d })
    """
    _config_params = ["_testServerPort", "_tlsServerPort", "_serverCert", "_serverKey", "_maxTCPConnsPerTLSFrontend"]
    _alternateListeningAddr = "127.0.0.1"
    _alternateListeningPort = _tlsServerPort

    def testTCPConnsPerTLSFrontend(self):
        """
        TLS Frontend Limits: Maximum number of conns per TLS frontend
        """
        name = "maxconnspertlsfrontend.tls.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        conns = []

        for idx in range(self._maxTCPConnsPerTLSFrontend + 1):
            try:
                conns.append(self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert))
            except Exception:
                conns.append(None)

        count = 0
        failed = 0
        for conn in conns:
            if not conn:
                failed = failed + 1
                continue

            try:
                self.sendTCPQueryOverConnection(conn, query)
                response = self.recvTCPResponseOverConnection(conn)
                if response:
                    count = count + 1
                else:
                    failed = failed + 1
            except Exception:
                failed = failed + 1

        for conn in conns:
            if conn:
                conn.close()

        # wait a bit to be sure that dnsdist closed the connections
        # and decremented the counters on its side, otherwise subsequent
        # connections will be dropped
        time.sleep(1)

        self.assertEqual(count, self._maxTCPConnsPerTLSFrontend)
        self.assertEqual(failed, 1)


class TestProtocols(DNSDistTest):
    _serverKey = "server.key"
    _serverCert = "server.chain"
    _serverName = "tls.tests.dnsdist.org"
    _caCert = "ca.pem"
    _tlsServerPort = pickAvailablePort()

    _config_template = """
    function checkDOT(dq)
      if dq:getProtocol() ~= "DNS over TLS" then
        return DNSAction.Spoof, '1.2.3.4'
      end
      return DNSAction.None
    end

    addAction("protocols.tls.tests.powerdns.com.", LuaAction(checkDOT))
    newServer{address="127.0.0.1:%d"}
    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="openssl" })
    """
    _config_params = ["_testServerPort", "_tlsServerPort", "_serverCert", "_serverKey"]

    def testProtocolDOT(self):
        """
        DoT: Test DNSQuestion.Protocol
        """
        name = "protocols.tls.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        response = dns.message.make_response(query)

        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)
        self.sendTCPQueryOverConnection(conn, query, response=response)
        (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
        conn.close()


class TestPKCSTLSCertificate(DNSDistTest, TLSTests):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")
    _serverCert = "server-tls.p12"
    _pkcsPassphrase = "passw0rd"
    _serverName = "tls.tests.dnsdist.org"
    _caCert = "ca.pem"
    _tlsServerPort = pickAvailablePort()
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}
    cert=newTLSCertificate("%s", {password="%s"})
    addTLSLocal("127.0.0.1:%d", cert, "", { provider="openssl" })
    addAction(SNIRule("powerdns.com"), SpoofAction("1.2.3.4"))
    """
    _config_params = [
        "_consoleKeyB64",
        "_consolePort",
        "_testServerPort",
        "_serverCert",
        "_pkcsPassphrase",
        "_tlsServerPort",
    ]

    @classmethod
    def setUpClass(cls):
        cls.generateNewCertificateAndKey("server-tls")
        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()


class TestOpenSSLTLSTicketsKeyCallback(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")

    _serverKey = "server.key"
    _serverCert = "server.chain"
    _serverName = "tls.tests.dnsdist.org"
    _caCert = "ca.pem"
    _tlsServerPort = pickAvailablePort()
    _numberOfKeys = 5

    _config_params = [
        "_consoleKeyB64",
        "_consolePort",
        "_testServerPort",
        "_tlsServerPort",
        "_serverCert",
        "_serverKey",
    ]
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    newServer{address="127.0.0.1:%d"}
    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="openssl" })

    lastKey = ""
    lastKeyLen = 0

    function keyAddedCallback(key, keyLen)
      lastKey = key
      lastKeyLen = keyLen
    end
    setTicketsKeyAddedHook(keyAddedCallback)
    """

    def testSetTicketsKey(self):
        """
        TLSTicketsKey: test setting new key and the key added hook
        """

        newKey = "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(80))
        self.sendConsoleCommand('getTLSFrontend(0):loadTicketsKey("{}")'.format(newKey))
        keyLen = self.sendConsoleCommand("lastKeyLen")
        self.assertEqual(int(keyLen), 80)
        lastKey = self.sendConsoleCommand("lastKey")
        self.assertEqual(newKey, lastKey.strip())


class TestGnuTLSTLSTicketsKeyCallback(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")

    _serverKey = "server.key"
    _serverCert = "server.chain"
    _serverName = "tls.tests.dnsdist.org"
    _caCert = "ca.pem"
    _tlsServerPort = pickAvailablePort()
    _numberOfKeys = 5

    _config_params = [
        "_consoleKeyB64",
        "_consolePort",
        "_testServerPort",
        "_tlsServerPort",
        "_serverCert",
        "_serverKey",
    ]
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    newServer{address="127.0.0.1:%d"}
    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="gnutls" })

    lastKey = ""
    lastKeyLen = 0

    function keyAddedCallback(key, keyLen)
      lastKey = key
      lastKeyLen = keyLen
    end
    setTicketsKeyAddedHook(keyAddedCallback)
    """

    def testSetTicketsKey(self):
        """
        TLSTicketsKey: test setting new key and the key added hook
        """

        newKey = "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(64))
        self.sendConsoleCommand('getTLSFrontend(0):loadTicketsKey("{}")'.format(newKey))
        keyLen = self.sendConsoleCommand("lastKeyLen")
        self.assertEqual(int(keyLen), 64)
        lastKey = self.sendConsoleCommand("lastKey")
        self.assertEqual(newKey, lastKey.strip())
