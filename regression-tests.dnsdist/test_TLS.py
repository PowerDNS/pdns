#!/usr/bin/env python
import dns
from dnsdisttests import DNSDistTest

class TestTLS(DNSDistTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _tlsServerPort = 8453
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    addTLSLocal("127.0.0.1:%s", "%s", "%s")
    addAction(SNIRule("powerdns.com"), SpoofAction("1.2.3.4"))
    """
    _config_params = ['_testServerPort', '_tlsServerPort', '_serverCert', '_serverKey']

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
