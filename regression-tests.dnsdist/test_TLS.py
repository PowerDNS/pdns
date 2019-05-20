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
