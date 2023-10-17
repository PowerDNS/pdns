#!/usr/bin/env python
import dns
import clientsubnetoption

from dnsdisttests import DNSDistTest
from dnsdisttests import pickAvailablePort
from doqclient import quic_bogus_query
import doqclient

class TestDOQBogus(DNSDistTest):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _doqServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    addDOQLocal("127.0.0.1:%d", "%s", "%s")
    """
    _config_params = ['_testServerPort', '_doqServerPort','_serverCert', '_serverKey']
    _verboseMode = True

    def testDOQBogus(self):
        """
        DOQ: Test a bogus query (wrong packed length)
        """
        name = 'bogus.doq.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0

        try:
            message = quic_bogus_query(query, '127.0.0.1', 2.0, self._doqServerPort, verify=self._caCert, server_hostname=self._serverName)
            self.assertFalse(True)
        except doqclient.StreamResetError as e :
            self.assertEqual(e.error, 2);

class TestDOQ(DNSDistTest):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _doqServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    addAction("drop.doq.tests.powerdns.com.", DropAction())
    addAction("refused.doq.tests.powerdns.com.", RCodeAction(DNSRCode.REFUSED))
    addAction("spoof.doq.tests.powerdns.com.", SpoofAction("1.2.3.4"))
    addAction("no-backend.doq.tests.powerdns.com.", PoolAction('this-pool-has-no-backend'))

    addDOQLocal("127.0.0.1:%d", "%s", "%s")
    """
    _config_params = ['_testServerPort', '_doqServerPort','_serverCert', '_serverKey']
    _verboseMode = True

    def testDOQSimple(self):
        """
        DOQ: Simple query
        """
        name = 'simple.doq.tests.powerdns.com.'
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
        (receivedQuery, receivedResponse) = self.sendDOQQuery(self._doqServerPort, query, response=response, caFile=self._caCert, serverName=self._serverName)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)

    def testDOQMultipleStreams(self):
        """
        DOQ: Test multiple queries using the same connection
        """

        name = 'simple.doq.tests.powerdns.com.'
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

        connection = self.getDOQConnection(self._doqServerPort, self._caCert)

        (receivedQuery, receivedResponse) = self.sendDOQQuery(self._doqServerPort, query, response=response, caFile=self._caCert, serverName=self._serverName, connection=connection)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)

        (receivedQuery, receivedResponse) = self.sendDOQQuery(self._doqServerPort, query, response=response, caFile=self._caCert, serverName=self._serverName, connection=connection)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)

    def testDropped(self):
        """
        DOQ: Dropped query
        """
        name = 'drop.doq.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        dropped = False
        try:
            (_, receivedResponse) = self.sendDOQQuery(self._doqServerPort, query, response=None, caFile=self._caCert, useQueue=False, serverName=self._serverName)
            self.assertTrue(False)
        except doqclient.StreamResetError as e :
            self.assertEqual(e.error, 5);

    def testRefused(self):
        """
        DOQ: Refused
        """
        name = 'refused.doq.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.id = 0
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        (_, receivedResponse) = self.sendDOQQuery(self._doqServerPort, query, response=None, caFile=self._caCert, useQueue=False, serverName=self._serverName)
        self.assertEqual(receivedResponse, expectedResponse)

    def testSpoof(self):
        """
        DOQ: Spoofed
        """
        name = 'spoof.doq.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.id = 0
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '1.2.3.4')
        expectedResponse.answer.append(rrset)

        (_, receivedResponse) = self.sendDOQQuery(self._doqServerPort, query, response=None, caFile=self._caCert, useQueue=False, serverName=self._serverName)
        self.assertEqual(receivedResponse, expectedResponse)

    def testDOQNoBackend(self):
        """
        DOQ: No backend
        """
        name = 'no-backend.doq.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        dropped = False
        try:
            (_, receivedResponse) = self.sendDOQQuery(self._doqServerPort, query, response=None, caFile=self._caCert, useQueue=False, serverName=self._serverName)
            self.assertTrue(False)
        except doqclient.StreamResetError as e :
            self.assertEqual(e.error, 5);

class TestDOQWithCache(DNSDistTest):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _doqServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    addDOQLocal("127.0.0.1:%d", "%s", "%s")

    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    """
    _config_params = ['_testServerPort', '_doqServerPort','_serverCert', '_serverKey']
    _verboseMode = True

    def testCached(self):
        """
        Cache: Served from cache

        dnsdist is configured to cache entries, we are sending several
        identical requests and checking that the backend only receive
        the first one.
        """
        numberOfQueries = 10
        name = 'cached.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        query.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendDOQQuery(self._doqServerPort, query, response=response, caFile=self._caCert, serverName=self._serverName)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

        for _ in range(numberOfQueries):
            (_, receivedResponse) = self.sendDOQQuery(self._doqServerPort, query, response=None, caFile=self._caCert, useQueue=False, serverName=self._serverName)
            self.assertEqual(receivedResponse, response)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]
            TestDOQWithCache._responsesCounter[key] = 0

        self.assertEqual(total, 1)
