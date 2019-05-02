#!/usr/bin/env python
import struct
import time
import dns
from dnsdisttests import DNSDistTest

try:
    range = xrange
except NameError:
    pass

class TestTCPKeepAlive(DNSDistTest):
    """
    These tests make sure that dnsdist keeps the TCP connection alive
    in various cases, like cache hits, self-generated answer, and
    that it doesn't in error cases (Drop, invalid queries...)
    """

    _tcpIdleTimeout = 20
    _maxTCPQueriesPerConn = 99
    _maxTCPConnsPerClient = 100
    _maxTCPConnDuration = 99
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    setTCPRecvTimeout(%s)
    setMaxTCPQueriesPerConnection(%s)
    setMaxTCPConnectionsPerClient(%s)
    setMaxTCPConnectionDuration(%s)
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    addAction("largernumberofconnections.tcpka.tests.powerdns.com.", SkipCacheAction())
    addAction("refused.tcpka.tests.powerdns.com.", RCodeAction(DNSRCode.REFUSED))
    addAction("dropped.tcpka.tests.powerdns.com.", DropAction())
    addResponseAction("dropped-response.tcpka.tests.powerdns.com.", DropResponseAction())
    -- create the pool named "nosuchpool"
    getPool("nosuchpool")
    addAction("nodownstream-servfail.tcpka.tests.powerdns.com.", PoolAction("nosuchpool"))
    setServFailWhenNoServer(true)
    """
    _config_params = ['_testServerPort', '_tcpIdleTimeout', '_maxTCPQueriesPerConn', '_maxTCPConnsPerClient', '_maxTCPConnDuration']

    def testTCPKaSelfGenerated(self):
        """
        TCP KeepAlive: Self-generated answer
        """
        name = 'refused.tcpka.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        conn = self.openTCPConnection()

        count = 0
        for idx in range(5):
            try:
                self.sendTCPQueryOverConnection(conn, query)
                response = self.recvTCPResponseOverConnection(conn)
                if response is None:
                    break
                self.assertEquals(expectedResponse, response)
                count = count + 1
            except:
                pass

        conn.close()
        self.assertEqual(count, 5)

    def testTCPKaCacheHit(self):
        """
        TCP KeepAlive: Cache Hit
        """
        name = 'cachehit.tcpka.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        expectedResponse.answer.append(rrset)

        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, expectedResponse)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, expectedResponse)

        conn = self.openTCPConnection()

        count = 0
        for idx in range(5):
            try:
                self.sendTCPQueryOverConnection(conn, query)
                response = self.recvTCPResponseOverConnection(conn)
                if response is None:
                    break
                self.assertEquals(expectedResponse, response)
                count = count + 1
            except:
                pass

        conn.close()
        self.assertEqual(count, 5)

    def testTCPKaNoDownstreamServFail(self):
        """
        TCP KeepAlive: No downstream ServFail

        The query is routed to a pool that has no server,
        and dnsdist is configured to send a ServFail when
        that happens. We should keep the TCP connection open.
        """
        name = 'nodownstream-servfail.tcpka.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.SERVFAIL)

        conn = self.openTCPConnection()

        count = 0
        for idx in range(5):
            try:
                self.sendTCPQueryOverConnection(conn, query)
                response = self.recvTCPResponseOverConnection(conn)
                if response is None:
                    break
                self.assertEquals(expectedResponse, response)
                count = count + 1
            except:
                pass

        conn.close()
        self.assertEqual(count, 5)

    def testTCPKaQRBitSet(self):
        """
        TCP KeepAlive: QR bit set in question
        """
        name = 'qrset.tcpka.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags |= dns.flags.QR

        conn = self.openTCPConnection()

        count = 0
        for idx in range(5):
            try:
                self.sendTCPQueryOverConnection(conn, query)
                response = self.recvTCPResponseOverConnection(conn)
                if response is None:
                    break
                count = count + 1
            except:
                pass

        conn.close()
        self.assertEqual(count, 0)

    def testTCPKaDrop(self):
        """
        TCP KeepAlive: Drop
        """
        name = 'dropped.tcpka.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags |= dns.flags.QR

        conn = self.openTCPConnection()

        count = 0
        for idx in range(5):
            try:
                self.sendTCPQueryOverConnection(conn, query)
                response = self.recvTCPResponseOverConnection(conn)
                if response is None:
                    break
                count = count + 1
            except:
                pass

        conn.close()
        self.assertEqual(count, 0)

    def testTCPKaDropResponse(self):
        """
        TCP KeepAlive: Drop Response
        """
        name = 'dropped-response.tcpka.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        conn = self.openTCPConnection()

        count = 0
        for idx in range(5):
            try:
                self.sendTCPQueryOverConnection(conn, query)
                response = self.recvTCPResponseOverConnection(conn)
                if response is None:
                    break
                count = count + 1
            except:
                pass

        conn.close()
        self.assertEqual(count, 0)

    def testTCPKaLargeNumberOfConnections(self):
        """
        TCP KeepAlive: Large number of connections
        """
        name = 'largernumberofconnections.tcpka.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        #expectedResponse.set_rcode(dns.rcode.SERVFAIL)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        expectedResponse.answer.append(rrset)

        # number of connections
        numConns = 50
        # number of queries per connections
        numQueriesPerConn = 4

        conns = []
        start = time.time()
        for idx in range(numConns):
            conns.append(self.openTCPConnection())

        count = 0
        for idx in range(numConns * numQueriesPerConn):
            try:
                conn = conns[idx % numConns]
                self.sendTCPQueryOverConnection(conn, query, response=expectedResponse)
                response = self.recvTCPResponseOverConnection(conn)
                if response is None:
                    break
                self.assertEquals(expectedResponse, response)
                count = count + 1
            except:
                pass

        for con in conns:
          conn.close()

        self.assertEqual(count, numConns * numQueriesPerConn)

class TestTCPKeepAliveNoDownstreamDrop(DNSDistTest):
    """
    This test makes sure that dnsdist drops the TCP connection
    if no downstream server is available and setServFailWhenNoServer()
    is not set.
    """

    _tcpIdleTimeout = 20
    _maxTCPQueriesPerConn = 99
    _maxTCPConnsPerClient = 3
    _maxTCPConnDuration = 99
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    setTCPRecvTimeout(%s)
    setMaxTCPQueriesPerConnection(%s)
    setMaxTCPConnectionsPerClient(%s)
    setMaxTCPConnectionDuration(%s)
    -- create the pool named "nosuchpool"
    getPool("nosuchpool")
    addAction("nodownstream-drop.tcpka.tests.powerdns.com.", PoolAction("nosuchpool"))
    """
    _config_params = ['_testServerPort', '_tcpIdleTimeout', '_maxTCPQueriesPerConn', '_maxTCPConnsPerClient', '_maxTCPConnDuration']

    def testTCPKaNoDownstreamDrop(self):
        """
        TCP KeepAlive: No downstream Drop

        The query is routed to a pool that has no server,
        and dnsdist is configured to drop the query when
        that happens. We should close the TCP connection right away.
        """
        name = 'nodownstream-drop.tcpka.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        conn = self.openTCPConnection()

        count = 0
        for idx in range(5):
            try:
                self.sendTCPQueryOverConnection(conn, query)
                response = self.recvTCPResponseOverConnection(conn)
                if response is None:
                    break
                count = count + 1
            except:
                pass

        conn.close()
        self.assertEqual(count, 0)
