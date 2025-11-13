#!/usr/bin/env python
import ssl
import struct
import time
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort

try:
  range = xrange
except NameError:
  pass

class TestTCPLimits(DNSDistTest):

    # this test suite uses a different responder port
    # because it uses a different health check configuration
    _testServerPort = pickAvailablePort()
    _answerUnexpected = True

    _tcpIdleTimeout = 2
    _maxTCPQueriesPerConn = 5
    _maxTCPConnsPerClient = 3
    _maxTCPConnDuration = 5
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    setTCPRecvTimeout(%d)
    setMaxTCPQueriesPerConnection(%d)
    setMaxTCPConnectionsPerClient(%d)
    setMaxTCPConnectionDuration(%d)
    -- disable "near limits" otherwise our tests are broken because connections are forcibly closed
    setTCPConnectionsOverloadThreshold(0)
    -- disable the maximum number of read IOs per query, otherwise the maximum duration (testTCPDuration)
    -- test gets us banned very quickly
    setMaxTCPReadIOsPerQuery(0)
    """
    _config_params = ['_testServerPort', '_tcpIdleTimeout', '_maxTCPQueriesPerConn', '_maxTCPConnsPerClient', '_maxTCPConnDuration']

    def testTCPQueriesPerConn(self):
        """
        TCP Limits: Maximum number of queries
        """
        name = 'maxqueriesperconn.tcp.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        conn = self.openTCPConnection()

        count = 0
        for idx in range(self._maxTCPQueriesPerConn):
            try:
                self.sendTCPQueryOverConnection(conn, query)
                response = self.recvTCPResponseOverConnection(conn)
                self.assertTrue(response)
                count = count + 1
            except Exception:
                pass

        # this one should fail
        failed = False
        try:
            self.sendTCPQueryOverConnection(conn, query)
            response = self.recvTCPResponseOverConnection(conn)
            self.assertFalse(response)
            if not response:
                failed = True
            else:
                count = count + 1
        except Exception:
            failed = True

        conn.close()
        self.assertTrue(failed)
        self.assertEqual(count, self._maxTCPQueriesPerConn)

    def testTCPConnsPerClient(self):
        """
        TCP Limits: Maximum number of conns per client
        """
        name = 'maxconnsperclient.tcp.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        conns = []

        for idx in range(self._maxTCPConnsPerClient + 1):
            conns.append(self.openTCPConnection())

        count = 0
        failed = 0
        for conn in conns:
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
            conn.close()

        # wait a bit to be sure that dnsdist closed the connections
        # and decremented the counters on its side, otherwise subsequent
        # connections will be dropped
        time.sleep(1)

        self.assertEqual(count, self._maxTCPConnsPerClient)
        self.assertEqual(failed, 1)

    def testTCPDuration(self):
        """
        TCP Limits: Maximum duration
        """

        start = time.time()
        conn = self.openTCPConnection()
        # immediately send the maximum size
        conn.send(struct.pack("!H", 65535))

        count = 0
        while count < (self._maxTCPConnDuration * 20):
            try:
                # sleeping for only one second keeps us below the
                # idle timeout (setTCPRecvTimeout())
                time.sleep(0.1)
                conn.send(b'A')
                count = count + 1
            except Exception as e:
                print("Exception: %s!" % (e))
                break

        end = time.time()

        self.assertAlmostEqual(count / 10, self._maxTCPConnDuration, delta=2)
        self.assertAlmostEqual(end - start, self._maxTCPConnDuration, delta=2)

        conn.close()

class TestTCPLimitsReadIO(DNSDistTest):

    # separate test suite because we get banned for a few seconds
    _testServerPort = pickAvailablePort()
    _answerUnexpected = True

    _tcpIdleTimeout = 2
    _maxTCPReadIOsPerQuery = 10
    _banDuration = 2
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    setTCPRecvTimeout(%d)
    setMaxTCPReadIOsPerQuery(%d)
    setBanDurationForExceedingMaxReadIOsPerQuery(%d)
    -- disable "near limits" otherwise our tests are broken because connections are forcibly closed
    setTCPConnectionsOverloadThreshold(0)
    """
    _config_params = ['_testServerPort', '_tcpIdleTimeout', '_maxTCPReadIOsPerQuery', '_banDuration']

    def testTCPMaxReadIOsPerQuery(self):
        """
        TCP Limits: Maximum number of IO read events per query
        """
        name = 'maxreadios.tcp.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        payload = query.to_wire()
        self.assertGreater(len(payload), self._maxTCPReadIOsPerQuery)

        conn = self.openTCPConnection()
        conn.send(struct.pack("!H", len(payload)))

        count = 0
        failed = False
        while count < len(payload):
            try:
                conn.send(payload[count].to_bytes())
                count = count + 1
                time.sleep(0.001)
            except Exception:
                failed = True
                break

        if not failed:
            try:
                response = self.recvTCPResponseOverConnection(conn)
                if not response:
                  failed = True
            except Exception:
                failed = True

        conn.close()
        self.assertTrue(failed)

        # and we should be banned now
        failed = False
        try:
            conn = self.openTCPConnection()
            response = self.recvTCPResponseOverConnection(conn)
            if response is None:
              failed = True
        except Exception:
            failed = True
        finally:
            conn.close()

        self.assertTrue(failed)

class TestTCPLimitsConnectionRate(DNSDistTest):

    # separate test suite because we get banned for a few seconds
    _testServerPort = pickAvailablePort()
    _answerUnexpected = True
    _maxConnectionRate = 10
    _tcpIdleTimeout = 2
    _banDuration = 2
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    setTCPRecvTimeout(%d)
    setMaxTCPConnectionRatePerClient(%d)
    setBanDurationForExceedingTCPTLSRate(%d)
    -- disable "near limits" otherwise our tests are broken because connections are forcibly closed
    setTCPConnectionsOverloadThreshold(0)
    """
    _config_params = ['_testServerPort', '_tcpIdleTimeout', '_maxConnectionRate', '_banDuration']
    _verboseMode = True

    def testTCPConnectionRate(self):
        """
        TCP Limits: Maximum connection rate
        """
        name = 'maxconnectionrate.tcp.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        # _maxConnectionRate connections in a row
        for idx in range(self._maxConnectionRate):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response=response)
            receivedQuery.id = query.id
            self.assertEqual(receivedQuery, query)
            self.assertEqual(receivedResponse, response)
        # the next one should be past the max rate
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedQuery, None)
        self.assertEqual(receivedResponse, None)

class TestTCPLimitsTLSNewSessionRate(DNSDistTest):
    # separate test suite because we get banned for a few seconds
    _testServerPort = pickAvailablePort()
    _tlsServerPort = pickAvailablePort()
    _answerUnexpected = True
    _maxNewTLSSessionRate = 10
    _tcpIdleTimeout = 2
    _banDuration = 2
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    setTCPRecvTimeout(%d)
    setMaxTLSNewSessionRatePerClient(%d)
    setBanDurationForExceedingTCPTLSRate(%d)
    addTLSLocal("127.0.0.1:%d", "%s", "%s")

    -- disable "near limits" otherwise our tests are broken because connections are forcibly closed
    setTCPConnectionsOverloadThreshold(0)
    """
    _config_params = ['_testServerPort', '_tcpIdleTimeout', '_maxNewTLSSessionRate', '_banDuration', '_tlsServerPort', '_serverCert', '_serverKey']
    _verboseMode = True

    def testTLSNewSessionRate(self):
        """
        TCP Limits: Maximum TLS new session rate
        """
        name = 'maxtlsnewsessionrate.tcp.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        # _maxNewTLSSessionRate connections in a row, plus one because
        # the session is only accounted for once the handshake has been completed
        for idx in range(self._maxNewTLSSessionRate + 1):
            (receivedQuery, receivedResponse) = self.sendDOTQueryWrapper(query, response=response)
            receivedQuery.id = query.id
            self.assertEqual(receivedQuery, query)
            self.assertEqual(receivedResponse, response)

        try:
            # the next one should be past the max rate
            self.sendDOTQueryWrapper(query, response=None, useQueue=False)
            self.assertTrue(False)
        except ConnectionResetError:
          pass

class TestTCPLimitsTLSResumedSessionRate(DNSDistTest):
    # separate test suite because we get banned for a few seconds
    _testServerPort = pickAvailablePort()
    _tlsServerPort = pickAvailablePort()
    _answerUnexpected = True
    _maxNewTLSSessionRate = 1
    _maxResumedTLSSessionRate = 10
    _tcpIdleTimeout = 2
    _banDuration = 2
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    setTCPRecvTimeout(%d)
    setMaxTLSNewSessionRatePerClient(%d)
    setMaxTLSResumedSessionRatePerClient(%d)
    setBanDurationForExceedingTCPTLSRate(%d)
    addTLSLocal("127.0.0.1:%d", "%s", "%s")

    -- disable "near limits" otherwise our tests are broken because connections are forcibly closed
    setTCPConnectionsOverloadThreshold(0)
    """
    _config_params = ['_testServerPort', '_tcpIdleTimeout', '_maxNewTLSSessionRate', '_maxResumedTLSSessionRate', '_banDuration', '_tlsServerPort', '_serverCert', '_serverKey']
    _verboseMode = True

    def testTLSResumedSessionRate(self):
        """
        TCP Limits: Maximum TLS resumed session rate
        """
        name = 'maxtlsresumedsessionrate.tcp.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        session = None
        sslctx = ssl.create_default_context(cafile=self._caCert)

        # _maxResumedTLSSessionRate connections in a row, plus two because
        # - the first one is a new TLS session
        # - the session is only accounted for once the handshake has been completed
        for idx in range(self._maxResumedTLSSessionRate + 2):
            conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert, timeout=1, sslctx=sslctx, session=session)
            self.sendTCPQueryOverConnection(conn, query, response=response, timeout=1)
            (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True, timeout=1)
            receivedQuery.id = query.id
            self.assertEqual(receivedQuery, query)
            self.assertEqual(receivedResponse, response)
            if idx == 0:
                self.assertFalse(conn.session_reused)
                session = conn.session
            else:
                self.assertTrue(conn.session_reused)

        try:
            # the next one should be past the max rate
            conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert, timeout=1, sslctx=sslctx, session=session)
            self.sendTCPQueryOverConnection(conn, query, response=response, timeout=1)
            self.recvTCPResponseOverConnection(conn, useQueue=True, timeout=1)
            self.assertTrue(False)
        except ConnectionResetError:
          pass

class TestTCPFrontendLimits(DNSDistTest):

    # this test suite uses a different responder port
    # because it uses a different health check configuration
    _testServerPort = pickAvailablePort()
    _answerUnexpected = True

    _skipListeningOnCL = True
    _tcpIdleTimeout = 2
    _maxTCPConnsPerFrontend = 10
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    setLocal("%s:%d", {maxConcurrentTCPConnections=%d})
    -- disable "near limits" otherwise our tests are broken because connections are forcibly closed
    setTCPConnectionsOverloadThreshold(0)
    """
    _config_params = ['_testServerPort', '_dnsDistListeningAddr', '_dnsDistPort', '_maxTCPConnsPerFrontend']

    def testTCPConnsPerFrontend(self):
        """
        TCP Frontend Limits: Maximum number of conns per frontend
        """
        name = 'maxconnsperfrontend.tcp.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        conns = []

        for idx in range(self._maxTCPConnsPerFrontend + 1):
            conns.append(self.openTCPConnection())

        count = 0
        failed = 0
        for conn in conns:
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
            conn.close()

        # wait a bit to be sure that dnsdist closed the connections
        # and decremented the counters on its side, otherwise subsequent
        # connections will be dropped
        time.sleep(1)

        self.assertEqual(count, self._maxTCPConnsPerFrontend)
        self.assertEqual(failed, 1)
