#!/usr/bin/env python
import base64
import threading
import time
import ssl
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort

class HealthCheckTest(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}
    """

    def getBackendStatus(self):
        return self.sendConsoleCommand("if getServer(0):isUp() then return 'up' else return 'down' end").strip("\n")

class TestDefaultHealthCheck(HealthCheckTest):
    # this test suite uses a different responder port
    # because we need fresh counters
    _testServerPort = pickAvailablePort()

    def testDefault(self):
        """
        HealthChecks: Default
        """
        before = TestDefaultHealthCheck._healthCheckCounter
        time.sleep(1.5)
        self.assertGreater(TestDefaultHealthCheck._healthCheckCounter, before)
        self.assertEqual(self.getBackendStatus(), 'up')

        self.sendConsoleCommand("getServer(0):setUp()")
        self.assertEqual(self.getBackendStatus(), 'up')

        before = TestDefaultHealthCheck._healthCheckCounter
        time.sleep(1.5)
        self.assertEqual(TestDefaultHealthCheck._healthCheckCounter, before)

        self.sendConsoleCommand("getServer(0):setDown()")
        self.assertEqual(self.getBackendStatus(), 'down')

        before = TestDefaultHealthCheck._healthCheckCounter
        time.sleep(1.5)
        self.assertEqual(TestDefaultHealthCheck._healthCheckCounter, before)

        self.sendConsoleCommand("getServer(0):setAuto()")
        # we get back the previous state, which was up
        self.assertEqual(self.getBackendStatus(), 'up')

        before = TestDefaultHealthCheck._healthCheckCounter
        time.sleep(1.5)
        self.assertGreater(TestDefaultHealthCheck._healthCheckCounter, before)
        self.assertEqual(self.getBackendStatus(), 'up')

        self.sendConsoleCommand("getServer(0):setDown()")
        self.assertEqual(self.getBackendStatus(), 'down')
        self.sendConsoleCommand("getServer(0):setAuto(false)")

        before = TestDefaultHealthCheck._healthCheckCounter
        time.sleep(1.5)
        self.assertGreater(TestDefaultHealthCheck._healthCheckCounter, before)
        self.assertEqual(self.getBackendStatus(), 'up')

class TestHealthCheckForcedUP(HealthCheckTest):
    # this test suite uses a different responder port
    # because we need fresh counters
    _testServerPort = pickAvailablePort()

    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    srv = newServer{address="127.0.0.1:%d"}
    srv:setUp()
    """

    def testForcedUp(self):
        """
        HealthChecks: Forced UP
        """
        before = TestHealthCheckForcedUP._healthCheckCounter
        time.sleep(1.5)
        self.assertEqual(TestHealthCheckForcedUP._healthCheckCounter, before)
        self.assertEqual(self.getBackendStatus(), 'up')

class TestHealthCheckForcedDown(HealthCheckTest):
    # this test suite uses a different responder port
    # because we need fresh counters
    _testServerPort = pickAvailablePort()

    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    srv = newServer{address="127.0.0.1:%d"}
    srv:setDown()
    """

    def testForcedDown(self):
        """
        HealthChecks: Forced Down
        """
        before = TestHealthCheckForcedDown._healthCheckCounter
        time.sleep(1.5)
        self.assertEqual(TestHealthCheckForcedDown._healthCheckCounter, before)

class TestHealthCheckCustomName(HealthCheckTest):
    # this test suite uses a different responder port
    # because it uses a different health check name
    _testServerPort = pickAvailablePort()

    _healthCheckName = 'powerdns.com.'
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort', '_healthCheckName']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    srv = newServer{address="127.0.0.1:%d", checkName='%s'}
    """

    def testAuto(self):
        """
        HealthChecks: Custom name
        """
        before = TestHealthCheckCustomName._healthCheckCounter
        time.sleep(1.5)
        self.assertGreater(TestHealthCheckCustomName._healthCheckCounter, before)
        self.assertEqual(self.getBackendStatus(), 'up')

class TestHealthCheckCustomNameNoAnswer(HealthCheckTest):
    # this test suite uses a different responder port
    # because it uses a different health check configuration
    _testServerPort = pickAvailablePort()

    _answerUnexpected = False
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    srv = newServer{address="127.0.0.1:%d", checkName='powerdns.com.'}
    """

    def testAuto(self):
        """
        HealthChecks: Custom name not expected by the responder
        """
        before = TestHealthCheckCustomNameNoAnswer._healthCheckCounter
        time.sleep(1.5)
        self.assertEqual(TestHealthCheckCustomNameNoAnswer._healthCheckCounter, before)
        self.assertEqual(self.getBackendStatus(), 'down')

class TestHealthCheckCustomFunction(HealthCheckTest):
    # this test suite uses a different responder port
    # because it uses a different health check configuration
    _testServerPort = pickAvailablePort()
    _answerUnexpected = False

    _healthCheckName = 'powerdns.com.'
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    function myHealthCheckFunction(qname, qtype, qclass, dh)
      dh:setCD(true)

      return newDNSName('powerdns.com.'), DNSQType.AAAA, qclass
    end

    srv = newServer{address="127.0.0.1:%d", checkName='powerdns.org.', checkFunction=myHealthCheckFunction}
    """

    def testAuto(self):
        """
        HealthChecks: Custom function
        """
        before = TestHealthCheckCustomFunction._healthCheckCounter
        time.sleep(1.5)
        self.assertGreater(TestHealthCheckCustomFunction._healthCheckCounter, before)
        self.assertEqual(self.getBackendStatus(), 'up')

_do53HealthCheckQueries = 0
_dotHealthCheckQueries = 0
_dohHealthCheckQueries = 0

class TestLazyHealthChecks(HealthCheckTest):
    _extraStartupSleep = 1
    _do53Port = pickAvailablePort()
    _dotPort = pickAvailablePort()
    _dohPort = pickAvailablePort()

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_do53Port', '_dotPort', '_dohPort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    newServer{address="127.0.0.1:%s", healthCheckMode='lazy', checkInterval=1, lazyHealthCheckFailedInterval=1, lazyHealthCheckThreshold=10, lazyHealthCheckSampleSize=100,  lazyHealthCheckMinSampleCount=10, lazyHealthCheckMode='TimeoutOrServFail', pool=''}

    newServer{address="127.0.0.1:%s", tls='openssl', caStore='ca.pem', healthCheckMode='lazy', checkInterval=1, lazyHealthCheckFailedInterval=1, lazyHealthCheckThreshold=10, lazyHealthCheckSampleSize=100,  lazyHealthCheckMinSampleCount=10, lazyHealthCheckMode='TimeoutOrServFail', pool='dot'}
    addAction('dot.lazy.test.powerdns.com.', PoolAction('dot'))

    newServer{address="127.0.0.1:%s", tls='openssl', dohPath='/dns-query', caStore='ca.pem', healthCheckMode='lazy', checkInterval=1, lazyHealthCheckFailedInterval=1, lazyHealthCheckThreshold=10, lazyHealthCheckSampleSize=100,  lazyHealthCheckMinSampleCount=10, lazyHealthCheckMode='TimeoutOrServFail', pool='doh'}
    addAction('doh.lazy.test.powerdns.com.', PoolAction('doh'))
    """
    _verboseMode = True

    @staticmethod
    def HandleDNSQuery(request):
        response = dns.message.make_response(request)
        if str(request.question[0].name).startswith('server-failure'):
            response.set_rcode(dns.rcode.SERVFAIL)
        return response.to_wire()

    @classmethod
    def Do53Callback(cls, request):
        global _do53HealthCheckQueries
        if str(request.question[0].name).startswith('a.root-servers.net'):
            _do53HealthCheckQueries = _do53HealthCheckQueries + 1
            response = dns.message.make_response(request)
            return response.to_wire()
        return cls.HandleDNSQuery(request)

    @classmethod
    def DoTCallback(cls, request):
        global _dotHealthCheckQueries
        if str(request.question[0].name).startswith('a.root-servers.net'):
            _dotHealthCheckQueries = _dotHealthCheckQueries + 1
            response = dns.message.make_response(request)
            return response.to_wire()
        return cls.HandleDNSQuery(request)

    @classmethod
    def DoHCallback(cls, request, requestHeaders, fromQueue, toQueue):
        global _dohHealthCheckQueries
        if str(request.question[0].name).startswith('a.root-servers.net'):
            _dohHealthCheckQueries = _dohHealthCheckQueries + 1
            response = dns.message.make_response(request)
            return 200, response.to_wire()
        return 200, cls.HandleDNSQuery(request)

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        Do53Responder = threading.Thread(name='Do53 Lazy Responder', target=cls.UDPResponder, args=[cls._do53Port, cls._toResponderQueue, cls._fromResponderQueue, False, cls.Do53Callback])
        Do53Responder.daemon = True
        Do53Responder.start()

        Do53TCPResponder = threading.Thread(name='Do53 TCP Lazy Responder', target=cls.TCPResponder, args=[cls._do53Port, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.Do53Callback])
        Do53TCPResponder.daemon = True
        Do53TCPResponder.start()

        DoTResponder = threading.Thread(name='DoT Lazy Responder', target=cls.TCPResponder, args=[cls._dotPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.DoTCallback, tlsContext])
        DoTResponder.daemon = True
        DoTResponder.start()

        DoHResponder = threading.Thread(name='DoH Lazy Responder', target=cls.DOHResponder, args=[cls._dohPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.DoHCallback, tlsContext])
        DoHResponder.daemon = True
        DoHResponder.start()

    def testDo53Lazy(self):
        """
        Lazy Healthchecks: Do53
        """
        # there is one initial query on startup
        self.assertEqual(_do53HealthCheckQueries, 1)
        time.sleep(1)
        self.assertEqual(_do53HealthCheckQueries, 1)

        name = 'do53.lazy.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        failedQuery = dns.message.make_query('server-failure.do53.lazy.test.powerdns.com.', 'A', 'IN')
        failedResponse = dns.message.make_response(failedQuery)
        failedResponse.set_rcode(dns.rcode.SERVFAIL)

        # send a few valid queries
        for _ in range(5):
            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                (_, receivedResponse) = sender(query, response=None, useQueue=False)
                self.assertEqual(receivedResponse, response)

        self.assertEqual(_do53HealthCheckQueries, 1)

        # we need at least 10 samples, and 10 percent of them failing, so two failing queries should be enough
        for _ in range(2):
            (_, receivedResponse) = self.sendUDPQuery(failedQuery, response=None, useQueue=False)
            self.assertEqual(receivedResponse, failedResponse)

        time.sleep(1.5)
        self.assertEqual(_do53HealthCheckQueries, 2)
        self.assertEqual(self.getBackendStatus(), 'up')

    def testDoTLazy(self):
        """
        Lazy Healthchecks: DoT
        """
        # there is one initial query on startup
        self.assertEqual(_dotHealthCheckQueries, 1)
        time.sleep(1)
        self.assertEqual(_dotHealthCheckQueries, 1)

        name = 'dot.lazy.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        failedQuery = dns.message.make_query('server-failure.dot.lazy.test.powerdns.com.', 'A', 'IN')
        failedResponse = dns.message.make_response(failedQuery)
        failedResponse.set_rcode(dns.rcode.SERVFAIL)

        # send a few valid queries
        for _ in range(5):
            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                (_, receivedResponse) = sender(query, response=None, useQueue=False)
                self.assertEqual(receivedResponse, response)

        self.assertEqual(_dotHealthCheckQueries, 1)

        # we need at least 10 samples, and 10 percent of them failing, so two failing queries should be enough
        for _ in range(2):
            (_, receivedResponse) = self.sendUDPQuery(failedQuery, response=None, useQueue=False)
            self.assertEqual(receivedResponse, failedResponse)

        time.sleep(1.5)
        self.assertEqual(_dotHealthCheckQueries, 2)
        self.assertEqual(self.getBackendStatus(), 'up')

    def testDoHLazy(self):
        """
        Lazy Healthchecks: DoH
        """
        # there is one initial query on startup
        self.assertEqual(_dohHealthCheckQueries, 1)
        time.sleep(1)
        self.assertEqual(_dohHealthCheckQueries, 1)

        name = 'doh.lazy.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        failedQuery = dns.message.make_query('server-failure.doh.lazy.test.powerdns.com.', 'A', 'IN')
        failedResponse = dns.message.make_response(failedQuery)
        failedResponse.set_rcode(dns.rcode.SERVFAIL)

        # send a few valid queries
        for _ in range(5):
            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                (_, receivedResponse) = sender(query, response=None, useQueue=False)
                self.assertEqual(receivedResponse, response)

        self.assertEqual(_dohHealthCheckQueries, 1)

        # we need at least 10 samples, and 10 percent of them failing, so two failing queries should be enough
        for _ in range(2):
            (_, receivedResponse) = self.sendUDPQuery(failedQuery, response=None, useQueue=False)
            self.assertEqual(receivedResponse, failedResponse)

        time.sleep(1.5)
        self.assertEqual(_dohHealthCheckQueries, 2)
        self.assertEqual(self.getBackendStatus(), 'up')
