#!/usr/bin/env python
import base64
import requests
import ssl
import threading
import time
import dns
import queue
from dnsdisttests import DNSDistTest, pickAvailablePort, ResponderDropAction

class HealthCheckTest(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _webTimeout = 2.0
    _webServerPort = pickAvailablePort()
    _webServerAPIKey = 'apisecret'
    _webServerAPIKeyHashed = '$scrypt$ln=10,p=1,r=8$9v8JxDfzQVyTpBkTbkUqYg==$bDQzAOHeK1G9UvTPypNhrX48w974ZXbFPtRKS34+aso='
    _config_params = ['_consoleKeyB64', '_consolePort', '_webServerPort', '_webServerAPIKeyHashed', '_testServerPort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    webserver("127.0.0.1:%d")
    setWebserverConfig({apiKey="%s"})
    newServer{address="127.0.0.1:%d"}
    """

    def getBackendStatus(self):
        return self.sendConsoleCommand("if getServer(0):isUp() then return 'up' else return 'down' end").strip("\n")

    def getBackendMetric(self, backendID, metricName):
        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/api/v1/servers/localhost'
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        self.assertIn('servers', content)
        servers = content['servers']
        server = servers[backendID]
        return int(server[metricName])

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
        self.assertEqual(self.getBackendMetric(0, 'healthCheckFailures'), 0)
        self.assertEqual(self.getBackendStatus(), 'up')

        self.sendConsoleCommand("getServer(0):setUp()")
        self.assertEqual(self.getBackendStatus(), 'up')
        self.assertEqual(self.sendConsoleCommand("getServer(0):getHealthCheckMode()").rstrip(), "active")

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
        self.assertEqual(self.sendConsoleCommand("getServer(0):getHealthCheckMode()").rstrip(), "active")

        before = TestDefaultHealthCheck._healthCheckCounter
        time.sleep(1.5)
        self.assertGreater(TestDefaultHealthCheck._healthCheckCounter, before)
        self.assertEqual(self.getBackendStatus(), 'up')

        self.sendConsoleCommand("getServer(0):setDown()")
        self.assertEqual(self.getBackendStatus(), 'down')
        self.assertEqual(self.sendConsoleCommand("getServer(0):getHealthCheckMode()").rstrip(), "active")
        self.sendConsoleCommand("getServer(0):setAuto(false)")

        before = TestDefaultHealthCheck._healthCheckCounter
        time.sleep(1.5)
        self.assertGreater(TestDefaultHealthCheck._healthCheckCounter, before)
        self.assertEqual(self.getBackendStatus(), 'up')
        self.assertEqual(self.getBackendMetric(0, 'healthCheckFailures'), 0)
        self.assertEqual(self.sendConsoleCommand("getServer(0):getHealthCheckMode()").rstrip(), "active")

        self.sendConsoleCommand("getServer(0):setLazyAuto()")
        self.assertEqual(self.sendConsoleCommand("getServer(0):getHealthCheckMode()").rstrip(), "lazy")
        self.sendConsoleCommand("getServer(0):setDown()")
        self.sendConsoleCommand("getServer(0):setAuto()")
        self.assertEqual(self.sendConsoleCommand("getServer(0):getHealthCheckMode()").rstrip(), "lazy")
        self.sendConsoleCommand("getServer(0):setActiveAuto()")
        self.assertEqual(self.sendConsoleCommand("getServer(0):getHealthCheckMode()").rstrip(), "active")

class TestHealthCheckForcedUP(HealthCheckTest):
    # this test suite uses a different responder port
    # because we need fresh counters
    _testServerPort = pickAvailablePort()

    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    webserver("127.0.0.1:%d")
    setWebserverConfig({apiKey="%s"})
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
        self.assertEqual(self.getBackendMetric(0, 'healthCheckFailures'), 0)

class TestHealthCheckForcedDown(HealthCheckTest):
    # this test suite uses a different responder port
    # because we need fresh counters
    _testServerPort = pickAvailablePort()

    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    webserver("127.0.0.1:%d")
    setWebserverConfig({apiKey="%s"})
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
        self.assertEqual(self.getBackendMetric(0, 'healthCheckFailures'), 0)

class TestHealthCheckCustomName(HealthCheckTest):
    # this test suite uses a different responder port
    # because it uses a different health check name
    _testServerPort = pickAvailablePort()

    _healthCheckName = 'powerdns.com.'
    _config_params = ['_consoleKeyB64', '_consolePort', '_webServerPort', '_webServerAPIKeyHashed', '_testServerPort', '_healthCheckName']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    webserver("127.0.0.1:%d")
    setWebserverConfig({apiKey="%s"})
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
        self.assertEqual(self.getBackendMetric(0, 'healthCheckFailures'), 0)

class TestHealthCheckCustomNameNoAnswer(HealthCheckTest):
    # this test suite uses a different responder port
    # because it uses a different health check configuration
    _testServerPort = pickAvailablePort()

    _answerUnexpected = False
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    webserver("127.0.0.1:%d")
    setWebserverConfig({apiKey="%s"})
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
        self.assertGreater(self.getBackendMetric(0, 'healthCheckFailures'), 0)
        self.assertGreater(self.getBackendMetric(0, 'healthCheckFailuresTimeout'), 0)

class TestHealthCheckCustomFunction(HealthCheckTest):
    # this test suite uses a different responder port
    # because it uses a different health check configuration
    _testServerPort = pickAvailablePort()
    _answerUnexpected = False

    _healthCheckName = 'powerdns.com.'
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    webserver("127.0.0.1:%d")
    setWebserverConfig({apiKey="%s"})

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

    newServer{address="127.0.0.1:%d", healthCheckMode='lazy', checkInterval=1, lazyHealthCheckFailedInterval=1, lazyHealthCheckThreshold=10, lazyHealthCheckSampleSize=100,  lazyHealthCheckMinSampleCount=10, lazyHealthCheckMode='TimeoutOrServFail', pool=''}

    newServer{address="127.0.0.1:%d", tls='openssl', caStore='ca.pem', subjectAddr='127.0.0.1', healthCheckMode='lazy', checkInterval=1, lazyHealthCheckFailedInterval=1, lazyHealthCheckThreshold=10, lazyHealthCheckSampleSize=100,  lazyHealthCheckMinSampleCount=10, lazyHealthCheckMode='TimeoutOrServFail', pool='dot'}
    addAction('dot.lazy.test.powerdns.com.', PoolAction('dot'))

    newServer{address="127.0.0.1:%d", tls='openssl', dohPath='/dns-query', caStore='ca.pem', subjectAddr='127.0.0.1', healthCheckMode='lazy', checkInterval=1, lazyHealthCheckFailedInterval=1, lazyHealthCheckThreshold=10, lazyHealthCheckSampleSize=100,  lazyHealthCheckMinSampleCount=10, lazyHealthCheckMode='TimeoutOrServFail', pool='doh'}
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

class HealthCheckUpdateParams(HealthCheckTest):

    _healthQueue = queue.Queue()
    _dropHealthCheck = False
    _delayResponse = None

    @classmethod
    def startResponders(cls):
        print("Launching responders..")
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, cls.healthCallback])
        cls._UDPResponder.daemon = True
        cls._UDPResponder.start()

    @classmethod
    def healthCallback(cls, request):
        if cls._dropHealthCheck:
          cls._healthQueue.put(False)
          return ResponderDropAction()
        response = dns.message.make_response(request)
        if cls._delayResponse is not None:
            time.sleep(cls._delayResponse)
        cls._healthQueue.put(True)
        return response.to_wire()

    @classmethod
    def wait1(cls, block=True):
        return cls._healthQueue.get(block)

    @classmethod
    def setDrop(cls, flag=True):
        cls._dropHealthCheck = flag

    @classmethod
    def setDelay(cls, delay):
        cls._delayResponse = delay

class TestUpdateHCParamsCombo1(HealthCheckUpdateParams):

    # this test suite uses a different responder port
    _testServerPort = pickAvailablePort()

    def testCombo1(self):
        """
        HealthChecks: Update maxCheckFailures, rise
        """
        # consume health checks upon sys init
        try:
          while self.wait1(False): pass
        except queue.Empty: pass

        self.assertEqual(self.wait1(), True)
        time.sleep(0.1)
        self.assertEqual(self.getBackendMetric(0, 'healthCheckFailures'), 0)
        self.assertEqual(self.getBackendStatus(), 'up')

        self.sendConsoleCommand("getServer(0):setHealthCheckParams({maxCheckFailures=2,rise=2})")
        self.setDrop()

        # wait for 1st failure
        i = 1
        while i <= 3:
            rc = self.wait1()
            if rc is False: break
            i += 1
        self.assertGreater(3, i)
        time.sleep(1.1)
        # should have failures but still up
        self.assertGreater(self.getBackendMetric(0, 'healthCheckFailures'), 0)
        self.assertEqual(self.getBackendStatus(), 'up')

        # wait for 2nd failure
        self.assertEqual(self.wait1(), False)
        time.sleep(1.1)
        # should have more failures and down
        self.assertGreater(self.getBackendMetric(0, 'healthCheckFailures'), 1)
        self.assertEqual(self.getBackendStatus(), 'down')

        self.setDrop(False)

        # wait for 1st success
        i = 1
        while i <= 3:
            rc = self.wait1()
            if rc is True: break
            i += 1
        self.assertGreater(3, i)
        time.sleep(0.1)
        # still down
        self.assertEqual(self.getBackendStatus(), 'down')

        beforeFailure = self.getBackendMetric(0, 'healthCheckFailures')

        # wati for 2nd success
        self.assertEqual(self.wait1(), True)
        time.sleep(0.1)
        # should have no more failures, back to up
        self.assertEqual(self.getBackendMetric(0, 'healthCheckFailures'), beforeFailure)
        self.assertEqual(self.getBackendStatus(), 'up')

class TestUpdateHCParamsCombo2(HealthCheckUpdateParams):

    # this test suite uses a different responder port
    _testServerPort = pickAvailablePort()

    def testCombo2(self):
        """
        HealthChecks: Update checkTimeout, checkInterval
        """
        # consume health checks upon sys init
        try:
          while self.wait1(False): pass
        except queue.Empty: pass

        self.assertEqual(self.wait1(), True)
        time.sleep(0.1)
        self.assertEqual(self.getBackendMetric(0, 'healthCheckFailures'), 0)
        self.assertEqual(self.getBackendStatus(), 'up')

        self.sendConsoleCommand("getServer(0):setHealthCheckParams({checkInterval=2})")

        # start timing
        self.assertEqual(self.wait1(), True)
        t1 = time.time()
        self.assertEqual(self.wait1(), True)
        t2 = time.time()
        # intervals shall be greater than 1
        self.assertGreater(t2-t1, 1.5)

        self.sendConsoleCommand("getServer(0):setHealthCheckParams({checkTimeout=2000})")
        self.setDrop()

        # wait for 1st failure
        i = 1
        while i <= 3:
            rc = self.wait1()
            if rc is False: break
            i += 1
        self.assertGreater(3, i)

        beforeFailure = self.getBackendMetric(0, 'healthCheckFailures')

        time.sleep(1.5)
        # not timeout yet, should have no failure increase
        self.assertEqual(self.getBackendMetric(0, 'healthCheckFailures'), beforeFailure)

        time.sleep(1)
        # now should timeout and failure increased
        self.assertEqual(self.getBackendMetric(0, 'healthCheckFailures'), beforeFailure+1)

class TestHealthCheckLatency(HealthCheckUpdateParams):

    # this test suite uses a different responder port
    _testServerPort = pickAvailablePort()

    def testLatency(self):
        """
        HealthChecks: Check latency
        """
        # consume health checks upon sys init
        try:
          while self.wait1(False): pass
        except queue.Empty: pass

        self.assertEqual(self.wait1(), True)
        time.sleep(0.1)
        self.assertEqual(self.getBackendMetric(0, 'healthCheckFailures'), 0)
        self.assertEqual(self.getBackendStatus(), 'up')
        latency = self.getBackendMetric(0, 'healthCheckLatency')
        # less than 500 ms
        self.assertLess(latency, 500)

        # introduce 500 ms of latency
        self.setDelay(0.5)

        self.wait1(True)

        # should have no failures, still up
        self.assertEqual(self.getBackendMetric(0, 'healthCheckFailures'), 0)
        self.assertEqual(self.getBackendStatus(), 'up')
        latency = self.getBackendMetric(0, 'healthCheckLatency')
        # should be at least 500 ms
        self.assertGreaterEqual(latency, 500)

        self.setDelay(None)

class TestServerStateChange(HealthCheckTest):

    _healthQueue = queue.Queue()
    _dropHealthCheck = False
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    webserver("127.0.0.1:%d")
    setWebserverConfig({apiKey="%s"})
    srv = newServer{address="127.0.0.1:%d",maxCheckFailures=1,checkTimeout=1000,checkInterval=1,rise=1}
    srv:setAuto(false)
    serverUpCount = {}
    serverDownCount = {}
    function ServerStateChange(nameAddr, newState)
        if newState then
            if not serverUpCount[nameAddr] then serverUpCount[nameAddr] = 0 end
            serverUpCount[nameAddr] = serverUpCount[nameAddr] + 1
        else
            if not serverDownCount[nameAddr] then serverDownCount[nameAddr] = 0 end
            serverDownCount[nameAddr] = serverDownCount[nameAddr] + 1
        end
    end
    addServerStateChangeCallback(ServerStateChange)
    function getCount(nameAddr, state)
        if state then
            if not serverUpCount[nameAddr] then serverUpCount[nameAddr] = 0 end
            return serverUpCount[nameAddr]
        else
            if not serverDownCount[nameAddr] then serverDownCount[nameAddr] = 0 end
            return serverDownCount[nameAddr]
        end
    end
    """

    @classmethod
    def startResponders(cls):
        print("Launching responders..")
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, cls.healthCallback])
        cls._UDPResponder.daemon = True
        cls._UDPResponder.start()

    @classmethod
    def healthCallback(cls, request):
        if cls._dropHealthCheck:
          cls._healthQueue.put(False)
          print("health check received drop")
          return ResponderDropAction()
        response = dns.message.make_response(request)
        cls._healthQueue.put(True)
        print("health check received return")
        return response.to_wire()

    @classmethod
    def setDrop(cls, flag=True):
        cls._dropHealthCheck = flag

    def getCount(self, nameAddr, state):
        if state:
            return int(self.sendConsoleCommand("getCount('{}', true)".format(nameAddr)).strip("\n"))
        return int(self.sendConsoleCommand("getCount('{}', false)".format(nameAddr)).strip("\n"))

    def testServerStateChange(self):
        """
        HealthChecks: test Server State Change callback
        """

        nameAddr = self.sendConsoleCommand("getServer(0):getNameWithAddr()").strip("\n")
        self.assertTrue(nameAddr)

        time.sleep(1)
        # server initial up shall have been hit
        self.assertEqual(self.getBackendStatus(), 'up')
        self.assertEqual(self.getCount(nameAddr, True), 1)
        self.assertEqual(self.getCount(nameAddr, False), 0)

        self.setDrop(True)
        time.sleep(2.5)
        # up count did not change, down count increased by 1
        self.assertEqual(self.getBackendStatus(), 'down')
        self.assertEqual(self.getCount(nameAddr, True), 1)
        self.assertEqual(self.getCount(nameAddr, False), 1)

        self.setDrop(False)
        time.sleep(1.5)
        # up count increased again, down count did not change
        self.assertEqual(self.getBackendStatus(), 'up')
        self.assertEqual(self.getCount(nameAddr, True), 2)
        self.assertEqual(self.getCount(nameAddr, False), 1)
