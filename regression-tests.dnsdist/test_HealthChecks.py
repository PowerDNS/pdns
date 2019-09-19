#!/usr/bin/env python
import base64
import time
import dns
from dnsdisttests import DNSDistTest

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
    _testServerPort = 5380

    def testDefault(self):
        """
        HealthChecks: Default
        """
        before = TestDefaultHealthCheck._healthCheckCounter
        time.sleep(1.5)
        self.assertGreater(TestDefaultHealthCheck._healthCheckCounter, before)
        self.assertEquals(self.getBackendStatus(), 'up')

        self.sendConsoleCommand("getServer(0):setUp()")
        self.assertEquals(self.getBackendStatus(), 'up')

        before = TestDefaultHealthCheck._healthCheckCounter
        time.sleep(1.5)
        self.assertEquals(TestDefaultHealthCheck._healthCheckCounter, before)

        self.sendConsoleCommand("getServer(0):setDown()")
        self.assertEquals(self.getBackendStatus(), 'down')

        before = TestDefaultHealthCheck._healthCheckCounter
        time.sleep(1.5)
        self.assertEquals(TestDefaultHealthCheck._healthCheckCounter, before)

        self.sendConsoleCommand("getServer(0):setAuto()")
        # we get back the previous state, which was up
        self.assertEquals(self.getBackendStatus(), 'up')

        before = TestDefaultHealthCheck._healthCheckCounter
        time.sleep(1.5)
        self.assertGreater(TestDefaultHealthCheck._healthCheckCounter, before)
        self.assertEquals(self.getBackendStatus(), 'up')

        self.sendConsoleCommand("getServer(0):setDown()")
        self.assertEquals(self.getBackendStatus(), 'down')
        self.sendConsoleCommand("getServer(0):setAuto(false)")

        before = TestDefaultHealthCheck._healthCheckCounter
        time.sleep(1.5)
        self.assertGreater(TestDefaultHealthCheck._healthCheckCounter, before)
        self.assertEquals(self.getBackendStatus(), 'up')

class TestHealthCheckForcedUP(HealthCheckTest):
    # this test suite uses a different responder port
    # because we need fresh counters
    _testServerPort = 5381

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
        self.assertEquals(TestHealthCheckForcedUP._healthCheckCounter, before)
        self.assertEquals(self.getBackendStatus(), 'up')

class TestHealthCheckForcedDown(HealthCheckTest):
    # this test suite uses a different responder port
    # because we need fresh counters
    _testServerPort = 5382

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
        self.assertEquals(TestHealthCheckForcedDown._healthCheckCounter, before)

class TestHealthCheckCustomName(HealthCheckTest):
    # this test suite uses a different responder port
    # because it uses a different health check name
    _testServerPort = 5383

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
        self.assertEquals(self.getBackendStatus(), 'up')

class TestHealthCheckCustomNameNoAnswer(HealthCheckTest):
    # this test suite uses a different responder port
    # because it uses a different health check configuration
    _testServerPort = 5384

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
        self.assertEquals(TestHealthCheckCustomNameNoAnswer._healthCheckCounter, before)
        self.assertEquals(self.getBackendStatus(), 'down')

class TestHealthCheckCustomFunction(HealthCheckTest):
    # this test suite uses a different responder port
    # because it uses a different health check configuration
    _testServerPort = 5385
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
        self.assertEquals(self.getBackendStatus(), 'up')
