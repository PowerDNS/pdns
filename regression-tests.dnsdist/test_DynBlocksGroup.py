#!/usr/bin/env python
import base64
import socket
import time
import dns
from dnsdisttests import DNSDistTest
from dnsdistDynBlockTests import DynBlocksTest, waitForMaintenanceToRun, _maintenanceWaitTime

class TestDynBlockGroupQPS(DynBlocksTest):

    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setQueryRate(%d, %d, "Exceeded query rate", %d)

    function maintenance()
	    dbr:apply()
    end
    newServer{address="127.0.0.1:%s"}
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']

    def testDynBlocksQRate(self):
        """
        Dyn Blocks (Group): QRate
        """
        name = 'qrate.group.dynblocks.tests.powerdns.com.'
        self.doTestQRate(name)

class TestDynBlockGroupQTypeRate(DynBlocksTest):

    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setQTypeRate(DNSQType.ANY, %d, %d, "Exceeded qtype rate", %d)

    function maintenance()
	    dbr:apply()
    end
    setDynBlocksAction(DNSAction.Refused)
    newServer{address="127.0.0.1:%d"}
    """
    _config_params = ['_dynBlockANYQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']

    def testDynBlocksQTypeRate(self):
        """
        Dyn Blocks (Group): QType Rate
        """
        name = 'qtype-rate.group.dynblocks.tests.powerdns.com.'
        self.doTestQTypeRate(name)

class TestDynBlockGroupQTypeRateYAML(DynBlocksTest):

    _yaml_config_template = """---
dynamic_rules:
  - name: "Block client generating too many ANY queries"
    rules:
      - type: "qtype-rate"
        rate: %d
        seconds: %d
        action_duration: %d
        comment: "Exceeded ANY rate"
        action: "Refused"
        qtype: "ANY"

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53
"""
    _config_params = []
    _yaml_config_params = ['_dynBlockANYQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']

    def testDynBlocksQTypeRate(self):
        """
        Dyn Blocks (Group / YAML): QType Rate
        """
        name = 'qtype-rate-yaml.group.dynblocks.tests.powerdns.com.'
        self.doTestQTypeRate(name)

class TestDynBlockGroupQPSRefused(DynBlocksTest):

    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setQueryRate(%d, %d, "Exceeded query rate", %d)

    function maintenance()
	    dbr:apply()
    end
    setDynBlocksAction(DNSAction.Refused)
    newServer{address="127.0.0.1:%s"}
    """

    def testDynBlocksQRate(self):
        """
        Dyn Blocks (Group): QRate refused
        """
        name = 'qraterefused.group.dynblocks.tests.powerdns.com.'
        self.doTestQRateRCode(name, dns.rcode.REFUSED)

class TestDynBlockGroupQPSActionRefused(DynBlocksTest):

    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setQueryRate(%d, %d, "Exceeded query rate", %d, DNSAction.Refused)

    function maintenance()
	    dbr:apply()
    end
    setDynBlocksAction(DNSAction.Drop)
    newServer{address="127.0.0.1:%s"}
    """

    def testDynBlocksQRate(self):
        """
        Dyn Blocks (group): QRate refused (action)
        """
        name = 'qrateactionrefused.group.dynblocks.tests.powerdns.com.'
        self.doTestQRateRCode(name, dns.rcode.REFUSED)

class TestDynBlockGroupExcluded(DynBlocksTest):

    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setQueryRate(%d, %d, "Exceeded query rate", %d)
    dbr:excludeRange("127.0.0.1/32")

    function maintenance()
	    dbr:apply()
    end

    newServer{address="127.0.0.1:%s"}
    """

    def testExcluded(self):
        """
        Dyn Blocks (group) : Excluded from the dynamic block rules
        """
        name = 'excluded.group.dynblocks.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        allowed = 0
        sent = 0
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(response, receivedResponse)
                allowed = allowed + 1
            else:
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()

        # we should not have been blocked
        self.assertEqual(allowed, sent)

        waitForMaintenanceToRun()

        # we should still not be blocked
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, receivedResponse)

class TestDynBlockGroupExcludedViaNMG(DynBlocksTest):

    _config_template = """
    local nmg = newNMG()
    nmg:addMask("127.0.0.1/32")

    local dbr = dynBlockRulesGroup()
    dbr:setQueryRate(%d, %d, "Exceeded query rate", %d)
    dbr:excludeRange(nmg)

    function maintenance()
	    dbr:apply()
    end

    newServer{address="127.0.0.1:%s"}
    """

    def testExcluded(self):
        """
        Dyn Blocks (group) : Excluded (via NMG) from the dynamic block rules
        """
        name = 'excluded-nmg.group.dynblocks.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        allowed = 0
        sent = 0
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(response, receivedResponse)
                allowed = allowed + 1
            else:
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()

        # we should not have been blocked
        self.assertEqual(allowed, sent)

        waitForMaintenanceToRun()

        # we should still not be blocked
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, receivedResponse)

class TestDynBlockGroupNoOp(DynBlocksTest):

    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setQueryRate(%d, %d, "Exceeded query rate", %d, DNSAction.NoOp)

    function maintenance()
	    dbr:apply()
    end

    newServer{address="127.0.0.1:%s"}
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']

    def testNoOp(self):
        """
        Dyn Blocks (group) : NoOp
        """
        name = 'noop.group.dynblocks.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        allowed = 0
        sent = 0
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(response, receivedResponse)
                allowed = allowed + 1
            else:
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()

        # a dynamic rule should have been inserted, but the queries should still go on
        self.assertEqual(allowed, sent)

        waitForMaintenanceToRun()

        # the rule should still be present, but the queries pass through anyway
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, receivedResponse)

        # check that the rule has been inserted
        self.doTestDynBlockViaAPI('127.0.0.1/32', 'Exceeded query rate', 1, self._dynBlockDuration, 0, sent)

class TestDynBlockGroupWarning(DynBlocksTest):

    _dynBlockWarningQPS = 5
    _dynBlockQPS = 20
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setQueryRate(%d, %d, "Exceeded query rate", %d, DNSAction.Drop, %d)

    function maintenance()
	    dbr:apply()
    end

    newServer{address="127.0.0.1:%s"}
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_dynBlockWarningQPS', '_testServerPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']

    def testWarning(self):
        """
        Dyn Blocks (group) : Warning
        """
        name = 'warning.group.dynblocks.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        allowed = 0
        sent = 0
        for _ in range((self._dynBlockWarningQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(response, receivedResponse)
                allowed = allowed + 1
            else:
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()

        # a dynamic rule should have been inserted, but the queries should
        # still go on because we are still at warning level
        self.assertEqual(allowed, sent)

        waitForMaintenanceToRun()

        # the rule should still be present, but the queries pass through anyway
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, receivedResponse)

        # check that the rule has been inserted
        self.doTestDynBlockViaAPI('127.0.0.1/32', 'Exceeded query rate', 1, self._dynBlockDuration, 0, sent)

        self.doTestQRate(name)

class TestDynBlockGroupPort(DNSDistTest):

    _dynBlockQPS = 20
    _dynBlockPeriod = 2
    # this needs to be greater than maintenanceWaitTime
    _dynBlockDuration = _maintenanceWaitTime + 1
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setQueryRate(%d, %d, "Exceeded query rate", %d, DNSAction.Drop)
    -- take the exact port into account
    dbr:setMasks(32, 128, 16)

    function maintenance()
	    dbr:apply()
    end
    newServer{address="127.0.0.1:%d"}
    """
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']

    def testPort(self):
        """
        Dyn Blocks (group): Exact port matching
        """
        name = 'port.group.dynblocks.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        allowed = 0
        sent = 0
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(response, receivedResponse)
                allowed = allowed + 1
            else:
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()

        # we might be already blocked, but we should have been able to send
        # at least self._dynBlockQPS queries
        self.assertGreaterEqual(allowed, self._dynBlockQPS)

        if allowed == sent:
            waitForMaintenanceToRun()

        # we should now be dropped for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)

        # use a new socket, so a new port
        self._toResponderQueue.put(response, True, 1.0)
        newsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        newsock.settimeout(1.0)
        newsock.connect(("127.0.0.1", self._dnsDistPort))
        newsock.send(query.to_wire())
        receivedResponse = newsock.recv(4096)
        if receivedResponse:
            receivedResponse = dns.message.from_wire(receivedResponse)
        receivedQuery = self._fromResponderQueue.get(True, 1.0)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

class TestDynBlockGroupQSuffixMatchYAML(DynBlocksTest):

    _yaml_config_template = """---
dynamic_rules:
  - name: "Check Suffix Match visitor from YAML"
    rules:
      - type: "suffix-match"
        seconds: %d
        action_duration: %d
        comment: "Suffix-match"
        visitor_function_code: |
          visitor_called = false
          return function(parentStats, nodeStats)
            visitor_called = true
            return false
          end

query_rules:
  - name: "check that the visitor function has been called"
    selector:
      type: "QNameSet"
      qnames:
        - "check-visitor.group.dynblocks.tests.powerdns.com."
    action:
      type: "Lua"
      name: "Return 192.0.2.1 if the visitor function has been called, 192.0.2.2 otherwise"
      function_code: |
        return function(dq)
          if visitor_called then
            return DNSAction.Spoof, "192.0.2.1"
          end
          return DNSAction.Spoof, "192.0.2.2"
        end

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53
"""
    _config_params = []
    _yaml_config_params = ['_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']

    def testSuffixMatchVisitorCalled(self):
        """
        Dyn Blocks (Group / YAML): Visitor called
        """
        name = 'check-visitor.group.dynblocks.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.NOERROR)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        expectedResponse.answer.append(rrset)

        method = "sendUDPQuery"
        sender = getattr(self, method)
        for _ in range(4):
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            if receivedResponse == expectedResponse:
                break
            time.sleep(1)

        self.assertEqual(receivedResponse, expectedResponse)
