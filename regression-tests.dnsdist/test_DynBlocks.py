#!/usr/bin/env python
import time
import dns
from dnsdisttests import DNSDistTest
from dnsdistDynBlockTests import DynBlocksTest, waitForMaintenanceToRun, _maintenanceWaitTime


class TestDynBlockQPS(DynBlocksTest):
    _config_template = """
    function maintenance()
	    addDynBlocks(exceedQRate(%d, %d), "Exceeded query rate", %d)
    end
    newServer{address="127.0.0.1:%d"}
    webserver("127.0.0.1:%d")
    setWebserverConfig({password="%s", apiKey="%s"})
    """
    _config_params = [
        "_dynBlockQPS",
        "_dynBlockPeriod",
        "_dynBlockDuration",
        "_testServerPort",
        "_webServerPort",
        "_webServerBasicAuthPasswordHashed",
        "_webServerAPIKeyHashed",
    ]

    def testDynBlocksQRate(self):
        """
        Dyn Blocks: QRate
        """
        name = "qrate.dynblocks.tests.powerdns.com."
        self.doTestQRate(name)


class TestDynBlockQPSRefused(DynBlocksTest):
    _config_template = """
    function maintenance()
	    addDynBlocks(exceedQRate(%d, %d), "Exceeded query rate", %d)
    end
    setDynBlocksAction(DNSAction.Refused)
    newServer{address="127.0.0.1:%d"}
    """

    def testDynBlocksQRate(self):
        """
        Dyn Blocks: QRate refused
        """
        name = "qraterefused.dynblocks.tests.powerdns.com."
        self.doTestQRateRCode(name, dns.rcode.REFUSED)


class TestDynBlockQPSActionRefused(DynBlocksTest):
    _config_template = """
    function maintenance()
	    addDynBlocks(exceedQRate(%d, %d), "Exceeded query rate", %d, DNSAction.Refused)
    end
    setDynBlocksAction(DNSAction.Drop)
    newServer{address="127.0.0.1:%d"}
    """

    def testDynBlocksQRate(self):
        """
        Dyn Blocks: QRate refused (action)
        """
        name = "qrateactionrefused.dynblocks.tests.powerdns.com."
        self.doTestQRateRCode(name, dns.rcode.REFUSED)


class TestDynBlockQPSActionNXD(DynBlocksTest):
    _config_template = """
    function maintenance()
	    addDynBlocks(exceedQRate(%d, %d), "Exceeded query rate", %d, DNSAction.Nxdomain)
    end
    setDynBlocksAction(DNSAction.Drop)
    newServer{address="127.0.0.1:%d"}
    """

    def testDynBlocksQRate(self):
        """
        Dyn Blocks: QRate NXD (action)
        """
        name = "qrateactionnxd.dynblocks.tests.powerdns.com."
        self.doTestQRateRCode(name, dns.rcode.NXDOMAIN)


class TestDynBlockQPSActionTruncated(DNSDistTest):
    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    # this needs to be greater than maintenanceWaitTime
    _dynBlockDuration = _maintenanceWaitTime + 1
    _config_params = ["_dynBlockQPS", "_dynBlockPeriod", "_dynBlockDuration", "_testServerPort"]
    _config_template = """
    function maintenance()
	    addDynBlocks(exceedQRate(%d, %d), "Exceeded query rate", %d, DNSAction.Truncate)
    end
    setDynBlocksAction(DNSAction.Drop)
    newServer{address="127.0.0.1:%d"}
    """

    def testDynBlocksQRate(self):
        """
        Dyn Blocks: QRate truncated (action)
        """
        name = "qrateactiontruncated.dynblocks.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist sets RA = RD for TC responses
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
        response.answer.append(rrset)
        truncatedResponse = dns.message.make_response(query)
        truncatedResponse.flags |= dns.flags.TC

        allowed = 0
        sent = 0
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(receivedResponse, response)
                allowed = allowed + 1
            else:
                self.assertEqual(receivedResponse, truncatedResponse)
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()

        # we might be already truncated, but we should have been able to send
        # at least self._dynBlockQPS queries
        self.assertGreaterEqual(allowed, self._dynBlockQPS)

        if allowed == sent:
            waitForMaintenanceToRun()

        # we should now be 'truncated' for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, truncatedResponse)

        # check over TCP, which should not be truncated
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)

        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        allowed = 0
        sent = 0
        # again, over TCP this time, we should never get truncated!
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            sent = sent + 1
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)
            receivedQuery.id = query.id
            allowed = allowed + 1

        self.assertEqual(allowed, sent)


class TestDynBlockAllowlist(DynBlocksTest):
    _config_template = """
    allowlisted = false
    function maintenance()
        toBlock = exceedQRate(%d, %d)
        for addr, count in pairs(toBlock) do
            if tostring(addr) == "127.0.0.1" then
                allowlisted = true
                toBlock[addr] = nil
            end
        end
        addDynBlocks(toBlock, "Exceeded query rate", %d)
    end

    function spoofrule(dq)
        if (allowlisted)
        then
                return DNSAction.Spoof, "192.0.2.42"
        else
                return DNSAction.None, ""
        end
    end
    addAction("allowlisted-test.dynblocks.tests.powerdns.com.", LuaAction(spoofrule))

    newServer{address="127.0.0.1:%d"}
    """

    def testAllowlisted(self):
        """
        Dyn Blocks: Allowlisted from the dynamic blocks
        """
        name = "allowlisted.dynblocks.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
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

        # check that we would have been blocked without the allowlisting
        name = "allowlisted-test.dynblocks.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.42")
        expectedResponse.answer.append(rrset)
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)
