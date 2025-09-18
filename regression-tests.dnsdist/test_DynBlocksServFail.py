#!/usr/bin/env python
import base64
import socket
import time
import dns
from dnsdisttests import DNSDistTest
from dnsdistDynBlockTests import DynBlocksTest, waitForMaintenanceToRun, _maintenanceWaitTime

class TestDynBlockServFails(DynBlocksTest):

    _config_template = """
    function maintenance()
	    addDynBlocks(exceedServFails(%d, %d), "Exceeded servfail rate", %d)
    end
    newServer{address="127.0.0.1:%s"}
    """

    def testDynBlocksServFailRate(self):
        """
        Dyn Blocks: Server Failure Rate
        """
        name = 'servfailrate.dynblocks.tests.powerdns.com.'
        self.doTestRCodeRate(name, dns.rcode.SERVFAIL)

class TestDynBlockServFailsCached(DynBlocksTest):

    _config_template = """
    pc = newPacketCache(10000, {maxTTL=86400, minTTL=0, temporaryFailureTTL=60, staleTTL=60, dontAge=false})
    getPool(""):setCache(pc)
    function maintenance()
	    addDynBlocks(exceedServFails(%d, %d), "Exceeded servfail rate", %d)
    end
    newServer{address="127.0.0.1:%s"}
    """

    def testDynBlocksServFailRateCached(self):
        """
        Dyn Blocks: Make sure cache hit responses also gets inserted into rings
        """
        name = 'servfailrate.dynblocks.tests.powerdns.com.'
        rcode = dns.rcode.SERVFAIL
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(rcode)


        for method in ("sendUDPQuery", "sendTCPQuery"):
            print(method, "()")
            sender = getattr(self, method)

            if method == 'sendUDPQuery':
                # fill the cache
                (receivedQuery, receivedResponse) = sender(query, expectedResponse)
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(expectedResponse, receivedResponse)

                waitForMaintenanceToRun()

            # we should NOT be dropped!
            (_, receivedResponse) = sender(query, response=None)
            self.assertEqual(receivedResponse, expectedResponse)

            # now with rcode!
            sent = 0
            allowed = 0
            for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
                (_, receivedResponse) = sender(query, expectedResponse)
                sent = sent + 1
                self.assertEqual(expectedResponse, receivedResponse)
                allowed = allowed + 1
            # we might be already blocked, but we should have been able to send
            # at least self._dynBlockQPS queries
            self.assertGreaterEqual(allowed, self._dynBlockQPS)

            if allowed == sent:
                waitForMaintenanceToRun()

            # we should now be dropped for up to self._dynBlockDuration + self._dynBlockPeriod
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, None)

            # wait until we are not blocked anymore
            time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

            # this one should succeed
            (receivedQuery, receivedResponse) = sender(query, response=None)
            self.assertEqual(expectedResponse, receivedResponse)

class TestDynBlockGroupServFails(DynBlocksTest):

    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setRCodeRate(DNSRCode.SERVFAIL, %d, %d, "Exceeded query rate", %d)

    function maintenance()
	    dbr:apply()
    end

    newServer{address="127.0.0.1:%s"}
    """

    def testDynBlocksServFailRate(self):
        """
        Dyn Blocks (group): Server Failure Rate
        """
        name = 'servfailrate.group.dynblocks.tests.powerdns.com.'
        self.doTestRCodeRate(name, dns.rcode.SERVFAIL)

class TestDynBlockGroupServFailsYAML(DynBlocksTest):

    _yaml_config_template = """---
dynamic_rules:
  - name: "Block client generating too many ServFails"
    mask_ipv4: 24
    mask_ipv6: 128
    exclude_ranges:
      - "192.0.2.1/32"
      - "192.0.2.2/32"
    include_ranges:
      - "127.0.0.0/24"
    exclude_domains:
      - "unused."
    rules:
      - type: "rcode-rate"
        rate: %d
        seconds: %d
        action_duration: %d
        comment: "Exceeded query rate"
        action: "Drop"
        rcode: "servfail"

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53
"""
    _config_params = []
    _yaml_config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']

    def testDynBlocksServFailRate(self):
        """
        Dyn Blocks (group / YAML): Server Failure Rate
        """
        name = 'servfailrate.group.dynblocks.tests.powerdns.com.'
        self.doTestRCodeRate(name, dns.rcode.SERVFAIL)
