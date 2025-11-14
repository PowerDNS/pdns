#!/usr/bin/env python
import time
import requests
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort

_maintenanceWaitTime = 2


def waitForMaintenanceToRun():
    time.sleep(_maintenanceWaitTime)


class DynBlocksTest(DNSDistTest):
    _webTimeout = 2.0
    _webServerPort = pickAvailablePort()
    _webServerBasicAuthPassword = "secret"
    _webServerBasicAuthPasswordHashed = (
        "$scrypt$ln=10,p=1,r=8$6DKLnvUYEeXWh3JNOd3iwg==$kSrhdHaRbZ7R74q3lGBqO1xetgxRxhmWzYJ2Qvfm7JM="
    )
    _webServerAPIKey = "apisecret"
    _webServerAPIKeyHashed = (
        "$scrypt$ln=10,p=1,r=8$9v8JxDfzQVyTpBkTbkUqYg==$bDQzAOHeK1G9UvTPypNhrX48w974ZXbFPtRKS34+aso="
    )
    _dynBlockQPS = 10
    _dynBlockANYQPS = 10
    _dynBlockPeriod = 2
    # this needs to be greater than maintenanceWaitTime
    _dynBlockDuration = _maintenanceWaitTime + 2
    _config_params = ["_dynBlockQPS", "_dynBlockPeriod", "_dynBlockDuration", "_testServerPort"]

    def doTestDynBlockViaAPI(self, ipRange, reason, minSeconds, maxSeconds, minBlocks, maxBlocks, ebpf=False):
        headers = {"x-api-key": self._webServerAPIKey}
        url = "http://127.0.0.1:" + str(self._webServerPort) + "/jsonstat?command=dynblocklist"
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)

        content = r.json()
        self.assertIsNotNone(content)
        self.assertIn(ipRange, content)

        values = content[ipRange]
        for key in ["reason", "seconds", "blocks", "action", "ebpf"]:
            self.assertIn(key, values)

        self.assertEqual(values["reason"], reason)
        self.assertGreaterEqual(values["seconds"], minSeconds)
        self.assertLessEqual(values["seconds"], maxSeconds)
        self.assertGreaterEqual(values["blocks"], minBlocks)
        self.assertLessEqual(values["blocks"], maxBlocks)
        self.assertEqual(values["ebpf"], True if ebpf else False)

    def doTestQRate(self, name, testViaAPI=True, ebpf=False):
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

        # we might be already blocked, but we should have been able to send
        # at least self._dynBlockQPS queries
        self.assertGreaterEqual(allowed, self._dynBlockQPS)

        if allowed == sent:
            waitForMaintenanceToRun()

        # we should now be dropped for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=0.5)
        self.assertEqual(receivedResponse, None)

        if testViaAPI:
            self.doTestDynBlockViaAPI(
                "127.0.0.1/32",
                "Exceeded query rate",
                1,
                self._dynBlockDuration,
                (sent - allowed) + 1,
                (sent - allowed) + 1,
                ebpf,
            )

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # again, over TCP this time
        allowed = 0
        sent = 0
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
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
        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False, timeout=0.5)
        self.assertEqual(receivedResponse, None)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

    def doTestQTypeRate(self, name):
        query = dns.message.make_query(name, "ANY", "IN")
        response = dns.message.make_response(query)
        blockedResponse = dns.message.make_response(query)
        blockedResponse.set_rcode(dns.rcode.REFUSED)

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
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=0.5)
        self.assertEqual(receivedResponse, blockedResponse)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

    def doTestQRateRCode(self, name, rcode):
        query = dns.message.make_query(name, "A", "IN")
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(rcode)

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
                self.assertEqual(receivedResponse, expectedResponse)
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()

        # we might be already blocked, but we should have been able to send
        # at least self._dynBlockQPS queries
        self.assertGreaterEqual(allowed, self._dynBlockQPS)

        if allowed == sent:
            waitForMaintenanceToRun()

        # we should now be 'rcode' for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        allowed = 0
        sent = 0
        # again, over TCP this time
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(receivedResponse, response)
                allowed = allowed + 1
            else:
                self.assertEqual(receivedResponse, expectedResponse)
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()

        # we might be already blocked, but we should have been able to send
        # at least self._dynBlockQPS queries
        self.assertGreaterEqual(allowed, self._dynBlockQPS)

        if allowed == sent:
            waitForMaintenanceToRun()

        # we should now be 'rcode' for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

    def doTestResponseByteRate(self, name, dynBlockBytesPerSecond):
        query = dns.message.make_query(name, "A", "IN")
        response = dns.message.make_response(query)
        response.answer.append(
            dns.rrset.from_text_list(
                name, 60, dns.rdataclass.IN, dns.rdatatype.A, ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"]
            )
        )
        response.answer.append(dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.AAAA, "2001:DB8::1"))

        allowed = 0
        sent = 0

        print(time.time())

        for _ in range(int(dynBlockBytesPerSecond * 5 / len(response.to_wire()))):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            sent = sent + len(response.to_wire())
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(response, receivedResponse)
                allowed = allowed + len(response.to_wire())
            else:
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()
                # and stop right there, otherwise we might
                # wait for so long that the dynblock is gone
                # by the time we finished
                break

        # we might be already blocked, but we should have been able to send
        # at least dynBlockBytesPerSecond bytes
        print(allowed)
        print(sent)
        print(time.time())
        self.assertGreaterEqual(allowed, dynBlockBytesPerSecond)

        print(self.sendConsoleCommand("showDynBlocks()"))
        print(self.sendConsoleCommand('grepq("")'))
        print(time.time())

        if allowed == sent:
            print("Waiting for the maintenance function to run")
            waitForMaintenanceToRun()

        print(self.sendConsoleCommand("showDynBlocks()"))
        print(self.sendConsoleCommand('grepq("")'))
        print(time.time())

        # we should now be dropped for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=1)
        self.assertEqual(receivedResponse, None)

        print(self.sendConsoleCommand("showDynBlocks()"))
        print(self.sendConsoleCommand('grepq("")'))
        print(time.time())

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        print(self.sendConsoleCommand("showDynBlocks()"))
        print(self.sendConsoleCommand('grepq("")'))
        print(time.time())

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # again, over TCP this time
        allowed = 0
        sent = 0
        for _ in range(int(dynBlockBytesPerSecond * 5 / len(response.to_wire()))):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response, timeout=0.5)
            sent = sent + len(response.to_wire())
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(response, receivedResponse)
                allowed = allowed + len(response.to_wire())
            else:
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()
                # and stop right there, otherwise we might
                # wait for so long that the dynblock is gone
                # by the time we finished
                break

        # we might be already blocked, but we should have been able to send
        # at least dynBlockBytesPerSecond bytes
        self.assertGreaterEqual(allowed, dynBlockBytesPerSecond)

        if allowed == sent:
            waitForMaintenanceToRun()

        # we should now be dropped for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

    def doTestRCodeRate(self, name, rcode):
        query = dns.message.make_query(name, "A", "IN")
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(rcode)

        # start with normal responses
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        waitForMaintenanceToRun()

        # we should NOT be dropped!
        (_, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertEqual(receivedResponse, response)

        # now with rcode!
        sent = 0
        allowed = 0
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, expectedResponse)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(expectedResponse, receivedResponse)
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
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=1)
        self.assertEqual(receivedResponse, None)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # again, over TCP this time
        # start with normal responses
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        waitForMaintenanceToRun()

        # we should NOT be dropped!
        (_, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertEqual(receivedResponse, response)

        # now with rcode!
        sent = 0
        allowed = 0
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, expectedResponse)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(expectedResponse, receivedResponse)
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
        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False, timeout=0.5)
        self.assertEqual(receivedResponse, None)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

    def doTestRCodeRatio(self, name, rcode, noerrorcount, rcodecount):
        query = dns.message.make_query(name, "A", "IN")
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(rcode)

        # start with normal responses
        for _ in range(noerrorcount - 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        waitForMaintenanceToRun()

        # we should NOT be dropped!
        (_, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertEqual(receivedResponse, response)

        # now with rcode!
        sent = 0
        allowed = 0
        for _ in range(rcodecount):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, expectedResponse)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(expectedResponse, receivedResponse)
                allowed = allowed + 1
            else:
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()

        # we should have been able to send all our queries since the minimum number of queries is set to noerrorcount + rcodecount
        self.assertGreaterEqual(allowed, rcodecount)

        waitForMaintenanceToRun()

        # we should now be dropped for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=1)
        self.assertEqual(receivedResponse, None)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # again, over TCP this time
        # start with normal responses
        for _ in range(noerrorcount - 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        waitForMaintenanceToRun()

        # we should NOT be dropped!
        (_, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertEqual(receivedResponse, response)

        # now with rcode!
        sent = 0
        allowed = 0
        for _ in range(rcodecount):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, expectedResponse)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(expectedResponse, receivedResponse)
                allowed = allowed + 1
            else:
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()

        # we should have been able to send all our queries since the minimum number of queries is set to noerrorcount + rcodecount
        self.assertGreaterEqual(allowed, rcodecount)

        waitForMaintenanceToRun()

        # we should now be dropped for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False, timeout=0.5)
        self.assertEqual(receivedResponse, None)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

    def doTestCacheMissRatio(self, name, cacheHits, cacheMisses):
        rrset = dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")

        for idx in range(cacheMisses):
            query = dns.message.make_query(str(idx) + "." + name, "A", "IN")
            response = dns.message.make_response(query)
            response.answer.append(rrset)
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(response, receivedResponse)
            else:
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()

        query = dns.message.make_query("0." + name, "A", "IN")
        response = dns.message.make_response(query)
        response.answer.append(rrset)
        for _ in range(cacheHits):
            (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)

        waitForMaintenanceToRun()

        # we should now be dropped for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=0.5)
        self.assertEqual(receivedResponse, None)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        query = dns.message.make_query(str(cacheMisses + 1) + name, "A", "IN")
        response = dns.message.make_response(query)
        response.answer.append(rrset)
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
