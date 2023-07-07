#!/usr/bin/env python
import base64
import json
import requests
import socket
import time
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort
try:
  range = xrange
except NameError:
  pass

class DynBlocksTest(DNSDistTest):

    _webTimeout = 2.0
    _webServerPort = pickAvailablePort()
    _webServerBasicAuthPassword = 'secret'
    _webServerBasicAuthPasswordHashed = '$scrypt$ln=10,p=1,r=8$6DKLnvUYEeXWh3JNOd3iwg==$kSrhdHaRbZ7R74q3lGBqO1xetgxRxhmWzYJ2Qvfm7JM='
    _webServerAPIKey = 'apisecret'
    _webServerAPIKeyHashed = '$scrypt$ln=10,p=1,r=8$9v8JxDfzQVyTpBkTbkUqYg==$bDQzAOHeK1G9UvTPypNhrX48w974ZXbFPtRKS34+aso='

    def doTestDynBlockViaAPI(self, range, reason, minSeconds, maxSeconds, minBlocks, maxBlocks):
        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/jsonstat?command=dynblocklist'
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)

        content = r.json()
        self.assertIsNotNone(content)
        self.assertIn(range, content)

        values = content[range]
        for key in ['reason', 'seconds', 'blocks', 'action']:
            self.assertIn(key, values)

        self.assertEqual(values['reason'], reason)
        self.assertGreaterEqual(values['seconds'], minSeconds)
        self.assertLessEqual(values['seconds'], maxSeconds)
        self.assertGreaterEqual(values['blocks'], minBlocks)
        self.assertLessEqual(values['blocks'], maxBlocks)

    def doTestQRate(self, name, testViaAPI=True):
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
            # wait for the maintenance function to run
            time.sleep(2)

        # we should now be dropped for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)

        if testViaAPI:
            self.doTestDynBlockViaAPI('127.0.0.1/32', 'Exceeded query rate', self._dynBlockDuration - 4, self._dynBlockDuration, (sent-allowed)+1, (sent-allowed)+1)

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
            # wait for the maintenance function to run
            time.sleep(2)

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

    def doTestQRateRCode(self, name, rcode):
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
            # wait for the maintenance function to run
            time.sleep(2)

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
            # wait for the maintenance function to run
            time.sleep(2)

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

    def doTestResponseByteRate(self, name):
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text_list(name,
                                                       60,
                                                       dns.rdataclass.IN,
                                                       dns.rdatatype.A,
                                                       ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4']))
        response.answer.append(dns.rrset.from_text(name,
                                                   60,
                                                   dns.rdataclass.IN,
                                                   dns.rdatatype.AAAA,
                                                   '2001:DB8::1'))

        allowed = 0
        sent = 0

        print(time.time())

        for _ in range(int(self._dynBlockBytesPerSecond * 5 / len(response.to_wire()))):
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
        # at least self._dynBlockBytesPerSecond bytes
        print(allowed)
        print(sent)
        print(time.time())
        self.assertGreaterEqual(allowed, self._dynBlockBytesPerSecond)

        print(self.sendConsoleCommand("showDynBlocks()"))
        print(self.sendConsoleCommand("grepq(\"\")"))
        print(time.time())

        if allowed == sent:
            # wait for the maintenance function to run
            print("Waiting for the maintenance function to run")
            time.sleep(2)

        print(self.sendConsoleCommand("showDynBlocks()"))
        print(self.sendConsoleCommand("grepq(\"\")"))
        print(time.time())

        # we should now be dropped for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)

        print(self.sendConsoleCommand("showDynBlocks()"))
        print(self.sendConsoleCommand("grepq(\"\")"))
        print(time.time())

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        print(self.sendConsoleCommand("showDynBlocks()"))
        print(self.sendConsoleCommand("grepq(\"\")"))
        print(time.time())

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # again, over TCP this time
        allowed = 0
        sent = 0
        for _ in range(int(self._dynBlockBytesPerSecond * 5 / len(response.to_wire()))):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
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
        # at least self._dynBlockBytesPerSecond bytes
        self.assertGreaterEqual(allowed, self._dynBlockBytesPerSecond)

        if allowed == sent:
            # wait for the maintenance function to run
            time.sleep(2)

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

        # start with normal responses
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        # wait for the maintenance function to run
        time.sleep(2)

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
            # wait for the maintenance function to run
            time.sleep(2)

        # we should now be dropped for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
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

        # wait for the maintenance function to run
        time.sleep(2)

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
        # wait for the maintenance function to run
            time.sleep(2)

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

    def doTestRCodeRatio(self, name, rcode, noerrorcount, rcodecount):
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

        # start with normal responses
        for _ in range(noerrorcount-1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        # wait for the maintenance function to run
        time.sleep(2)

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

        # wait for the maintenance function to run
        time.sleep(2)

        # we should now be dropped for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
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
        for _ in range(noerrorcount-1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        # wait for the maintenance function to run
        time.sleep(2)

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

        # wait for the maintenance function to run
        time.sleep(2)

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

class TestDynBlockQPS(DynBlocksTest):

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _config_template = """
    function maintenance()
	    addDynBlocks(exceedQRate(%d, %d), "Exceeded query rate", %d)
    end
    newServer{address="127.0.0.1:%s"}
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    """
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']

    def testDynBlocksQRate(self):
        """
        Dyn Blocks: QRate
        """
        name = 'qrate.dynblocks.tests.powerdns.com.'
        self.doTestQRate(name)

class TestDynBlockGroupQPS(DynBlocksTest):

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
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


class TestDynBlockQPSRefused(DynBlocksTest):

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    function maintenance()
	    addDynBlocks(exceedQRate(%d, %d), "Exceeded query rate", %d)
    end
    setDynBlocksAction(DNSAction.Refused)
    newServer{address="127.0.0.1:%s"}
    """

    def testDynBlocksQRate(self):
        """
        Dyn Blocks: QRate refused
        """
        name = 'qraterefused.dynblocks.tests.powerdns.com.'
        self.doTestQRateRCode(name, dns.rcode.REFUSED)

class TestDynBlockGroupQPSRefused(DynBlocksTest):

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
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

class TestDynBlockQPSActionRefused(DynBlocksTest):

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    function maintenance()
	    addDynBlocks(exceedQRate(%d, %d), "Exceeded query rate", %d, DNSAction.Refused)
    end
    setDynBlocksAction(DNSAction.Drop)
    newServer{address="127.0.0.1:%s"}
    """

    def testDynBlocksQRate(self):
        """
        Dyn Blocks: QRate refused (action)
        """
        name = 'qrateactionrefused.dynblocks.tests.powerdns.com.'
        self.doTestQRateRCode(name, dns.rcode.REFUSED)

class TestDynBlockQPSActionNXD(DynBlocksTest):

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    function maintenance()
	    addDynBlocks(exceedQRate(%d, %d), "Exceeded query rate", %d, DNSAction.Nxdomain)
    end
    setDynBlocksAction(DNSAction.Drop)
    newServer{address="127.0.0.1:%s"}
    """

    def testDynBlocksQRate(self):
        """
        Dyn Blocks: QRate NXD (action)
        """
        name = 'qrateactionnxd.dynblocks.tests.powerdns.com.'
        self.doTestQRateRCode(name, dns.rcode.NXDOMAIN)

class TestDynBlockGroupQPSActionRefused(DynBlocksTest):

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
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

class TestDynBlockQPSActionTruncated(DNSDistTest):

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    function maintenance()
	    addDynBlocks(exceedQRate(%d, %d), "Exceeded query rate", %d, DNSAction.Truncate)
    end
    setDynBlocksAction(DNSAction.Drop)
    newServer{address="127.0.0.1:%s"}
    """

    def testDynBlocksQRate(self):
        """
        Dyn Blocks: QRate truncated (action)
        """
        name = 'qrateactiontruncated.dynblocks.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist sets RA = RD for TC responses
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
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
            # wait for the maintenance function to run
            time.sleep(2)

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

class TestDynBlockServFails(DynBlocksTest):

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
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

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
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

            # fill the cache
            (receivedQuery, receivedResponse) = sender(query, expectedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(expectedResponse, receivedResponse)

            # wait for the maintenance function to run
            time.sleep(2)

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
                # wait for the maintenance function to run
                time.sleep(2)

            # we should now be dropped for up to self._dynBlockDuration + self._dynBlockPeriod
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, None)

            # wait until we are not blocked anymore
            time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

            # this one should succeed
            (receivedQuery, receivedResponse) = sender(query, response=None)
            self.assertEqual(expectedResponse, receivedResponse)

class TestDynBlockAllowlist(DynBlocksTest):

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
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

    newServer{address="127.0.0.1:%s"}
    """

    def testAllowlisted(self):
        """
        Dyn Blocks: Allowlisted from the dynamic blocks
        """
        name = 'allowlisted.dynblocks.tests.powerdns.com.'
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

        # wait for the maintenance function to run
        time.sleep(2)

        # we should still not be blocked
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, receivedResponse)

        # check that we would have been blocked without the allowlisting
        name = 'allowlisted-test.dynblocks.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.42')
        expectedResponse.answer.append(rrset)
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)

class TestDynBlockGroupServFails(DynBlocksTest):

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
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

class TestDynBlockGroupServFailsRatio(DynBlocksTest):

    # we need this period to be quite long because we request the valid
    # queries to be still looked at to reach the 20 queries count!
    _dynBlockPeriod = 6
    _dynBlockDuration = 5
    _config_params = ['_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setRCodeRatio(DNSRCode.SERVFAIL, 0.2, %d, "Exceeded query rate", %d, 20)

    function maintenance()
	    dbr:apply()
    end

    newServer{address="127.0.0.1:%s"}
    """

    def testDynBlocksServFailRatio(self):
        """
        Dyn Blocks (group): Server Failure Ratio
        """
        name = 'servfailratio.group.dynblocks.tests.powerdns.com.'
        self.doTestRCodeRatio(name, dns.rcode.SERVFAIL, 10, 10)

class TestDynBlockResponseBytes(DynBlocksTest):

    _dynBlockBytesPerSecond = 200
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_dynBlockBytesPerSecond', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")
    function maintenance()
	    addDynBlocks(exceedRespByterate(%d, %d), "Exceeded response byterate", %d)
    end
    newServer{address="127.0.0.1:%s"}
    """

    def testDynBlocksResponseByteRate(self):
        """
        Dyn Blocks: Response Byte Rate
        """
        name = 'responsebyterate.dynblocks.tests.powerdns.com.'
        self.doTestResponseByteRate(name)

class TestDynBlockGroupResponseBytes(DynBlocksTest):

    _dynBlockBytesPerSecond = 200
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_dynBlockBytesPerSecond', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")
    local dbr = dynBlockRulesGroup()
    dbr:setResponseByteRate(%d, %d, "Exceeded query rate", %d)

    function maintenance()
	    dbr:apply()
    end

    newServer{address="127.0.0.1:%s"}
    """

    def testDynBlocksResponseByteRate(self):
        """
        Dyn Blocks (group) : Response Byte Rate
        """
        name = 'responsebyterate.group.dynblocks.tests.powerdns.com.'
        self.doTestResponseByteRate(name)

class TestDynBlockGroupExcluded(DynBlocksTest):

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
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

        # wait for the maintenance function to run
        time.sleep(2)

        # we should still not be blocked
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, receivedResponse)

class TestDynBlockGroupExcludedViaNMG(DynBlocksTest):

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
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

        # wait for the maintenance function to run
        time.sleep(2)

        # we should still not be blocked
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, receivedResponse)

class TestDynBlockGroupNoOp(DynBlocksTest):

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
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

        # wait for the maintenance function to run
        time.sleep(2)

        # the rule should still be present, but the queries pass through anyway
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, receivedResponse)

        # check that the rule has been inserted
        self.doTestDynBlockViaAPI('127.0.0.1/32', 'Exceeded query rate', self._dynBlockDuration - 4, self._dynBlockDuration, 0, sent)

class TestDynBlockGroupWarning(DynBlocksTest):

    _dynBlockWarningQPS = 5
    _dynBlockQPS = 20
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
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

        # wait for the maintenance function to run
        time.sleep(2)

        # the rule should still be present, but the queries pass through anyway
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, receivedResponse)

        # check that the rule has been inserted
        self.doTestDynBlockViaAPI('127.0.0.1/32', 'Exceeded query rate', self._dynBlockDuration - 4, self._dynBlockDuration, 0, sent)

        self.doTestQRate(name)

class TestDynBlockGroupPort(DNSDistTest):

    _dynBlockQPS = 20
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
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
            # wait for the maintenance function to run
            time.sleep(2)

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
