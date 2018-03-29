#!/usr/bin/env python
import base64
import time
import dns
from dnsdisttests import DNSDistTest, range

class DynBlocksTest(DNSDistTest):

    def doTestQRate(self, name):
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
                self.assertEquals(query, receivedQuery)
                self.assertEquals(response, receivedResponse)
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
        self.assertEquals(receivedResponse, None)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        # again, over TCP this time
        allowed = 0
        sent = 0
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEquals(query, receivedQuery)
                self.assertEquals(response, receivedResponse)
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
        self.assertEquals(receivedResponse, None)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

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
                self.assertEquals(query, receivedQuery)
                self.assertEquals(receivedResponse, response)
                allowed = allowed + 1
            else:
                self.assertEquals(receivedResponse, expectedResponse)
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
        self.assertEquals(receivedResponse, expectedResponse)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        allowed = 0
        sent = 0
        # again, over TCP this time
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEquals(query, receivedQuery)
                self.assertEquals(receivedResponse, response)
                allowed = allowed + 1
            else:
                self.assertEquals(receivedResponse, expectedResponse)
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
        self.assertEquals(receivedResponse, expectedResponse)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

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
                self.assertEquals(query, receivedQuery)
                self.assertEquals(response, receivedResponse)
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
        self.assertEquals(receivedResponse, None)

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
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        # again, over TCP this time
        allowed = 0
        sent = 0
        for _ in range(int(self._dynBlockBytesPerSecond * 5 / len(response.to_wire()))):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            sent = sent + len(response.to_wire())
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEquals(query, receivedQuery)
                self.assertEquals(response, receivedResponse)
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
        self.assertEquals(receivedResponse, None)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

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
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

        # wait for the maintenance function to run
        time.sleep(2)

        # we should NOT be dropped!
        (_, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertEquals(receivedResponse, response)

        # now with rcode!
        sent = 0
        allowed = 0
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, expectedResponse)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEquals(query, receivedQuery)
                self.assertEquals(expectedResponse, receivedResponse)
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
        self.assertEquals(receivedResponse, None)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        # again, over TCP this time
        # start with normal responses
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

        # wait for the maintenance function to run
        time.sleep(2)

        # we should NOT be dropped!
        (_, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertEquals(receivedResponse, response)

        # now with rcode!
        sent = 0
        allowed = 0
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, expectedResponse)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEquals(query, receivedQuery)
                self.assertEquals(expectedResponse, receivedResponse)
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
        self.assertEquals(receivedResponse, None)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

class TestDynBlockQPS(DynBlocksTest):

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    function maintenance()
	    addDynBlocks(exceedQRate(%d, %d), "Exceeded query rate", %d)
    end
    newServer{address="127.0.0.1:%s"}
    """

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
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setQueryRate(%d, %d, "Exceeded query rate", %d)

    function maintenance()
	    dbr:apply()
    end
    newServer{address="127.0.0.1:%s"}
    """

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

class TestDynBlockQPSActionRefused(DynBlocksTest):

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
                self.assertEquals(query, receivedQuery)
                self.assertEquals(receivedResponse, response)
                allowed = allowed + 1
            else:
                self.assertEquals(receivedResponse, truncatedResponse)
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
        self.assertEquals(receivedResponse, truncatedResponse)

        # check over TCP, which should not be truncated
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)

        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        allowed = 0
        sent = 0
        # again, over TCP this time, we should never get truncated!
        for _ in range((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            sent = sent + 1
            self.assertEquals(query, receivedQuery)
            self.assertEquals(receivedResponse, response)
            receivedQuery.id = query.id
            allowed = allowed + 1

        self.assertEquals(allowed, sent)

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

class TestDynBlockGroupServFails(DynBlocksTest):

    _dynBlockQPS = 10
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _config_params = ['_dynBlockQPS', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setRCodeRate(dnsdist.SERVFAIL, %d, %d, "Exceeded query rate", %d)

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
