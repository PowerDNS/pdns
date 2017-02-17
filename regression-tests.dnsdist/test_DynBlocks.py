#!/usr/bin/env python
import time
import dns
from dnsdisttests import DNSDistTest

class TestDynBlockQPS(DNSDistTest):

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
        for _ in xrange((self._dynBlockQPS * self._dynBlockPeriod) + 1):
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
        for _ in xrange((self._dynBlockQPS * self._dynBlockPeriod) + 1):
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

class TestDynBlockQPSRefused(DNSDistTest):

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
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)
        refusedResponse = dns.message.make_response(query)
        refusedResponse.set_rcode(dns.rcode.REFUSED)

        allowed = 0
        sent = 0
        for _ in xrange((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEquals(query, receivedQuery)
                self.assertEquals(receivedResponse, response)
                allowed = allowed + 1
            else:
                self.assertEquals(receivedResponse, refusedResponse)
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()

        # we might be already blocked, but we should have been able to send
        # at least self._dynBlockQPS queries
        self.assertGreaterEqual(allowed, self._dynBlockQPS)

        if allowed == sent:
            # wait for the maintenance function to run
            time.sleep(2)

        # we should now be 'refused' for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, refusedResponse)

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
        for _ in xrange((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEquals(query, receivedQuery)
                self.assertEquals(receivedResponse, response)
                allowed = allowed + 1
            else:
                self.assertEquals(receivedResponse, refusedResponse)
                # the query has not reached the responder,
                # let's clear the response queue
                self.clearToResponderQueue()

        # we might be already blocked, but we should have been able to send
        # at least self._dynBlockQPS queries
        self.assertGreaterEqual(allowed, self._dynBlockQPS)

        if allowed == sent:
            # wait for the maintenance function to run
            time.sleep(2)

        # we should now be 'refused' for up to self._dynBlockDuration + self._dynBlockPeriod
        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, refusedResponse)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

class TestDynBlockServFails(DNSDistTest):

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
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)
        servfailResponse = dns.message.make_response(query)
        servfailResponse.set_rcode(dns.rcode.SERVFAIL)

        # start with normal responses
        for _ in xrange((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

        # wait for the maintenance function to run
        time.sleep(2)

        # we should NOT be dropped!
        (_, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertEquals(receivedResponse, response)

        # now with ServFail!
        sent = 0
        allowed = 0
        for _ in xrange((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, servfailResponse)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEquals(query, receivedQuery)
                self.assertEquals(servfailResponse, receivedResponse)
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
        for _ in xrange((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

        # wait for the maintenance function to run
        time.sleep(2)

        # we should NOT be dropped!
        (_, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertEquals(receivedResponse, response)

        # now with ServFail!
        sent = 0
        allowed = 0
        for _ in xrange((self._dynBlockQPS * self._dynBlockPeriod) + 1):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, servfailResponse)
            sent = sent + 1
            if receivedQuery:
                receivedQuery.id = query.id
                self.assertEquals(query, receivedQuery)
                self.assertEquals(servfailResponse, receivedResponse)
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

class TestDynBlockResponseBytes(DNSDistTest):

    _dynBlockBytesPerSecond = 200
    _dynBlockPeriod = 2
    _dynBlockDuration = 5
    _config_params = ['_dynBlockBytesPerSecond', '_dynBlockPeriod', '_dynBlockDuration', '_testServerPort']
    _config_template = """
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
        for _ in xrange(self._dynBlockBytesPerSecond * 5 / len(response.to_wire())):
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

        # we might be already blocked, but we should have been able to send
        # at least self._dynBlockBytesPerSecond bytes
        self.assertGreaterEqual(allowed, self._dynBlockBytesPerSecond)

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
        for _ in xrange(self._dynBlockBytesPerSecond * 5 / len(response.to_wire())):
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
