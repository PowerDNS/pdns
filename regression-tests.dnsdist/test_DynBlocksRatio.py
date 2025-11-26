#!/usr/bin/env python
import time
import dns
from dnsdistDynBlockTests import DynBlocksTest, waitForMaintenanceToRun


class TestDynBlockGroupServFailsRatio(DynBlocksTest):
    # we need this period to be quite long because we request the valid
    # queries to be still looked at to reach the 20 queries count!
    _dynBlockPeriod = 6
    _config_params = ["_dynBlockPeriod", "_dynBlockDuration", "_testServerPort"]
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setRCodeRatio(DNSRCode.SERVFAIL, 0.2, %d, "Exceeded query rate", %d, 20)

    function maintenance()
	    dbr:apply()
    end

    newServer{address="127.0.0.1:%d"}
    """

    def testDynBlocksServFailRatio(self):
        """
        Dyn Blocks (group): Server Failure Ratio
        """
        name = "servfailratio.group.dynblocks.tests.powerdns.com."
        self.doTestRCodeRatio(name, dns.rcode.SERVFAIL, 10, 10)


class TestDynBlockGroupCacheMissRatio(DynBlocksTest):
    # we need this period to be quite long because we request the valid
    # queries to be still looked at to reach the 20 queries count!
    _dynBlockPeriod = 6
    _config_params = ["_dynBlockPeriod", "_dynBlockDuration", "_testServerPort"]
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setCacheMissRatio(0.8, %d, "Exceeded cache miss ratio", %d, 20, 0.0)

    function maintenance()
	    dbr:apply()
    end

    newServer{address="127.0.0.1:%d"}
    local pc = newPacketCache(1000, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    """

    def testDynBlocksCacheMissRatio(self):
        """
        Dyn Blocks (group): Cache miss ratio
        """
        name = "cachemissratio.group.dynblocks.tests.powerdns.com."
        self.doTestCacheMissRatio(name, 3, 17)


class TestDynBlockGroupCacheMissRatioSetTag(DynBlocksTest):
    # we need this period to be quite long because we request the valid
    # queries to be still looked at to reach the 20 queries count!
    _dynBlockPeriod = 6
    _config_params = ["_dynBlockPeriod", "_dynBlockDuration", "_testServerPort"]
    _config_template = """
    local dbr = dynBlockRulesGroup()
    dbr:setCacheMissRatio(0.8, %d, "Exceeded cache miss ratio", %d, 20, 0.0, DNSAction.SetTag, 0.0, { tagName='dyn-miss-ratio', tagValue='hit' })

    -- check that the tag is set and query rules executed
    addAction(AndRule{QNameRule("test-query-rules.cachemissratio-settag.group.dynblocks.tests.powerdns.com."), TagRule('dyn-miss-ratio', 'hit')}, SpoofAction("192.0.2.2"))

    -- on a cache miss, and if the cache miss ratio threshold was exceeded, send a REFUSED response
    addCacheMissAction(TagRule('dyn-miss-ratio', 'hit'), RCodeAction(DNSRCode.REFUSED))

    function maintenance()
	    dbr:apply()
    end

    newServer{address="127.0.0.1:%d"}
    local pc = newPacketCache(1000, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    """

    def testDynBlocksCacheMissRatio(self):
        """
        Dyn Blocks (group): Cache miss ratio with SetTag
        """
        name = "cachemissratio-settag.group.dynblocks.tests.powerdns.com."
        rrset = dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")

        cacheHits = 3
        cacheMisses = 17
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

        # we should now get REFUSED for cache misses for up to self._dynBlockDuration + self._dynBlockPeriod

        # cache miss
        query = dns.message.make_query(str(cacheMisses + 1) + "." + name, "A", "IN")
        # dnsdist sets RA = RD for TC responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=0.5)
        self.assertEqual(receivedResponse, expectedResponse)

        # but a cache hit should be OK
        query = dns.message.make_query("0." + name, "A", "IN")
        expectedResponse = dns.message.make_response(query)
        expectedResponse.answer.append(rrset)
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=0.5)
        self.assertEqual(receivedResponse, expectedResponse)

        # this specific query will match the query rules before triggering a cache miss
        # so we can check that the tag is correctly set for query rules as well
        query = dns.message.make_query("test-query-rules." + name, "A", "IN")
        # dnsdist sets RA = RD for TC responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        queryRulesRRset = dns.rrset.from_text(
            "test-query-rules." + name, 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.2"
        )
        expectedResponse.answer.append(queryRulesRRset)
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=0.5)
        self.assertEqual(receivedResponse, expectedResponse)

        # wait until we are not blocked anymore
        time.sleep(self._dynBlockDuration + self._dynBlockPeriod)

        # this one should succeed
        query = dns.message.make_query(str(cacheMisses + 2) + "." + name, "A", "IN")
        response = dns.message.make_response(query)
        response.answer.append(rrset)
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
