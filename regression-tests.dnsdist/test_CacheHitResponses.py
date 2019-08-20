#!/usr/bin/env python
import base64
import time
import dns
from dnsdisttests import DNSDistTest

class TestCacheHitResponses(DNSDistTest):

    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    addCacheHitResponseAction(makeRule("dropwhencached.cachehitresponses.tests.powerdns.com."), DropResponseAction())
    newServer{address="127.0.0.1:%s"}
    """

    def testDroppedWhenCached(self):
        """
        CacheHitResponse: Drop when served from the cache
        """
        ttl = 5
        name = 'dropwhencached.cachehitresponses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        # now the result should be cached, and so dropped
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        print(receivedResponse)
        self.assertEquals(receivedResponse, None)

        time.sleep(ttl + 1)

        # should not be cached anymore and so valid
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]
            TestCacheHitResponses._responsesCounter[key] = 0

        self.assertEquals(total, 2)

        # TCP should not be cached
        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        # now the result should be cached, and so dropped
        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, None)

        time.sleep(ttl + 1)

        # should not be cached anymore and so valid
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]
            TestCacheHitResponses._responsesCounter[key] = 0

        self.assertEquals(total, 2)
