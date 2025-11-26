#!/usr/bin/env python
import base64
import time
import dns
from dnsdisttests import DNSDistTest


class TestCacheHitResponses(DNSDistTest):
    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    addCacheHitResponseAction(SuffixMatchNodeRule("dropwhencached.cachehitresponses.tests.powerdns.com."), DropResponseAction())
    newServer{address="127.0.0.1:%d"}
    """

    def testDroppedWhenCached(self):
        """
        CacheHitResponse: Drop when served from the cache
        """
        ttl = 5
        name = "dropwhencached.cachehitresponses.tests.powerdns.com."
        query = dns.message.make_query(name, "AAAA", "IN")
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, "::1")
        response.answer.append(rrset)

        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

        # now the result should be cached, and so dropped
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        print(receivedResponse)
        self.assertEqual(receivedResponse, None)

        time.sleep(ttl + 1)

        # should not be cached anymore and so valid
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]
            TestCacheHitResponses._responsesCounter[key] = 0

        self.assertEqual(total, 2)

        # TCP should not be cached
        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

        # now the result should be cached, and so dropped
        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)

        time.sleep(ttl + 1)

        # should not be cached anymore and so valid
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]
            TestCacheHitResponses._responsesCounter[key] = 0

        self.assertEqual(total, 2)


class TestStaleCacheHitResponses(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")
    _config_params = ["_consoleKeyB64", "_consolePort", "_testServerPort"]
    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    setStaleCacheEntriesTTL(600)
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}
    function hitCache(dr) if dr:getStaleCacheHit() then return DNSResponseAction.Drop end return DNSResponseAction.None end
    addCacheHitResponseAction(SuffixMatchNodeRule("dropstaleentry.cachehitresponses.tests.powerdns.com."), LuaResponseAction(hitCache))
    """

    def testDroppedWhenStaleCached(self):
        """
        CacheHitResponse: Drop when served from the stale cache entry
        """
        ttl = 5
        name = "dropstaleentry.cachehitresponses.tests.powerdns.com."
        query = dns.message.make_query(name, "AAAA", "IN")
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, "::1")
        response.answer.append(rrset)

        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

        # mark server down
        self.sendConsoleCommand("getServer(0):setDown()")

        # next query should hit the cache within ttl
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, response)

        time.sleep(ttl + 1)

        # further query should hit stale cache thus dropped
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)
