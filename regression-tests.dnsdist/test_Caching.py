#!/usr/bin/env python
import base64
import time
import dns
import clientsubnetoption
from dnsdisttests import DNSDistTest

class TestCaching(DNSDistTest):

    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    addAction(makeRule("nocache.cache.tests.powerdns.com."), SkipCacheAction())
    function skipViaLua(dq)
        dq.skipCache = true
        return DNSAction.None, ""
    end
    addAction("nocachevialua.cache.tests.powerdns.com.", LuaAction(skipViaLua))
    newServer{address="127.0.0.1:%d"}
    """

    def testCached(self):
        """
        Cache: Served from cache

        dnsdist is configured to cache entries, we are sending several
        identical requests and checking that the backend only receive
        the first one.
        """
        numberOfQueries = 10
        name = 'cached.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
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

        for _ in range(numberOfQueries):
            (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, response)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]
            TestCaching._responsesCounter[key] = 0

        self.assertEquals(total, 1)

        # TCP should not be cached
        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        for _ in range(numberOfQueries):
            (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, response)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]
            TestCaching._responsesCounter[key] = 0

        self.assertEquals(total, 1)

    def testDOCached(self):
        """
        Cache: Served from cache, query has DO bit set

        dnsdist is configured to cache entries, we are sending several
        identical requests and checking that the backend only receive
        the first one.
        """
        numberOfQueries = 10
        name = 'cached-do.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN', use_edns=True, payload=4096, want_dnssec=True)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
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

        for _ in range(numberOfQueries):
            (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, response)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]
            TestCaching._responsesCounter[key] = 0

        self.assertEquals(total, 1)

        # TCP should not be cached
        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        for _ in range(numberOfQueries):
            (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, response)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]
            TestCaching._responsesCounter[key] = 0

        self.assertEquals(total, 1)

    def testSkipCache(self):
        """
        Cache: SkipCacheAction

        dnsdist is configured to not cache entries for nocache.cache.tests.powerdns.com.
         we are sending several requests and checking that the backend get them all.
        """
        name = 'nocache.cache.tests.powerdns.com.'
        numberOfQueries = 10
        query = dns.message.make_query(name, 'AAAA', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        for _ in range(numberOfQueries):
            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                (receivedQuery, receivedResponse) = sender(query, response)
                self.assertTrue(receivedQuery)
                self.assertTrue(receivedResponse)
                receivedQuery.id = query.id
                self.assertEquals(query, receivedQuery)
                self.assertEquals(receivedResponse, response)

        for key in self._responsesCounter:
            value = self._responsesCounter[key]
            self.assertEquals(value, numberOfQueries)

    def testSkipCacheViaLua(self):
        """
        Cache: SkipCache via Lua

        dnsdist is configured to not cache entries for nocachevialua.cache.tests.powerdns.com.
         we are sending several requests and checking that the backend get them all.
        """
        name = 'nocachevialua.cache.tests.powerdns.com.'
        numberOfQueries = 10
        query = dns.message.make_query(name, 'AAAA', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        for _ in range(numberOfQueries):
            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                (receivedQuery, receivedResponse) = sender(query, response)
                self.assertTrue(receivedQuery)
                self.assertTrue(receivedResponse)
                receivedQuery.id = query.id
                self.assertEquals(query, receivedQuery)
                self.assertEquals(receivedResponse, response)

        for key in self._responsesCounter:
            value = self._responsesCounter[key]
            self.assertEquals(value, numberOfQueries)

    def testCacheExpiration(self):
        """
        Cache: Cache expiration

        dnsdist is configured to cache entries, we are sending one request
        (cache miss) with a very short TTL, checking that the next requests
        are cached. Then we wait for the TTL to expire, check that the
        next request is a miss but the following one a hit.
        """
        ttl = 2
        misses = 0
        name = 'cacheexpiration.cache.tests.powerdns.com.'
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
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # now we wait a bit for the cache entry to expire
        time.sleep(ttl + 1)

        # next query should be a miss, fill the cache again
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)
        misses += 1

        # following queries should hit the cache again
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

    def testCacheExpirationDifferentSets(self):
        """
        Cache: Cache expiration with different sets

        dnsdist is configured to cache entries, we are sending one request
        (cache miss) whose response has a long and a very short TTL,
        checking that the next requests are cached. Then we wait for the
        short TTL to expire, check that the
        next request is a miss but the following one a hit.
        """
        ttl = 2
        misses = 0
        name = 'cacheexpirationdifferentsets.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'cname.cacheexpirationdifferentsets.cache.tests.powerdns.com.')
        response.answer.append(rrset)
        rrset = dns.rrset.from_text('cname.cacheexpirationdifferentsets.cache.tests.powerdns.com.',
                                    ttl + 3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.2.0.1')
        response.additional.append(rrset)

        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # now we wait a bit for the cache entry to expire
        time.sleep(ttl + 1)

        # next query should be a miss, fill the cache again
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)
        misses += 1

        # following queries should hit the cache again
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

    def testCacheDecreaseTTL(self):
        """
        Cache: Cache decreases TTL

        dnsdist is configured to cache entries, we are sending one request
        (cache miss) and verify that the cache hits have a decreasing TTL.
        """
        ttl = 600
        misses = 0
        name = 'cachedecreasettl.cache.tests.powerdns.com.'
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
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)
        for an in receivedResponse.answer:
            self.assertTrue(an.ttl <= ttl)

        # now we wait a bit for the TTL to decrease
        time.sleep(1)

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)
        for an in receivedResponse.answer:
            self.assertTrue(an.ttl < ttl)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

    def testCacheDifferentCase(self):
        """
        Cache: Cache matches different case

        dnsdist is configured to cache entries, we are sending one request
        (cache miss) and verify that the same one with a different case
        matches.
        """
        ttl = 600
        name = 'cachedifferentcase.cache.tests.powerdns.com.'
        differentCaseName = 'CacheDifferentCASE.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        differentCaseQuery = dns.message.make_query(differentCaseName, 'AAAA', 'IN')
        response = dns.message.make_response(query)
        differentCaseResponse = dns.message.make_response(differentCaseQuery)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)
        differentCaseResponse.answer.append(rrset)

        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        # different case query should still hit the cache
        (_, receivedResponse) = self.sendUDPQuery(differentCaseQuery, response=None, useQueue=False)
        self.assertEquals(receivedResponse, differentCaseResponse)

    def testLargeAnswer(self):
        """
        Cache: Check that we can cache (and retrieve) large answers

        We should be able to get answers as large as 4096 bytes
        """
        numberOfQueries = 10
        name = 'large-answer.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'TXT', 'IN')
        response = dns.message.make_response(query)
        # we prepare a large answer
        content = ""
        for i in range(44):
            if len(content) > 0:
                content = content + ', '
            content = content + (str(i)*50)
        # pad up to 4096
        content = content + 'A'*42

        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    content)
        response.answer.append(rrset)
        self.assertEquals(len(response.to_wire()), 4096)

        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        for _ in range(numberOfQueries):
            (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, response)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]
            TestCaching._responsesCounter[key] = 0

        self.assertEquals(total, 1)

        # TCP should not be cached
        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        for _ in range(numberOfQueries):
            (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, response)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]
            TestCaching._responsesCounter[key] = 0

        self.assertEquals(total, 1)

class TestTempFailureCacheTTLAction(DNSDistTest):

    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    addAction("servfail.cache.tests.powerdns.com.", TempFailureCacheTTLAction(1))
    newServer{address="127.0.0.1:%d"}
    """

    def testTempFailureCacheTTLAction(self):
        """
        Cache: When a TempFailure TTL is set, it should be honored

        dnsdist is configured to cache packets, plus a specific qname is
        set up with a lower TempFailure Cache TTL. we are sending one request
        (cache miss) and verify that the cache is hit for the following query,
        but the TTL then expires before the larger "good" packetcache TTL.
        """
        name = 'servfail.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.SERVFAIL)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        # next query should hit the cache
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertFalse(receivedQuery)
        self.assertTrue(receivedResponse)
        self.assertEquals(receivedResponse, response)

        # now we wait a bit for the Failure-Cache TTL to expire
        time.sleep(2)

        # next query should NOT hit the cache
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        self.assertEquals(receivedResponse, response)


class TestCachingWithExistingEDNS(DNSDistTest):

    _config_template = """
    pc = newPacketCache(5, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%d"}
    """
    def testCacheWithEDNS(self):
        """
        Cache: Cache should not match different EDNS value

        dnsdist is configured to cache entries, we are sending one request
        (cache miss) and verify that the same one with a different EDNS UDP
        Payload size is not served from the cache.
        """
        misses = 0
        name = 'cachedifferentedns.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=512)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

class TestCachingCacheFull(DNSDistTest):

    _config_template = """
    pc = newPacketCache(1, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%d"}
    """
    def testCacheFull(self):
        """
        Cache: No new entries are cached when the cache is full

        """
        misses = 0
        name = 'cachenotfullyet.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # ok, now the cache is full, send another query
        name = 'cachefull.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries should NOT hit the cache
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

class TestCachingNoStale(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}
    """
    def testCacheNoStale(self):
        """
        Cache: Cache entry, set backend down, we should not get a stale entry

        """
        ttl = 2
        name = 'nostale.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    1,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # ok, we mark the backend as down
        self.sendConsoleCommand("getServer(0):setDown()")
        # and we wait for the entry to expire
        time.sleep(ttl + 1)

        # we should NOT get a cached, stale, entry
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, None)


class TestCachingStale(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _staleCacheTTL = 60
    _config_params = ['_staleCacheTTL', '_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1, temporaryFailureTTL=0, staleTTL=%d})
    getPool(""):setCache(pc)
    setStaleCacheEntriesTTL(600)
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}
    """
    def testCacheStale(self):
        """
        Cache: Cache entry, set backend down, get stale entry

        """
        misses = 0
        ttl = 2
        name = 'stale.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # ok, we mark the backend as down
        self.sendConsoleCommand("getServer(0):setDown()")
        # and we wait for the entry to expire
        time.sleep(ttl + 1)

        # we should get a cached, stale, entry
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)
        for an in receivedResponse.answer:
            self.assertEquals(an.ttl, self._staleCacheTTL)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

class TestCachingStaleExpunged(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _staleCacheTTL = 60
    _config_params = ['_staleCacheTTL', '_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1, temporaryFailureTTL=0, staleTTL=%d})
    getPool(""):setCache(pc)
    setStaleCacheEntriesTTL(600)
    -- try to remove all expired entries
    setCacheCleaningPercentage(100)
    -- clean the cache every second
    setCacheCleaningDelay(1)
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}
    """
    def testCacheStale(self):
        """
        Cache: Cache entry, set backend down, wait for the cache cleaning to run and remove the entry, get no entry
        """
        misses = 0
        drops = 0
        ttl = 2
        name = 'stale-but-expunged.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1
        self.assertEquals(int(self.sendConsoleCommand("getPool(\"\"):getCache():getStats()[\"misses\"]").strip("\n")), misses + drops)

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)
        # the cache should have one entry
        self.assertEquals(int(self.sendConsoleCommand("getPool(\"\"):getCache():getStats()[\"entries\"]").strip("\n")), 1)
        self.assertEquals(int(self.sendConsoleCommand("getPool(\"\"):getCache():getStats()[\"hits\"]").strip("\n")), 1)

        # ok, we mark the backend as down
        self.sendConsoleCommand("getServer(0):setDown()")
        # and we wait for the entry to expire
        time.sleep(ttl + 1)
        # wait a bit more to be sure that the cache cleaning algo has been run
        time.sleep(1)
        # the cache should be empty now
        self.assertEquals(int(self.sendConsoleCommand("getPool(\"\"):getCache():getStats()[\"entries\"]").strip("\n")), 0)

        # we should get a DROP (backend is down, nothing in the cache anymore)
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, None)
        drops += 1

        self.assertEquals(int(self.sendConsoleCommand("getPool(\"\"):getCache():getStats()[\"misses\"]").strip("\n")), misses + drops)
        self.assertEquals(int(self.sendConsoleCommand("getPool(\"\"):getCache():getStats()[\"hits\"]").strip("\n")), 1)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

class TestCachingStaleExpungePrevented(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1, temporaryFailureTTL=0, staleTTL=60, dontAge=false, numberOfShards=1, deferrableInsertLock=true, maxNegativeTTL=3600, ecsParsing=false, keepStaleData=true})
    getPool(""):setCache(pc)
    setStaleCacheEntriesTTL(600)
    -- try to remove all expired entries
    setCacheCleaningPercentage(100)
    -- clean the cache every second
    setCacheCleaningDelay(1)
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}
    """
    def testCacheStale(self):
        """
        Cache: Cache entry, set backend down, wait for the cache cleaning to run and remove the entry, still get a cache HIT because the stale entry was not removed
        """
        misses = 0
        ttl = 2
        name = 'stale-not-expunged.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1
        self.assertEquals(int(self.sendConsoleCommand("getPool(\"\"):getCache():getStats()[\"misses\"]").strip("\n")), 1)

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)
        # the cache should have one entry
        self.assertEquals(int(self.sendConsoleCommand("getPool(\"\"):getCache():getStats()[\"entries\"]").strip("\n")), 1)
        self.assertEquals(int(self.sendConsoleCommand("getPool(\"\"):getCache():getStats()[\"hits\"]").strip("\n")), 1)

        # ok, we mark the backend as down
        self.sendConsoleCommand("getServer(0):setDown()")
        # and we wait for the entry to expire
        time.sleep(ttl + 1)
        # wait a bit more to be sure that the cache cleaning algo has been run
        time.sleep(1)
        # the cache should NOT be empty because the removal of the expired entry should have been prevented
        # since all backends for this pool are down
        self.assertEquals(int(self.sendConsoleCommand("getPool(\"\"):getCache():getStats()[\"entries\"]").strip("\n")), 1)

        # we should get a HIT
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        self.assertEquals(int(self.sendConsoleCommand("getPool(\"\"):getCache():getStats()[\"misses\"]").strip("\n")), 1)
        self.assertEquals(int(self.sendConsoleCommand("getPool(\"\"):getCache():getStats()[\"hits\"]").strip("\n")), 2)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

class TestCacheManagement(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}
    """
    def testCacheExpunge(self):
        """
        Cache: Expunge

        """
        misses = 0
        ttl = 600
        name = 'expunge.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # remove cached entries
        self.sendConsoleCommand("getPool(\"\"):getCache():expunge(0)")

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries should hit the cache again
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

    def testCacheExpungeByName(self):
        """
        Cache: Expunge by name

        """
        misses = 0
        ttl = 600
        name = 'expungebyname.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        name2 = 'expungebynameother.cache.tests.powerdns.com.'
        query2 = dns.message.make_query(name2, 'A', 'IN')
        response2 = dns.message.make_response(query2)
        rrset2 = dns.rrset.from_text(name2,
                                     ttl,
                                     dns.rdataclass.IN,
                                     dns.rdatatype.A,
                                     '127.0.0.1')
        response2.answer.append(rrset2)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # cache another entry
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query2, response2)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query2.id
        self.assertEquals(query2, receivedQuery)
        self.assertEquals(response2, receivedResponse)
        misses += 1

        # queries for name and name 2 should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        (_, receivedResponse) = self.sendUDPQuery(query2, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response2)

        # remove cached entries from name
        self.sendConsoleCommand("getPool(\"\"):getCache():expungeByName(newDNSName(\"" + name + "\"))")

        # Miss for name
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries for name should hit the cache again
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # queries for name2 should still hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query2, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response2)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

    def testCacheExpungeByNameAndType(self):
        """
        Cache: Expunge by name and type

        """
        misses = 0
        ttl = 600
        name = 'expungebynameandtype.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        query2 = dns.message.make_query(name, 'AAAA', 'IN')
        response2 = dns.message.make_response(query2)
        rrset2 = dns.rrset.from_text(name,
                                     ttl,
                                     dns.rdataclass.IN,
                                     dns.rdatatype.AAAA,
                                     '::1')
        response2.answer.append(rrset2)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # cache another entry
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query2, response2)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query2.id
        self.assertEquals(query2, receivedQuery)
        self.assertEquals(response2, receivedResponse)
        misses += 1

        # queries for name A and AAAA should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        (_, receivedResponse) = self.sendUDPQuery(query2, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response2)

        # remove cached entries from name A
        self.sendConsoleCommand("getPool(\"\"):getCache():expungeByName(newDNSName(\"" + name + "\"), DNSQType.A)")

        # Miss for name A
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries for name A should hit the cache again
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # queries for name AAAA should still hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query2, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response2)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]
        self.assertEquals(total, misses)

    def testCacheExpungeByNameAndSuffix(self):
        """
        Cache: Expunge by name

        """
        misses = 0
        ttl = 600
        name = 'expungebyname.suffix.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        name2 = 'expungebyname.suffixother.cache.tests.powerdns.com.'
        query2 = dns.message.make_query(name2, 'A', 'IN')
        response2 = dns.message.make_response(query2)
        rrset2 = dns.rrset.from_text(name2,
                                     ttl,
                                     dns.rdataclass.IN,
                                     dns.rdatatype.A,
                                     '127.0.0.1')
        response2.answer.append(rrset2)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # cache another entry
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query2, response2)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query2.id
        self.assertEquals(query2, receivedQuery)
        self.assertEquals(response2, receivedResponse)
        misses += 1

        # queries for name and name 2 should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        (_, receivedResponse) = self.sendUDPQuery(query2, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response2)

        # remove cached entries from name
        self.sendConsoleCommand("getPool(\"\"):getCache():expungeByName(newDNSName(\"suffix.cache.tests.powerdns.com.\"), DNSQType.ANY, true)")

        # Miss for name
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries for name should hit the cache again
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # queries for name2 should still hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query2, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response2)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

    def testCacheExpungeByNameAndTypeAndSuffix(self):
        """
        Cache: Expunge by name and type

        """
        misses = 0
        ttl = 600
        name = 'expungebynameandtype.suffixtype.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        query2 = dns.message.make_query(name, 'AAAA', 'IN')
        response2 = dns.message.make_response(query2)
        rrset2 = dns.rrset.from_text(name,
                                     ttl,
                                     dns.rdataclass.IN,
                                     dns.rdatatype.AAAA,
                                     '::1')
        response2.answer.append(rrset2)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # cache another entry
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query2, response2)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query2.id
        self.assertEquals(query2, receivedQuery)
        self.assertEquals(response2, receivedResponse)
        misses += 1

        # queries for name A and AAAA should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        (_, receivedResponse) = self.sendUDPQuery(query2, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response2)

        # remove cached entries from name A
        self.sendConsoleCommand("getPool(\"\"):getCache():expungeByName(newDNSName(\"suffixtype.cache.tests.powerdns.com.\"), DNSQType.A, true)")

        # Miss for name A
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries for name A should hit the cache again
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # queries for name AAAA should still hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query2, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response2)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]
        self.assertEquals(total, misses)

class TestCachingTTL(DNSDistTest):

    _maxCacheTTL = 86400
    _minCacheTTL = 600
    _config_params = ['_maxCacheTTL', '_minCacheTTL', '_testServerPort']
    _config_template = """
    pc = newPacketCache(1000, {maxTTL=%d, minTTL=%d})
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%d"}
    """
    def testCacheShortTTL(self):
        """
        Cache: Entries with a TTL shorter than minTTL

        """
        misses = 0
        ttl = 60
        name = 'ttltooshort.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        for an in receivedResponse.answer:
            self.assertEquals(an.ttl, ttl)
        misses += 1

        # We should not have been cached
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        for an in receivedResponse.answer:
            self.assertEquals(an.ttl, ttl)
        misses += 1

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

    def testCacheNXWithNoRR(self):
        """
        Cache: NX with no RR

        """
        misses = 0
        name = 'nxwithnorr.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # We should not have been cached
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

class TestCachingLongTTL(DNSDistTest):

    _maxCacheTTL = 2
    _config_params = ['_maxCacheTTL', '_testServerPort']
    _config_template = """
    pc = newPacketCache(1000, {maxTTL=%d})
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%d"}
    """
    def testCacheLongTTL(self):
        """
        Cache: Entries with a longer TTL than the maximum

        """
        misses = 0
        ttl = 172800
        name = 'longttl.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        for an in receivedResponse.answer:
            self.assertEquals(an.ttl, ttl)
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)
        for an in receivedResponse.answer:
            self.assertTrue(an.ttl <= ttl)

        time.sleep(self._maxCacheTTL + 1)

        # we should not have cached for longer than max cache
        # so it should be a miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        for an in receivedResponse.answer:
            self.assertEquals(an.ttl, ttl)
        misses += 1

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

class TestCachingFailureTTL(DNSDistTest):

    _failureCacheTTL = 2
    _config_params = ['_failureCacheTTL', '_testServerPort']
    _config_template = """
    pc = newPacketCache(1000, {maxTTL=86400, minTTL=0, temporaryFailureTTL=%d, staleTTL=60})
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%d"}
    """
    def testCacheServFailTTL(self):
        """
        Cache: ServFail TTL

        """
        misses = 0
        name = 'servfail.failure.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.SERVFAIL)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        time.sleep(self._failureCacheTTL + 1)

        # we should not have cached for longer than failure cache
        # so it should be a miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

    def testCacheRefusedTTL(self):
        """
        Cache: Refused TTL

        """
        misses = 0
        name = 'refused.failure.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        time.sleep(self._failureCacheTTL + 1)

        # we should not have cached for longer than failure cache
        # so it should be a miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

    def testCacheHeaderOnlyRefusedTTL(self):
        """
        Cache: Header-Only Refused TTL

        """
        misses = 0
        name = 'header-only-refused.failure.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)
        response.question = []

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        time.sleep(self._failureCacheTTL + 1)

        # we should not have cached for longer than failure cache
        # so it should be a miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

class TestCachingNegativeTTL(DNSDistTest):

    _negCacheTTL = 1
    _config_params = ['_negCacheTTL', '_testServerPort']
    _config_template = """
    pc = newPacketCache(1000, {maxTTL=86400, minTTL=0, temporaryFailureTTL=60, staleTTL=60, dontAge=false, numberOfShards=1, deferrableInsertLock=true, maxNegativeTTL=%d})
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%d"}
    """

    def testCacheNegativeTTLNXDomain(self):
        """
        Cache: Negative TTL on NXDOMAIN

        """
        misses = 0
        name = 'nxdomain.negativettl.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)
        soa = dns.rrset.from_text(name,
                                  60,
                                  dns.rdataclass.IN,
                                  dns.rdatatype.SOA,
                                  'ns.' + name + ' hostmaster.' + name + ' 1 3600 3600 3600 60')
        response.authority.append(soa)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        time.sleep(self._negCacheTTL + 1)

        # we should not have cached for longer than the negative TTL
        # so it should be a miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

    def testCacheNegativeTTLNoData(self):
        """
        Cache: Negative TTL on NoData

        """
        misses = 0
        name = 'nodata.negativettl.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NOERROR)
        soa = dns.rrset.from_text(name,
                                  60,
                                  dns.rdataclass.IN,
                                  dns.rdatatype.SOA,
                                  'ns.' + name + ' hostmaster.' + name + ' 1 3600 3600 3600 60')
        response.authority.append(soa)

        # Miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        time.sleep(self._negCacheTTL + 1)

        # we should not have cached for longer than the negativel TTL
        # so it should be a miss
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

class TestCachingDontAge(DNSDistTest):

    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=0, temporaryFailureTTL=60, staleTTL=60, dontAge=true})
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%d"}
    """
    def testCacheDoesntDecreaseTTL(self):
        """
        Cache: Cache doesn't decrease TTL with 'don't age' set

        dnsdist is configured to cache entries but without aging the TTL,
        we are sending one request (cache miss) and verify that the cache
        hits don't have a decreasing TTL.
        """
        ttl = 600
        misses = 0
        name = 'cachedoesntdecreasettl.cache-dont-age.tests.powerdns.com.'
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
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)
        for an in receivedResponse.answer:
            self.assertTrue(an.ttl == ttl)

        # now we wait a bit for the TTL to decrease
        time.sleep(1)

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)
        for an in receivedResponse.answer:
            self.assertTrue(an.ttl == ttl)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEquals(total, misses)

class TestCachingECSWithoutPoolECS(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d", useClientSubnet=true}
    """

    def testCached(self):
        """
        Cache: Cached entry with ECS is a miss when no backend are available
        """
        ttl = 600
        name = 'cached.cache-ecs-without-pool-ecs.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        # first query to fill the cache
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(receivedResponse, response)

        # next queries should hit the cache
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, response)

        # we mark the backend as down
        self.sendConsoleCommand("getServer(0):setDown()")

        # we should NOT get a cached entry since it has ECS and we haven't asked the pool
        # to add ECS when no backend is up
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, None)

class TestCachingECSWithPoolECS(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    getPool(""):setECS(true)
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d", useClientSubnet=true}
    """

    def testCached(self):
        """
        Cache: Cached entry with ECS is a hit when no backend are available
        """
        ttl = 600
        name = 'cached.cache-ecs-with-pool-ecs.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        # first query to fill the cache
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(receivedResponse, response)

        # next queries should hit the cache
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, response)

        # we mark the backend as down
        self.sendConsoleCommand("getServer(0):setDown()")

        # we should STILL get a cached entry since it has ECS and we have asked the pool
        # to add ECS when no backend is up
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, response)

class TestCachingCollisionNoECSParsing(DNSDistTest):

    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%d"}
    """

    def testCacheCollisionNoECSParsing(self):
        """
        Cache: Collision with no ECS parsing
        """
        name = 'collision-no-ecs-parsing.cache.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('10.0.188.3', 32)
        query = dns.message.make_query(name, 'AAAA', 'IN', use_edns=True, options=[ecso], payload=512)
        query.flags = dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        # first query should to fill the cache
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        # second query will hash to the same key, triggering a collision which
        # will not be detected because the qname, qtype, qclass and flags will
        # match and EDNS Client Subnet parsing has not been enabled
        ecso2 = clientsubnetoption.ClientSubnetOption('10.0.192.138', 32)
        query2 = dns.message.make_query(name, 'AAAA', 'IN', use_edns=True, options=[ecso2], payload=512)
        query2.flags = dns.flags.RD
        (_, receivedResponse) = self.sendUDPQuery(query2, response=None, useQueue=False)
        receivedResponse.id = response.id
        self.assertEquals(receivedResponse, response)

class TestCachingCollisionWithECSParsing(DNSDistTest):

    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1, temporaryFailureTTL=60, staleTTL=60, dontAge=false, numberOfShards=1, deferrableInsertLock=true, maxNegativeTTL=3600, parseECS=true})
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%d"}
    """

    def testCacheCollisionWithECSParsing(self):
        """
        Cache: Collision with ECS parsing
        """
        name = 'collision-with-ecs-parsing.cache.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('10.0.115.61', 32)
        query = dns.message.make_query(name, 'AAAA', 'IN', use_edns=True, options=[ecso], payload=512)
        query.flags = dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        # first query should to fill the cache
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        # second query will hash to the same key, triggering a collision which
        # _will_ be detected this time because the qname, qtype, qclass and flags will
        # match but EDNS Client Subnet parsing is now enabled and will detect the issue
        ecso2 = clientsubnetoption.ClientSubnetOption('10.0.143.21', 32)
        query2 = dns.message.make_query(name, 'AAAA', 'IN', use_edns=True, options=[ecso2], payload=512)
        query2.flags = dns.flags.RD
        response2 = dns.message.make_response(query2)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '2001:DB8::1')
        response2.answer.append(rrset)
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query2, response2)
        self.assertEquals(receivedResponse, response2)

class TestCachingScopeZero(DNSDistTest):

    _config_template = """
    -- Be careful to enable ECS parsing in the packet cache, otherwise scope zero is disabled
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1, temporaryFailureTTL=60, staleTTL=60, dontAge=false, numberOfShards=1, deferrableInsertLock=true, maxNegativeTTL=3600, parseECS=true})
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%d", useClientSubnet=true}
    -- to simulate a second client coming from a different IP address,
    -- we will force the ECS value added to the query if RD is set (note that we need
    -- to unset it using rules before the first cache lookup)
    addAction(RDRule(), SetECSAction("192.0.2.1/32"))
    addAction(RDRule(), NoRecurseAction())
    """

    def testScopeZero(self):
        """
        Cache: Test the scope-zero feature, backend returns a scope of zero
        """
        ttl = 600
        name = 'scope-zero.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        query.flags &= ~dns.flags.RD
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.0', 24)
        expectedQuery = dns.message.make_query(name, 'AAAA', 'IN', use_edns=True, options=[ecso], payload=512)
        expectedQuery.flags &= ~dns.flags.RD
        ecsoResponse = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24, 0)
        expectedResponse = dns.message.make_response(query)
        scopedResponse = dns.message.make_response(query)
        scopedResponse.use_edns(edns=True, payload=4096, options=[ecsoResponse])
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        scopedResponse.answer.append(rrset)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, scopedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkMessageEDNSWithECS(expectedQuery, receivedQuery)
            self.checkMessageNoEDNS(receivedResponse, expectedResponse)

        # next query should hit the cache, nothing special about that
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageNoEDNS(receivedResponse, expectedResponse)

        query = dns.message.make_query(name, 'AAAA', 'IN')
        query.flags &= dns.flags.RD
        # next query FROM A DIFFERENT CLIENT since RD is now set should STILL hit the cache
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            receivedResponse.id = expectedResponse.id
            self.checkMessageNoEDNS(receivedResponse, expectedResponse)

        name = 'scope-zero-with-ecs.cache.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'AAAA', 'IN', use_edns=True, options=[ecso], payload=512)
        query.flags &= ~dns.flags.RD
        expectedQuery = dns.message.make_query(name, 'AAAA', 'IN', use_edns=True, options=[ecso], payload=512)
        expectedQuery.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.use_edns(edns=True, payload=4096, options=[ecsoResponse])
        expectedResponse.answer.append(rrset)
        scopedResponse = dns.message.make_response(query)
        scopedResponse.use_edns(edns=True, payload=4096, options=[ecsoResponse])
        scopedResponse.answer.append(rrset)
        # this query has ECS, it should NOT be able to use the scope-zero cached entry since the hash will be
        # different
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, scopedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkMessageEDNSWithECS(expectedQuery, receivedQuery)
            self.checkMessageEDNSWithECS(receivedResponse, expectedResponse)

        # it should still have been cached, though, so the next query should be a hit
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageEDNSWithECS(receivedResponse, expectedResponse)

    def testScopeNotZero(self):
        """
        Cache: Test the scope-zero feature, backend returns a scope of non-zero
        """
        ttl = 600
        name = 'scope-not-zero.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        query.flags &= ~dns.flags.RD
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.0', 24)
        expectedQuery = dns.message.make_query(name, 'AAAA', 'IN', use_edns=True, options=[ecso], payload=512)
        expectedQuery.flags &= ~dns.flags.RD
        ecso2 = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        expectedQuery2 = dns.message.make_query(name, 'AAAA', 'IN', use_edns=True, options=[ecso2], payload=512)
        expectedQuery2.flags &= ~dns.flags.RD
        ecsoResponse = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24, 24)
        ecsoResponse2 = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32, 24)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.answer.append(rrset)
        scopedResponse = dns.message.make_response(query)
        scopedResponse.use_edns(edns=True, payload=4096, options=[ecsoResponse])
        scopedResponse.answer.append(rrset)
        scopedResponse2 = dns.message.make_response(query)
        scopedResponse2.use_edns(edns=True, payload=4096, options=[ecsoResponse2])
        scopedResponse2.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, scopedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkMessageEDNSWithECS(expectedQuery, receivedQuery)
            self.checkMessageNoEDNS(receivedResponse, expectedResponse)

        # next query should hit the cache, nothing special about that
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageNoEDNS(receivedResponse, expectedResponse)

        query = dns.message.make_query(name, 'AAAA', 'IN')
        query.flags &= dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.answer.append(rrset)
        # next query FROM A DIFFERENT CLIENT since RD is now set should NOT hit the cache
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, scopedResponse2)
            receivedQuery.id = expectedQuery2.id
            self.checkMessageEDNSWithECS(expectedQuery2, receivedQuery)
            self.checkMessageNoEDNS(receivedResponse, expectedResponse)

    def testNoECS(self):
        """
        Cache: Test the scope-zero feature, backend returns no ECS at all
        """
        ttl = 600
        name = 'scope-zero-no-ecs.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        query.flags &= ~dns.flags.RD
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.0', 24)
        expectedQuery = dns.message.make_query(name, 'AAAA', 'IN', use_edns=True, options=[ecso], payload=512)
        expectedQuery.flags &= ~dns.flags.RD
        ecso2 = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        expectedQuery2 = dns.message.make_query(name, 'AAAA', 'IN', use_edns=True, options=[ecso2], payload=512)
        expectedQuery2.flags &= ~dns.flags.RD
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response = dns.message.make_response(query)
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = expectedQuery.id
            self.checkMessageEDNSWithECS(expectedQuery, receivedQuery)
            self.checkMessageNoEDNS(receivedResponse, response)

        # next query should hit the cache, nothing special about that
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageNoEDNS(receivedResponse, response)

        query = dns.message.make_query(name, 'AAAA', 'IN')
        query.flags &= dns.flags.RD
        response = dns.message.make_response(query)
        response.answer.append(rrset)
        # next query FROM A DIFFERENT CLIENT since RD is now set should NOT hit the cache
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = expectedQuery2.id
            self.checkMessageEDNSWithECS(expectedQuery2, receivedQuery)
            self.checkMessageNoEDNS(receivedResponse, response)

class TestCachingScopeZeroButNoSubnetcheck(DNSDistTest):

    _config_template = """
    -- We disable ECS parsing in the packet cache, meaning scope zero is disabled
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1, temporaryFailureTTL=60, staleTTL=60, dontAge=false, numberOfShards=1, deferrableInsertLock=true, maxNegativeTTL=3600, parseECS=false})
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%d", useClientSubnet=true}
    -- to simulate a second client coming from a different IP address,
    -- we will force the ECS value added to the query if RD is set (note that we need
    -- to unset it using rules before the first cache lookup)
    addAction(RDRule(), SetECSAction("192.0.2.1/32"))
    addAction(RDRule(), NoRecurseAction())
    """

    def testScopeZero(self):
        """
        Cache: Test that the scope-zero feature is disabled when ECS parsing is not enabled in the cache
        """
        ttl = 600
        name = 'scope-zero-no-subnet.cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        query.flags &= ~dns.flags.RD
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.0', 24)
        expectedQuery = dns.message.make_query(name, 'AAAA', 'IN', use_edns=True, options=[ecso], payload=512)
        expectedQuery.flags &= ~dns.flags.RD
        ecso2 = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        expectedQuery2 = dns.message.make_query(name, 'AAAA', 'IN', use_edns=True, options=[ecso2], payload=512)
        expectedQuery2.flags &= ~dns.flags.RD
        ecsoResponse = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24, 0)
        expectedResponse = dns.message.make_response(query)
        scopedResponse = dns.message.make_response(query)
        scopedResponse.use_edns(edns=True, payload=4096, options=[ecsoResponse])
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        scopedResponse.answer.append(rrset)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, scopedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkMessageEDNSWithECS(expectedQuery, receivedQuery)
            self.checkMessageNoEDNS(receivedResponse, expectedResponse)

        # next query should hit the cache, nothing special about that
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageNoEDNS(receivedResponse, expectedResponse)

        query = dns.message.make_query(name, 'AAAA', 'IN')
        query.flags &= dns.flags.RD
        response = dns.message.make_response(query)
        response.answer.append(rrset)
        # next query FROM A DIFFERENT CLIENT since RD is now set should NOT hit the cache
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = expectedQuery2.id
            self.checkMessageEDNSWithECS(expectedQuery2, receivedQuery)
            self.checkMessageNoEDNS(receivedResponse, response)
