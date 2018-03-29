#!/usr/bin/env python
import base64
import time
import dns
from dnsdisttests import DNSDistTest

class TestCaching(DNSDistTest):

    _config_template = """
    pc = newPacketCache(100, 86400, 1)
    getPool(""):setCache(pc)
    addAction(makeRule("nocache.cache.tests.powerdns.com."), SkipCacheAction())
    function skipViaLua(dq)
        dq.skipCache = true
        return DNSAction.None, ""
    end
    addAction("nocachevialua.cache.tests.powerdns.com.", LuaAction(skipViaLua))
    newServer{address="127.0.0.1:%s"}
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
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(receivedResponse, response)

            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
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
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(receivedResponse, response)

            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
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


class TestTempFailureCacheTTLAction(DNSDistTest):

    _config_template = """
    pc = newPacketCache(100, 86400, 1)
    getPool(""):setCache(pc)
    addAction("servfail.cache.tests.powerdns.com.", TempFailureCacheTTLAction(1))
    newServer{address="127.0.0.1:%s"}
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
    pc = newPacketCache(5, 86400, 1)
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%s"}
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
    pc = newPacketCache(1, 86400, 1)
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%s"}
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
    pc = newPacketCache(100, 86400, 1)
    getPool(""):setCache(pc)
    setKey("%s")
    controlSocket("127.0.0.1:%s")
    newServer{address="127.0.0.1:%s"}
    """
    def testCacheNoStale(self):
        """
        Cache: Cache entry, set backend down, we should not get a stale entry

        """
        ttl = 1
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
    pc = newPacketCache(100, 86400, 1, %s)
    getPool(""):setCache(pc)
    setStaleCacheEntriesTTL(600)
    setKey("%s")
    controlSocket("127.0.0.1:%s")
    newServer{address="127.0.0.1:%s"}
    """
    def testCacheStale(self):
        """
        Cache: Cache entry, set backend down, get stale entry

        """
        misses = 0
        ttl = 1
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

class TestCacheManagement(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    pc = newPacketCache(100, 86400, 1)
    getPool(""):setCache(pc)
    setKey("%s")
    controlSocket("127.0.0.1:%s")
    newServer{address="127.0.0.1:%s"}
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
        self.sendConsoleCommand("getPool(\"\"):getCache():expungeByName(newDNSName(\"" + name + "\"), dnsdist.A)")

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
        self.sendConsoleCommand("getPool(\"\"):getCache():expungeByName(newDNSName(\"suffix.cache.tests.powerdns.com.\"), dnsdist.ANY, true)")

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
        self.sendConsoleCommand("getPool(\"\"):getCache():expungeByName(newDNSName(\"suffixtype.cache.tests.powerdns.com.\"), dnsdist.A, true)")

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
    pc = newPacketCache(1000, %s, %s)
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%s"}
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
    pc = newPacketCache(1000, %s)
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%s"}
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
    pc = newPacketCache(1000, 86400, 0, %d, 60)
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%s"}
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

class TestCachingDontAge(DNSDistTest):

    _config_template = """
    pc = newPacketCache(100, 86400, 0, 60, 60, true)
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%s"}
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
    pc = newPacketCache(100, 86400, 1)
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
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # over TCP too
        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # we mark the backend as down
        self.sendConsoleCommand("getServer(0):setDown()")

        # we should NOT get a cached entry since it has ECS and we haven't asked the pool
        # to add ECS when no backend is up
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, None)

        # same over TCP
        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, None)

class TestCachingECSWithPoolECS(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    pc = newPacketCache(100, 86400, 1)
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
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # over TCP too
        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # we mark the backend as down
        self.sendConsoleCommand("getServer(0):setDown()")

        # we should STILL get a cached entry since it has ECS and we have asked the pool
        # to add ECS when no backend is up
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)

        # same over TCP
        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, response)
