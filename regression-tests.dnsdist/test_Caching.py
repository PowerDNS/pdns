#!/usr/bin/env python
import time
import dns
from dnsdisttests import DNSDistTest

class TestCaching(DNSDistTest):

    _config_template = """
    pc = newPacketCache(100, 86400, 1)
    getPool(""):setCache(pc)
    addAction(makeRule("nocache.cache.tests.powerdns.com."), SkipCacheAction())
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
        for key in TestCaching._responsesCounter:
            total += TestCaching._responsesCounter[key]
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
        for key in TestCaching._responsesCounter:
            total += TestCaching._responsesCounter[key]
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

        for key in TestCaching._responsesCounter:
            value = TestCaching._responsesCounter[key]
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
        for key in TestCaching._responsesCounter:
            total += TestCaching._responsesCounter[key]

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
        for key in TestCaching._responsesCounter:
            total += TestCaching._responsesCounter[key]

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
        for key in TestCaching._responsesCounter:
            total += TestCaching._responsesCounter[key]

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
        for key in TestCachingWithExistingEDNS._responsesCounter:
            total += TestCachingWithExistingEDNS._responsesCounter[key]

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
        for key in TestCachingCacheFull._responsesCounter:
            total += TestCachingCacheFull._responsesCounter[key]

        self.assertEquals(total, misses)
