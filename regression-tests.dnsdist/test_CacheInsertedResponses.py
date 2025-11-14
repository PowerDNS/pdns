#!/usr/bin/env python
import base64
import time
import dns
from dnsdisttests import DNSDistTest


class TestCacheInsertedResponses(DNSDistTest):
    capTTLMax = 3600
    capTTLMin = 60
    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    addCacheInsertedResponseAction(SuffixMatchNodeRule("cacheinsertedresponses.tests.powerdns.com."), LimitTTLResponseAction(%d, %d))
    newServer{address="127.0.0.1:%d"}
    """
    _config_params = ["capTTLMax", "capTTLMin", "_testServerPort"]

    def testTTLSetAfterInsertion(self):
        """
        CacheInsertedResponse: Check that the TTL is capped after inserting into the cache
        """
        initialTTL = 86400
        name = "reduce-ttl-after-insertion.cacheinsertedresponses.tests.powerdns.com."
        query = dns.message.make_query(name, "AAAA", "IN")

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, initialTTL, dns.rdataclass.IN, dns.rdatatype.AAAA, "::1")
        response.answer.append(rrset)

        responseOnMiss = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, self.capTTLMax, dns.rdataclass.IN, dns.rdatatype.AAAA, "::1")
        responseOnMiss.answer.append(rrset)

        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, responseOnMiss)
        self.assertLessEqual(receivedResponse.answer[0].ttl, self.capTTLMax)

        # now the result should be cached
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, response)
        self.assertGreater(receivedResponse.answer[0].ttl, self.capTTLMax)
        self.assertLessEqual(receivedResponse.answer[0].ttl, initialTTL)

    def testTTLRaisedAfterInsertion(self):
        """
        CacheInsertedResponse: Check that the TTL can be raised after inserting into the cache
        """
        initialTTL = 0
        name = "raise-ttl-after-insertion.cacheinsertedresponses.tests.powerdns.com."
        query = dns.message.make_query(name, "AAAA", "IN")

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, initialTTL, dns.rdataclass.IN, dns.rdatatype.AAAA, "::1")
        response.answer.append(rrset)

        responseOnMiss = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, self.capTTLMax, dns.rdataclass.IN, dns.rdatatype.AAAA, "::1")
        responseOnMiss.answer.append(rrset)

        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, responseOnMiss)
        self.assertGreater(receivedResponse.answer[0].ttl, initialTTL)
        self.assertLessEqual(receivedResponse.answer[0].ttl, self.capTTLMin)

        # the result should NOT have been cached
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, responseOnMiss)
        self.assertGreater(receivedResponse.answer[0].ttl, initialTTL)
        self.assertLessEqual(receivedResponse.answer[0].ttl, self.capTTLMin)
