#!/usr/bin/env python
import dns
import paddingoption
import randompaddingoption
from dnsdisttests import DNSDistTest, pickAvailablePort

class TestCachePadding(DNSDistTest):

    _config_template = """
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%d"}
    """

    def testCached(self):
        """
        Cache padding
        """
        name = 'padding.cache-padding.tests.powerdns.com.'
        po = paddingoption.PaddingOption(64)
        query = dns.message.make_query(name, 'A', want_dnssec=True, options=[po])
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

        # identical query, should be cached
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, response)

        # generate a new padding payload, with random bytes
        rpo = randompaddingoption.RandomPaddingOption(64)
        query = dns.message.make_query(name, 'A', want_dnssec=True, options=[rpo])
        response = dns.message.make_response(query)
        response.answer.append(rrset)

        # identical query except for the padding content which should be skipped, should be cached
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, response)

class TestCacheNotSkippingPadding(DNSDistTest):

    _config_template = """
    -- only skip EDNS cookies, not padding
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1, skipOptions={10}})
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%d"}
    """

    def testCached(self):
        """
        Cache padding: not skipping the padding
        """
        name = 'not-skipping-padding.cache-padding.tests.powerdns.com.'
        po = paddingoption.PaddingOption(64)
        query = dns.message.make_query(name, 'A', want_dnssec=True, options=[po])
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

        # identical query, should be cached
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, response)

        # generate a new padding payload, with random bytes
        rpo = randompaddingoption.RandomPaddingOption(64)
        query = dns.message.make_query(name, 'A', want_dnssec=True, options=[rpo])
        response = dns.message.make_response(query)

        # identical query except for the padding content which should NOT be skipped, should NOT be cached
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)
