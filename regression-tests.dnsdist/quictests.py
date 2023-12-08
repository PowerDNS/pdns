#!/usr/bin/env python

import dns
from doqclient import StreamResetError

class QUICTests(object):

    def testQUICSimple(self):
        """
        QUIC: Simple query
        """
        name = 'simple.doq.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        (receivedQuery, receivedResponse) = self.sendQUICQuery(query, response=response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.assertEqual(receivedResponse, response)

    def testQUICMultipleStreams(self):
        """
        QUIC: Test multiple queries using the same connection
        """
        name = 'simple.doq.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        connection = self.getQUICConnection()

        (receivedQuery, receivedResponse) = self.sendQUICQuery(query, response=response, connection=connection)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)

        (receivedQuery, receivedResponse) = self.sendQUICQuery(query, response=response, connection=connection)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)

    def testDropped(self):
        """
        QUIC: Dropped query
        """
        name = 'drop.doq.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        dropped = False
        try:
            (_, receivedResponse) = self.sendQUICQuery(query, response=None, useQueue=False)
            self.assertTrue(False)
        except StreamResetError as e:
            self.assertEqual(e.error, 5);

    def testRefused(self):
        """
        QUIC: Refused
        """
        name = 'refused.doq.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.id = 0
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        (_, receivedResponse) = self.sendQUICQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)

    def testSpoof(self):
        """
        QUIC: Spoofed
        """
        name = 'spoof.doq.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.id = 0
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '1.2.3.4')
        expectedResponse.answer.append(rrset)

        (_, receivedResponse) = self.sendQUICQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)

    def testQUICNoBackend(self):
        """
        QUIC: No backend
        """
        name = 'no-backend.doq.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        dropped = False
        try:
            (_, receivedResponse) = self.sendQUICQuery(query, response=None, useQueue=False)
            self.assertTrue(False)
        except StreamResetError as e :
            self.assertEqual(e.error, 5);

class QUICWithCacheTests(object):
    def testCached(self):
        """
        QUIC Cache: Served from cache
        """
        numberOfQueries = 10
        name = 'cached.quic.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        query.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendQUICQuery(query, response=response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

        for _ in range(numberOfQueries):
            (_, receivedResponse) = self.sendQUICQuery(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, response)

        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]

        self.assertEqual(total, 1)
