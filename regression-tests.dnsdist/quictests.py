#!/usr/bin/env python

import dns
from doqclient import StreamResetError


class QUICTests(object):
    def testQUICSimple(self):
        """
        QUIC: Simple query
        """
        name = "simple.doq.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN", use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, "A", "IN", use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
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
        name = "simple.doq.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN", use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, "A", "IN", use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
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
        name = "drop.doq.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        try:
            (_, receivedResponse) = self.sendQUICQuery(query, response=None, useQueue=False, passExceptions=True)
            self.fail()
        except StreamResetError as e:
            self.assertEqual(e.error, 5)

    def testDroppedResponse(self):
        """
        QUIC: Dropped query response
        """
        name = "drop-response.doq.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        backendResponse = dns.message.make_response(query)
        backendResponse.set_rcode(dns.rcode.REFUSED)
        try:
            (_, _) = self.sendQUICQuery(query, response=backendResponse, passExceptions=True)
            self.fail()
        except StreamResetError as e:
            self.assertEqual(e.error, 5)

    def testRefused(self):
        """
        QUIC: Refused
        """
        name = "refused.doq.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
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
        name = "spoof.doq.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        query.id = 0
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.4")
        expectedResponse.answer.append(rrset)

        (_, receivedResponse) = self.sendQUICQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)

    def testQUICNoBackend(self):
        """
        QUIC: No backend
        """
        name = "no-backend.doq.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN", use_edns=False)
        try:
            (_, receivedResponse) = self.sendQUICQuery(query, response=None, useQueue=False, passExceptions=True)
            self.fail()
        except StreamResetError as e:
            self.assertEqual(e.error, 5)


class QUICACLTests(object):
    def testDropped(self):
        """
        QUIC: Dropped query because of ACL
        """
        name = "acl.doq.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        dropped = False
        try:
            (_, receivedResponse) = self.sendQUICQuery(query, response=None, useQueue=False, passExceptions=True)
            self.fail()
        except StreamResetError as e:
            self.assertEqual(e.error, 5)
            dropped = True
        self.assertTrue(dropped)


class QUICWithCacheTests(object):
    def testCached(self):
        """
        QUIC Cache: Served from cache
        """
        numberOfQueries = 10
        name = "cached.quic.tests.powerdns.com."
        query = dns.message.make_query(name, "AAAA", "IN")
        query.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.AAAA, "::1")
        response.answer.append(rrset)

        before = 0
        for key in self._responsesCounter:
            before += self._responsesCounter[key]

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

        after = 0
        for key in self._responsesCounter:
            after += self._responsesCounter[key]

        self.assertEqual(after - before, 1)

    def testTruncation(self):
        """
        QUIC cache: Truncation over UDP
        """
        # the query is first forwarded over UDP, leading to a TC=1 answer from the
        # backend, then over TCP
        name = "truncated-udp.doq-with-cache.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        query.id = 42
        expectedQuery = dns.message.make_query(name, "A", "IN", use_edns=True, payload=4096)
        expectedQuery.id = 42
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        response.answer.append(rrset)

        before = 0
        for key in self._responsesCounter:
            before += self._responsesCounter[key]

        # first response is a TC=1
        tcResponse = dns.message.make_response(query)
        tcResponse.flags |= dns.flags.TC
        self._toResponderQueue.put(tcResponse, True, 2.0)

        (receivedQuery, receivedResponse) = self.sendQUICQuery(query, response=response)
        # first query, received by the responder over UDP
        self.assertTrue(receivedQuery)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)

        # check the response
        self.assertTrue(receivedResponse)
        self.assertEqual(response, receivedResponse)

        # check the second query, received by the responder over TCP
        receivedQuery = self._fromResponderQueue.get(True, 2.0)
        self.assertTrue(receivedQuery)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)

        # now check the cache for a QUIC query
        (receivedQuery, receivedResponse) = self.sendQUICQuery(query, response=None, useQueue=False)
        self.assertEqual(response, receivedResponse)

        # The TC=1 answer received over UDP will not be cached, because we currently do not cache answers with no records (no TTL)
        # The TCP one should, however
        (_, receivedResponse) = self.sendTCPQuery(expectedQuery, response=None, useQueue=False)
        self.assertEqual(response, receivedResponse)

        after = 0
        for key in self._responsesCounter:
            after += self._responsesCounter[key]

        # one UDP, one TCP
        self.assertEqual(after - before, 2)


class QUICGetLocalAddressOnAnyBindTests(object):
    def testGetLocalAddressOnAnyBind(self):
        """
        QUIC: Return CNAME containing the local address for an ANY bind
        """
        name = "local-address-any.quic.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(
            name,
            60,
            dns.rdataclass.IN,
            dns.rdatatype.CNAME,
            "address-was-127-0-0-1.local-address-any.advanced.tests.powerdns.com.",
        )
        response.answer.append(rrset)

        (_, receivedResponse) = self.sendQUICQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, response)


class QUICXFRTests(object):
    def testXFR(self):
        """
        QUIC: XFR
        """
        name = "xfr.doq.tests.powerdns.com."
        for xfrType in [dns.rdatatype.AXFR, dns.rdatatype.IXFR]:
            query = dns.message.make_query(name, xfrType, "IN")
            expectedResponse = dns.message.make_response(query)
            expectedResponse.set_rcode(dns.rcode.NOTIMP)

            (_, receivedResponse) = self.sendQUICQuery(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)


class QUICTooLargeTests(object):
    def testTooLarge(self):
        """
        QUIC: Too large
        """
        name = "too-large.doq.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")

        raw = query.to_wire()
        padding = b"A" * (65536 - len(raw))
        raw = raw + padding

        (_, receivedResponse) = self.sendQUICQuery(raw, response=None, useQueue=False, rawQuery=True)
        # None over DoQ
        if receivedResponse is not None:
            self.assertEqual(receivedResponse, {b":status": b"400", b"content-length": b"24"})
