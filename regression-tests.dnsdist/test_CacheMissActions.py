#!/usr/bin/env python
import base64
import time
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort

class TestCacheMissSelfAnswered(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']

    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}

    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    -- this does not really make sense on its own, but we might want
    -- to refuse queries for a domain under attack if the anwer is not cached
    addCacheMissAction(SuffixMatchNodeRule("refused.cache-miss.tests.powerdns.com."), RCodeAction(DNSRCode.REFUSED), {name="myFirstRule"})
    """

    def testRefusedWhenNotCached(self):
        """
        CacheMiss: Refused when not in cache
        """
        # check that the rule is in place
        lines = self.sendConsoleCommand('showCacheMissRules()').splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn('myFirstRule', lines[1])

        name = 'refused.cache-miss.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEqual(receivedResponse, expectedResponse)

        # now we remove the rule
        self.sendConsoleCommand('clearCacheMissRules()')
        lines = self.sendConsoleCommand('showCacheMissRules()').splitlines()
        self.assertEqual(len(lines), 1)

        # get a response inserted into the cache
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '2001:db8::1')
        response.answer.append(rrset)
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response=response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)

        # add the rule back
        self.sendConsoleCommand('addCacheMissAction(SuffixMatchNodeRule("refused.cache-miss.tests.powerdns.com."), RCodeAction(DNSRCode.REFUSED), {name="myFirstRule"})')
        lines = self.sendConsoleCommand('showCacheMissRules()').splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn('myFirstRule', lines[1])

        # and check that we do get the cached response
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEqual(receivedResponse, response)

class TestCacheMissGoToADifferentPool(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _testServer2Port = pickAvailablePort()
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort', '_testServer2Port']

    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    newServer{address="127.0.0.1:%d", pool="slow", name="slow"}
    newServer{address="127.0.0.1:%d", pool="initial", name="initial"}

    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool("initial"):setCache(pc)
    getPool("slow"):setCache(pc)

    addAction(AllRule(), PoolAction("initial"))
    -- this does not really make sense on its own, but we might want
    -- to route queries for a domain under attack to a different pool
    -- of 'best-effort' servers if the anwer is not cached
    addCacheMissAction(SuffixMatchNodeRule("routed-to-slow.cache-miss.tests.powerdns.com."), PoolAction("slow"))
    """

    def testRoutedToSlowWhenNotCached(self):
        """
        CacheMiss: Routed to a different pool when not in cache
        """
        name = 'routed-to-slow.cache-miss.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '2001:db8::1')
        response.answer.append(rrset)

        # first query goes to the 'slow' server
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response=response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)

        # the second one is a cache-hit
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEqual(receivedResponse, response)

        backendLines = self.sendConsoleCommand('showServers()').splitlines(False)
        self.assertEqual(len(backendLines), 4)
        for line in backendLines:
            if line.startswith('#') or line.startswith('All'):
                continue
            tokens = line.split()
            self.assertEqual(len(tokens), 15)
            pool = tokens[13]
            queries = int(tokens[9])
            if pool == 'slow':
                self.assertEqual(queries, 1)
            else:
                self.assertEqual(queries, 0)
