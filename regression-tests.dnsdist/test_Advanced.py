#!/usr/bin/env python
from datetime import datetime, timedelta
import dns
import os
import subprocess
import threading
import time
import unittest
from dnsdisttests import DNSDistTest

class TestAdvancedFixupCase(DNSDistTest):

    _config_template = """
    truncateTC(true)
    fixupCase(true)
    newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedFixupCase(self):
        """
        Send a query with lower and upper chars,
        make the backend return a lowercase version,
        check that dnsdist fixes the response.
        """
        name = 'fiXuPCasE.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        lowercasequery = dns.message.make_query(name.lower(), 'A', 'IN')
        response = dns.message.make_response(lowercasequery)
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        receivedResponse.id = expectedResponse.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        receivedResponse.id = expectedResponse.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)


class TestAdvancedRemoveRD(DNSDistTest):

    _config_template = """
    addNoRecurseRule("norecurse.advanced.tests.powerdns.com.")
    newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedNoRD(self):
        """
        Send a query with RD,
        check that dnsdist clears the RD flag.
        """
        name = 'norecurse.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN')
        expectedQuery.flags &= ~dns.flags.RD

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
        receivedQuery.id = expectedQuery.id
        receivedResponse.id = response.id
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        receivedResponse.id = response.id
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testAdvancedKeepRD(self):
        """
        Send a query with RD for a canary domain,
        check that dnsdist does not clear the RD flag.
        """
        name = 'keeprecurse.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

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
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)


class TestAdvancedAddCD(DNSDistTest):

    _config_template = """
    addDisableValidationRule("setcd.advanced.tests.powerdns.com.")
    newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedSetCD(self):
        """
        Send a query with CD cleared,
        check that dnsdist set the CD flag.
        """
        name = 'setcd.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name.lower(), 'A', 'IN')
        expectedQuery.flags |= dns.flags.CD

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
        receivedQuery.id = expectedQuery.id
        receivedResponse.id = response.id
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        receivedResponse.id = response.id
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testAdvancedKeepNoCD(self):
        """
        Send a query without CD for a canary domain,
        check that dnsdist does not set the CD flag.
        """
        name = 'keepnocd.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

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
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

class TestAdvancedSpoof(DNSDistTest):

    _config_template = """
    addDomainSpoof("spoof.tests.powerdns.com.", "192.0.2.1", "2001:DB8::1")
    addDomainCNAMESpoof("cnamespoof.tests.powerdns.com.", "cname.tests.powerdns.com.")
    newServer{address="127.0.0.1:%s"}
    """

    def testSpoofA(self):
        """
        Send an A query to "spoof.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'spoof.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        expectedResponse.answer.append(rrset)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=2.0)
        self.assertTrue(receivedResponse)
        receivedResponse.id = expectedResponse.id
        self.assertEquals(expectedResponse, receivedResponse)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False, timeout=2.0)
        self.assertTrue(receivedResponse)
        receivedResponse.id = expectedResponse.id
        self.assertEquals(expectedResponse, receivedResponse)

    def testSpoofAAAA(self):
        """
        Send an AAAA query to "spoof.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'spoof.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '2001:DB8::1')
        expectedResponse.answer.append(rrset)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=2.0)
        self.assertTrue(receivedResponse)
        receivedResponse.id = expectedResponse.id
        self.assertEquals(expectedResponse, receivedResponse)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False, timeout=2.0)
        self.assertTrue(receivedResponse)
        receivedResponse.id = expectedResponse.id
        self.assertEquals(expectedResponse, receivedResponse)

    def testSpoofCNAME(self):
        """
        Send an A query for "cnamespoof.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'cnamespoof.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'cname.tests.powerdns.com.')
        expectedResponse.answer.append(rrset)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=2.0)
        self.assertTrue(receivedResponse)
        receivedResponse.id = expectedResponse.id
        self.assertEquals(expectedResponse, receivedResponse)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False, timeout=2.0)
        self.assertTrue(receivedResponse)
        receivedResponse.id = expectedResponse.id
        self.assertEquals(expectedResponse, receivedResponse)

class TestAdvancedPoolRouting(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s", pool="real"}
    addPoolRule("pool.tests.powerdns.com", "real")
    """

    def testPolicyPool(self):
        """
        Send an A query to "pool.tests.powerdns.com.",
        check that dnsdist routes the query to the "real" pool.
        """
        name = 'pool.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testDefaultPool(self):
        """
        Send an A query to "notpool.tests.powerdns.com.",
        check that dnsdist sends no response (no servers
        in the default pool).
        """
        name = 'notpool.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=2.0)
        self.assertEquals(receivedResponse, None)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False, timeout=2.0)
        self.assertEquals(receivedResponse, None)

class TestAdvancedRoundRobinLB(DNSDistTest):

    _testServer2Port = 5351
    _config_params = ['_testServerPort', '_testServer2Port']
    _config_template = """
    setServerPolicy(roundrobin)
    s1 = newServer{address="127.0.0.1:%s"}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%s"}
    s2:setUp()
    """

    @classmethod
    def startResponders(cls):
        print("Launching responders..")
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort])
        cls._UDPResponder.setDaemon(True)
        cls._UDPResponder.start()
        cls._UDPResponder2 = threading.Thread(name='UDP Responder 2', target=cls.UDPResponder, args=[cls._testServer2Port])
        cls._UDPResponder2.setDaemon(True)
        cls._UDPResponder2.start()

        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort])
        cls._TCPResponder.setDaemon(True)
        cls._TCPResponder.start()

        cls._TCPResponder2 = threading.Thread(name='TCP Responder 2', target=cls.TCPResponder, args=[cls._testServer2Port])
        cls._TCPResponder2.setDaemon(True)
        cls._TCPResponder2.start()

    def testRR(self):
        """
        Send 100 A queries to "rr.tests.powerdns.com.",
        check that dnsdist routes half of it to each backend.
        """
        numberOfQueries = 10
        name = 'rr.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        # clear counters
        for key in TestAdvancedRoundRobinLB._responsesCounter:
            TestAdvancedRoundRobinLB._responsesCounter[key] = 0

        # the round robin counter is shared for UDP and TCP,
        # so we need to do UDP then TCP to have a clean count
        for idx in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            receivedResponse.id = response.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

        for idx in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            receivedQuery.id = query.id
            receivedResponse.id = response.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

        for key in TestAdvancedRoundRobinLB._responsesCounter:
            value = TestAdvancedRoundRobinLB._responsesCounter[key]
            self.assertEquals(value, numberOfQueries / 2)

class TestAdvancedRoundRobinLBOneDown(DNSDistTest):

    _testServer2Port = 5351
    _config_params = ['_testServerPort', '_testServer2Port']
    _config_template = """
    setServerPolicy(roundrobin)
    s1 = newServer{address="127.0.0.1:%s"}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%s"}
    s2:setDown()
    """

    def testRRWithOneDown(self):
        """
        Send 100 A queries to "rr.tests.powerdns.com.",
        check that dnsdist routes all of it to the only backend up.
        """
        numberOfQueries = 10
        name = 'rr.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        # the round robin counter is shared for UDP and TCP,
        # so we need to do UDP then TCP to have a clean count
        for idx in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            receivedResponse.id = response.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

        for idx in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            receivedQuery.id = query.id
            receivedResponse.id = response.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

        total = 0
        for key in TestAdvancedRoundRobinLB._responsesCounter:
            value = TestAdvancedRoundRobinLB._responsesCounter[key]
            self.assertTrue(value == numberOfQueries or value == 0)
            total += value

        self.assertEquals(total, numberOfQueries * 2)

class TestAdvancedACL(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
    """
    _acl = ['192.0.2.1/32']

    def testACLBlocked(self):
        """
        Send an A query to "tests.powerdns.com.",
        we expect no response since 127.0.0.1 is not on the
        ACL.
        """
        name = 'tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False, timeout=2.0)
        self.assertEquals(receivedResponse, None)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False, timeout=2.0)
        self.assertEquals(receivedResponse, None)

class TestAdvancedDelay(DNSDistTest):

    _config_template = """
    addAction(AllRule(), DelayAction(1000))
    newServer{address="127.0.0.1:%s"}
    """

    def testDelayed(self):
        """
        Send an A query to "tests.powerdns.com.",
        check that the response delay is longer than 1000 ms
        over UDP, less than that over TCP.
        """
        name = 'tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        begin = datetime.now()
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        end = datetime.now()
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        self.assertTrue((end - begin) > timedelta(0, 1));

        begin = datetime.now()
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        end = datetime.now()
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        self.assertTrue((end - begin) < timedelta(0, 1));
