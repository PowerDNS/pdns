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
        Advanced: Fixup Case

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
        self.assertEquals(query, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)


class TestAdvancedRemoveRD(DNSDistTest):

    _config_template = """
    addNoRecurseRule("norecurse.advanced.tests.powerdns.com.")
    newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedNoRD(self):
        """
        Advanced: No RD

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
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testAdvancedKeepRD(self):
        """
        Advanced: No RD canary

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
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)


class TestAdvancedAddCD(DNSDistTest):

    _config_template = """
    addDisableValidationRule("setcd.advanced.tests.powerdns.com.")
    newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedSetCD(self):
        """
        Advanced: Set CD

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
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testAdvancedKeepNoCD(self):
        """
        Advanced: Preserve CD canary

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
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
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
        Advanced: Spoof A

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

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)

    def testSpoofAAAA(self):
        """
        Advanced: Spoof AAAA

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

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)

    def testSpoofCNAME(self):
        """
        Advanced: Spoof CNAME

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

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)

class TestAdvancedPoolRouting(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s", pool="real"}
    addPoolRule("pool.tests.powerdns.com", "real")
    """

    def testPolicyPool(self):
        """
        Advanced: Set pool by qname

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
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testDefaultPool(self):
        """
        Advanced: Set pool by qname canary

        Send an A query to "notpool.tests.powerdns.com.",
        check that dnsdist sends no response (no servers
        in the default pool).
        """
        name = 'notpool.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, None)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
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
        Advanced: Round Robin

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

        # the round robin counter is shared for UDP and TCP,
        # so we need to do UDP then TCP to have a clean count
        for idx in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

        for idx in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            receivedQuery.id = query.id
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
        Advanced: Round Robin with one server down

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
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

        for idx in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            receivedQuery.id = query.id
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
        Advanced: ACL blocked

        Send an A query to "tests.powerdns.com.",
        we expect no response since 127.0.0.1 is not on the
        ACL.
        """
        name = 'tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, None)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, None)

class TestAdvancedDelay(DNSDistTest):

    _config_template = """
    addAction(AllRule(), DelayAction(1000))
    newServer{address="127.0.0.1:%s"}
    """

    def testDelayed(self):
        """
        Advanced: Delayed

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
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        self.assertTrue((end - begin) > timedelta(0, 1));

        begin = datetime.now()
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        end = datetime.now()
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        self.assertTrue((end - begin) < timedelta(0, 1));

class TestAdvancedLuaSpoof(DNSDistTest):

    _config_template = """
    function spoof1rule(dq)
        if(dq.qtype==1) -- A
        then
                return DNSAction.Spoof, "192.0.2.1"
        elseif(dq.qtype == 28) -- AAAA
        then
                return DNSAction.Spoof, "2001:DB8::1"
        else
                return DNSAction.None, ""
        end
    end
    function spoof2rule(dq)
        return DNSAction.Spoof, "spoofedcname.tests.powerdns.com."
    end
    addLuaAction("luaspoof1.tests.powerdns.com.", spoof1rule)
    addLuaAction("luaspoof2.tests.powerdns.com.", spoof2rule)
    newServer{address="127.0.0.1:%s"}
    """

    def testLuaSpoofA(self):
        """
        Advanced: Spoofing an A via Lua

        Send an A query to "luaspoof1.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'luaspoof1.tests.powerdns.com.'
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

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)

    def testLuaSpoofAAAA(self):
        """
        Advanced: Spoofing an AAAA via Lua

        Send an AAAA query to "luaspoof1.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'luaspoof1.tests.powerdns.com.'
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

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)

    def testLuaSpoofAWithCNAME(self):
        """
        Advanced: Spoofing an A with a CNAME via Lua

        Send an A query to "luaspoof2.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'luaspoof2.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'spoofedcname.tests.powerdns.com.')
        expectedResponse.answer.append(rrset)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)

    def testLuaSpoofAAAAWithCNAME(self):
        """
        Advanced: Spoofing an AAAA with a CNAME via Lua

        Send an AAAA query to "luaspoof2.tests.powerdns.com.",
        check that dnsdist sends a spoofed result.
        """
        name = 'luaspoof2.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'spoofedcname.tests.powerdns.com.')
        expectedResponse.answer.append(rrset)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(expectedResponse, receivedResponse)

class TestAdvancedTruncateAnyAndTCP(DNSDistTest):

    _config_template = """
    truncateTC(false)
    addAction(AndRule({QTypeRule("ANY"), TCPRule(true)}), TCAction())
    newServer{address="127.0.0.1:%s"}
    """
    def testTruncateAnyOverTCP(self):
        """
        Advanced: Truncate ANY over TCP

        Send an ANY query to "anytruncatetcp.tests.powerdns.com.",
        should be truncated over TCP, not over UDP (yes, it makes no sense,
        deal with it).
        """
        name = 'anytruncatetcp.tests.powerdns.com.'
        query = dns.message.make_query(name, 'ANY', 'IN')

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
        self.assertEquals(receivedResponse, response)

        expectedResponse = dns.message.make_response(query)
        expectedResponse.flags |= dns.flags.TC

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, expectedResponse)

class TestAdvancedAndNot(DNSDistTest):

    _config_template = """
    addAction(AndRule({NotRule(QTypeRule("A")), TCPRule(false)}), RCodeAction(4))
    newServer{address="127.0.0.1:%s"}
    """
    def testAOverUDPReturnsNotImplementedCanary(self):
        """
        Advanced: !A && UDP canary

        dnsdist is configured to reply 'not implemented' for query
        over UDP AND !qtype A.
        We send an A query over UDP and TCP, and check that the
        response is OK.
        """
        name = 'andnot.tests.powerdns.com.'
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
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

    def testAOverUDPReturnsNotImplemented(self):
        """
        Advanced: !A && UDP

        dnsdist is configured to reply 'not implemented' for query
        over UDP AND !qtype A.
        We send a TXT query over UDP and TCP, and check that the
        response is OK for TCP and 'not implemented' for UDP.
        """
        name = 'andnot.tests.powerdns.com.'
        query = dns.message.make_query(name, 'TXT', 'IN')

        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.NOTIMP)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, expectedResponse)

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    'nothing to see here')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

class TestAdvancedOr(DNSDistTest):

    _config_template = """
    addAction(OrRule({QTypeRule("A"), TCPRule(false)}), RCodeAction(4))
    newServer{address="127.0.0.1:%s"}
    """
    def testAAAAOverUDPReturnsNotImplemented(self):
        """
        Advanced: A || UDP: AAAA

        dnsdist is configured to reply 'not implemented' for query
        over UDP OR qtype A.
        We send an AAAA query over UDP and TCP, and check that the
        response is 'not implemented' for UDP and OK for TCP.
        """
        name = 'aorudp.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.NOTIMP)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, expectedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

    def testAOverUDPReturnsNotImplemented(self):
        """
        Advanced: A || UDP: A

        dnsdist is configured to reply 'not implemented' for query
        over UDP OR qtype A.
        We send an A query over UDP and TCP, and check that the
        response is 'not implemented' for both.
        """
        name = 'aorudp.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.NOTIMP)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, expectedResponse)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, expectedResponse)

class TestAdvancedCaching(DNSDistTest):

    _config_template = """
    pc = newPacketCache(5, 86400, 1)
    getPool(""):setCache(pc)
    addAction(makeRule("nocache.tests.powerdns.com."), SkipCacheAction())
    newServer{address="127.0.0.1:%s"}
    """
    def testCached(self):
        """
        Advanced: Served from cache

        dnsdist is configured to cache entries, we are sending several
        identical requests and checking that the backend only receive
        the first one.
        """
        numberOfQueries = 10
        name = 'cached.tests.powerdns.com.'
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
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        for idx in range(numberOfQueries):
            (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
            receivedResponse.id = response.id
            self.assertEquals(receivedResponse, response)

            (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
            receivedResponse.id = response.id
            self.assertEquals(receivedResponse, response)

        total = 0
        for key in TestAdvancedCaching._responsesCounter:
            total += TestAdvancedCaching._responsesCounter[key]

        self.assertEquals(total, 1)

    def testSkipCache(self):
        """
        Advanced: SkipCacheAction

        dnsdist is configured to not cache entries for nocache.tests.powerdns.com.
         we are sending several requests and checking that the backend get them all.
        """
        name = 'nocache.tests.powerdns.com.'
        numberOfQueries = 10
        query = dns.message.make_query(name, 'AAAA', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        for idx in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            receivedResponse.id = response.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(receivedResponse, response)

            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            receivedResponse.id = response.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(receivedResponse, response)

        for key in TestAdvancedCaching._responsesCounter:
            value = TestAdvancedCaching._responsesCounter[key]
            self.assertEquals(value, numberOfQueries)

    def testCacheExpiration(self):
        """
        Advanced: Cache expiration

        dnsdist is configured to cache entries, we are sending one request
        (cache miss) with a very short TTL, checking that the next requests
        are cached. Then we wait for the TTL to expire, check that the
        next request is a miss but the following one a hit.
        """
        ttl = 2
        misses = 0
        name = 'cacheexpiration.tests.powerdns.com.'
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
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        receivedResponse.id = response.id
        self.assertEquals(receivedResponse, response)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        receivedResponse.id = response.id
        self.assertEquals(receivedResponse, response)

        # now we wait a bit for the cache entry to expire
        time.sleep(ttl + 1)

        # next query should be a miss, fill the cache again
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)
        misses += 1

        # following queries should hit the cache again
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        receivedResponse.id = response.id
        self.assertEquals(receivedResponse, response)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        receivedResponse.id = response.id
        self.assertEquals(receivedResponse, response)

        total = 0
        for key in TestAdvancedCaching._responsesCounter:
            total += TestAdvancedCaching._responsesCounter[key]

        self.assertEquals(total, misses)

    def testCacheDecreaseTTL(self):
        """
        Advanced: Cache decreases TTL

        dnsdist is configured to cache entries, we are sending one request
        (cache miss) and verify that the cache hits have a decreasing TTL.
        """
        ttl = 600
        misses = 0
        name = 'cachedecreasettl.tests.powerdns.com.'
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
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)
        misses += 1

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        receivedResponse.id = response.id
        self.assertEquals(receivedResponse, response)
        for an in receivedResponse.answer:
            self.assertTrue(an.ttl <= ttl)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        receivedResponse.id = response.id
        self.assertEquals(receivedResponse, response)
        for an in receivedResponse.answer:
            self.assertTrue(an.ttl <= ttl)

        # now we wait a bit for the TTL to decrease
        time.sleep(1)

        # next queries should hit the cache
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        receivedResponse.id = response.id
        self.assertEquals(receivedResponse, response)
        for an in receivedResponse.answer:
            self.assertTrue(an.ttl < ttl)

        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        receivedResponse.id = response.id
        self.assertEquals(receivedResponse, response)
        for an in receivedResponse.answer:
            self.assertTrue(an.ttl < ttl)

        total = 0
        for key in TestAdvancedCaching._responsesCounter:
            total += TestAdvancedCaching._responsesCounter[key]

        self.assertEquals(total, misses)

    def testCacheDifferentCase(self):
        """
        Advanced: Cache matches different case

        dnsdist is configured to cache entries, we are sending one request
        (cache miss) and verify that the same one with a different case
        matches.
        """
        ttl = 600
        name = 'cachedifferentcase.tests.powerdns.com.'
        differentCaseName = 'CacheDifferentCASE.tests.powerdns.com.'
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
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, response)

        # different case query should still hit the cache
        (_, receivedResponse) = self.sendUDPQuery(differentCaseQuery, response=None, useQueue=False)
        receivedResponse.id = differentCaseResponse.id
        self.assertEquals(receivedResponse, differentCaseResponse)

        (_, receivedResponse) = self.sendTCPQuery(differentCaseQuery, response=None, useQueue=False)
        receivedResponse.id = differentCaseResponse.id
        self.assertEquals(receivedResponse, differentCaseResponse)

class TestAdvancedCachingWithExistingEDNS(DNSDistTest):

    _config_template = """
    pc = newPacketCache(5, 86400, 1)
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%s"}
    """
    def testCacheWithEDNS(self):
        """
        Advanced: Cache should not match different EDNS value

        dnsdist is configured to cache entries, we are sending one request
        (cache miss) and verify that the same one with a different EDNS UDP
        Payload size is not served from the cache.
        """
        misses = 0
        name = 'cachedifferentedns.tests.powerdns.com.'
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
        receivedResponse.id = response.id
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
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        misses += 1

        total = 0
        for key in TestAdvancedCaching._responsesCounter:
            total += TestAdvancedCaching._responsesCounter[key]

        self.assertEquals(total, misses)
