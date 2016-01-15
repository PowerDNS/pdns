#!/usr/bin/env python
import clientsubnetoption
import dns
import os
import subprocess
import time
import unittest
from dnsdisttests import DNSDistTest

class TestEdnsClientSubnetNoOverride(DNSDistTest):
    """
    dnsdist is configured to add the EDNS0 Client Subnet
    option, but only if it's not already present in the
    original query.
    """

    _config_template = """
    truncateTC(true)
    block=newDNSName("powerdns.org.")
    function blockFilter(dq)
        if(dq.qname:isPartOf(block))
        then
            print("Blocking *.powerdns.org")
            return true
        end
        return false
    end
    newServer{address="127.0.0.1:%s", useClientSubnet=true}
    """

    def testWithoutEDNS(self):
        """
        ECS: No existing EDNS

        Send a query without EDNS, check that the query
        received by the responder has the correct ECS value
        and that the response received from dnsdist does not
        have an EDNS pseudo-RR.
        """
        name = 'withoutedns.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, options=[ecso], payload=512)
        response = dns.message.make_response(expectedQuery)
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
        receivedQuery.id = expectedQuery.id
        receivedResponse.id = expectedResponse.id
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        receivedResponse.id = expectedResponse.id
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

    def testWithEDNSNoECS(self):
        """
        ECS: Existing EDNS without ECS

        Send a query with EDNS but no ECS value.
        Check that the query received by the responder
        has a valid ECS value and that the response
        received from dnsdist contains an EDNS pseudo-RR.
        """
        name = 'withednsnoecs.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        response = dns.message.make_response(expectedQuery)
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
        receivedQuery.id = expectedQuery.id
        receivedResponse.id = expectedResponse.id
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        receivedResponse.id = expectedResponse.id
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

    def testWithEDNSECS(self):
        """
        ECS: Existing EDNS with ECS

        Send a query with EDNS and a crafted ECS value.
        Check that the query received by the responder
        has the initial ECS value (not overwritten)
        and that the response received from dnsdist contains
        an EDNS pseudo-RR.
        """
        name = 'withednsecs.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('1.2.3.4', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
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

class TestEdnsClientSubnetOverride(DNSDistTest):
    """
    dnsdist is configured to add the EDNS0 Client Subnet
    option, overwriting any existing value.
    """

    _config_template = """
    truncateTC(true)
    block=newDNSName("powerdns.org.")
    function blockFilter(dq)
        if(dq.qname:isPartOf(block))
        then
            print("Blocking *.powerdns.org")
            return true
        end
        return false
    end
    setECSOverride(true)
    setECSSourcePrefixV4(24)
    setECSSourcePrefixV6(56)
    newServer{address="127.0.0.1:%s", useClientSubnet=true}
    """

    def testWithoutEDNS(self):
        """
        ECS Override: No existing EDNS

        Send a query without EDNS, check that the query
        received by the responder has the correct ECS value
        and that the response received from dnsdist does not
        have an EDNS pseudo-RR.
        """
        name = 'withoutedns.overriden.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, options=[ecso], payload=512)
        response = dns.message.make_response(expectedQuery)
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
        receivedQuery.id = expectedQuery.id
        receivedResponse.id = expectedResponse.id
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        receivedResponse.id = expectedResponse.id
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

    def testWithEDNSNoECS(self):
        """
        ECS Override: Existing EDNS without ECS

        Send a query with EDNS but no ECS value.
        Check that the query received by the responder
        has a valid ECS value and that the response
        received from dnsdist contains an EDNS pseudo-RR.
        """
        name = 'withednsnoecs.overriden.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        response = dns.message.make_response(expectedQuery)
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
        receivedQuery.id = expectedQuery.id
        receivedResponse.id = expectedResponse.id
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        receivedResponse.id = expectedResponse.id
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

    def testWithEDNSShorterInitialECS(self):
        """
        ECS Override: Existing EDNS with ECS (short)

        Send a query with EDNS and a crafted ECS value.
        Check that the query received by the responder
        has an overwritten ECS value (not the initial one)
        and that the response received from dnsdist contains
        an EDNS pseudo-RR.
        The initial ECS value is shorter than the one it will
        replaced with.
        """
        name = 'withednsecs.overriden.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 8)
        rewrittenEcso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[rewrittenEcso])
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

    def testWithEDNSLongerInitialECS(self):
        """
        ECS Override: Existing EDNS with ECS (long)

        Send a query with EDNS and a crafted ECS value.
        Check that the query received by the responder
        has an overwritten ECS value (not the initial one)
        and that the response received from dnsdist contains
        an EDNS pseudo-RR.
        The initial ECS value is longer than the one it will
        replaced with.
        """
        name = 'withednsecs.overriden.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        rewrittenEcso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[rewrittenEcso])
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

    def testWithEDNSSameSizeInitialECS(self):
        """
        ECS Override: Existing EDNS with ECS (same)

        Send a query with EDNS and a crafted ECS value.
        Check that the query received by the responder
        has an overwritten ECS value (not the initial one)
        and that the response received from dnsdist contains
        an EDNS pseudo-RR.
        The initial ECS value is exactly the same size as
        the one it will replaced with.
        """
        name = 'withednsecs.overriden.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 24)
        rewrittenEcso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[rewrittenEcso])
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


if __name__ == '__main__':
    unittest.main()
    exit(0)
