#!/usr/bin/env python
import dns
import clientsubnetoption
import cookiesoption
from dnsdisttests import DNSDistTest
from datetime import datetime, timedelta

class TestEdnsClientSubnetNoOverride(DNSDistTest):
    """
    dnsdist is configured to add the EDNS0 Client Subnet
    option, but only if it's not already present in the
    original query.
    """

    _config_template = """
    truncateTC(true)
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

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseNoEDNS(expectedResponse, receivedResponse)

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

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseEDNSWithoutECS(expectedResponse, receivedResponse)

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


        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.checkQueryEDNSWithECS(query, receivedQuery)
            self.checkResponseEDNSWithoutECS(response, receivedResponse)

    def testWithoutEDNSResponseWithECS(self):
        """
        ECS: No existing EDNS (BE returning ECS)

        Send a query without EDNS, check that the query
        received by the responder has the correct ECS value
        and that the response received from dnsdist does not
        have an EDNS pseudo-RR.
        This time the response returned by the backend contains
        an ECS option with scope set.
        """
        name = 'withoutedns.bereturnsecs.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, options=[ecso], payload=512)
        response = dns.message.make_response(expectedQuery)
        ecsoResponse = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24, scope=24)
        response.use_edns(edns=True, payload=4096, options=[ecsoResponse])
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseNoEDNS(expectedResponse, receivedResponse)

    def testWithEDNSNoECSResponseWithECS(self):
        """
        ECS: Existing EDNS without ECS (BE returning only the ECS option)

        Send a query with EDNS but no ECS value.
        Check that the query received by the responder
        has a valid ECS value and that the response
        received from dnsdist contains an EDNS pseudo-RR.
        This time the response returned by the backend contains
        an ECS option with scope set.
        """
        name = 'withednsnoecs.bereturnsecs.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        response = dns.message.make_response(expectedQuery)
        ecsoResponse = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24, scope=24)
        response.use_edns(edns=True, payload=4096, options=[ecsoResponse])
        expectedResponse = dns.message.make_response(query, our_payload=4096)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseEDNSWithoutECS(expectedResponse, receivedResponse)

    def testWithEDNSNoECSResponseWithCookiesThenECS(self):
        """
        ECS: Existing EDNS without ECS (BE returning Cookies then ECS options)

        Send a query with EDNS but no ECS value.
        Check that the query received by the responder
        has a valid ECS value and that the response
        received from dnsdist contains an EDNS pseudo-RR.
        This time the response returned by the backend contains
        one cookies then one ECS option.
        """
        name = 'withednsnoecs.bereturnscookiesthenecs.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        response = dns.message.make_response(expectedQuery)
        ecoResponse = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        ecsoResponse = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24, scope=24)
        response.use_edns(edns=True, payload=4096, options=[ecoResponse, ecsoResponse])
        expectedResponse = dns.message.make_response(query)
        expectedResponse.use_edns(edns=True, payload=4096, options=[ecoResponse])
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse.answer.append(rrset)
        expectedResponse.use_edns(edns=True, payload=4096, options=[ecoResponse])

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseEDNSWithoutECS(expectedResponse, receivedResponse, withCookies=1)

    def testWithEDNSNoECSResponseWithECSThenCookies(self):
        """
        ECS: Existing EDNS without ECS (BE returning ECS then Cookies options)

        Send a query with EDNS but no ECS value.
        Check that the query received by the responder
        has a valid ECS value and that the response
        received from dnsdist contains an EDNS pseudo-RR.
        This time the response returned by the backend contains
        one ECS then one Cookies option.
        """
        name = 'withednsnoecs.bereturnsecsthencookies.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        response = dns.message.make_response(expectedQuery)
        ecoResponse = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        ecsoResponse = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24, scope=24)
        response.use_edns(edns=True, payload=4096, options=[ecsoResponse, ecoResponse])
        expectedResponse = dns.message.make_response(query, our_payload=4096)
        expectedResponse.use_edns(edns=True, payload=4096, options=[ecoResponse])
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse.answer.append(rrset)
        response.use_edns(edns=True, payload=4096, options=[ecoResponse])

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseEDNSWithoutECS(expectedResponse, receivedResponse, withCookies=1)

    def testWithEDNSNoECSResponseWithCookiesThenECSThenCookies(self):
        """
        ECS: Existing EDNS without ECS (BE returning Cookies, ECS then Cookies options)

        Send a query with EDNS but no ECS value.
        Check that the query received by the responder
        has a valid ECS value and that the response
        received from dnsdist contains an EDNS pseudo-RR.
        This time the response returned by the backend contains
        one Cookies, one ECS then one Cookies option.
        """
        name = 'withednsnoecs.bereturnscookiesecscookies.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        response = dns.message.make_response(expectedQuery)
        ecoResponse = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        ecsoResponse = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24, scope=24)
        response.use_edns(edns=True, payload=4096, options=[ecoResponse, ecsoResponse, ecoResponse])
        expectedResponse = dns.message.make_response(query, our_payload=4096)
        expectedResponse.use_edns(edns=True, payload=4096, options=[ecoResponse, ecoResponse])
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseEDNSWithoutECS(expectedResponse, receivedResponse, withCookies=2)

class TestEdnsClientSubnetOverride(DNSDistTest):
    """
    dnsdist is configured to add the EDNS0 Client Subnet
    option, overwriting any existing value.
    """

    _config_template = """
    truncateTC(true)
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
        name = 'withoutedns.overridden.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, options=[ecso], payload=512)
        response = dns.message.make_response(expectedQuery)
        response.use_edns(edns=True, payload=4096, options=[ecso])
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseNoEDNS(expectedResponse, receivedResponse)

    def testWithEDNSNoECS(self):
        """
        ECS Override: Existing EDNS without ECS

        Send a query with EDNS but no ECS value.
        Check that the query received by the responder
        has a valid ECS value and that the response
        received from dnsdist contains an EDNS pseudo-RR.
        """
        name = 'withednsnoecs.overridden.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        response = dns.message.make_response(expectedQuery)
        response.use_edns(edns=True, payload=4096, options=[ecso])
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query, our_payload=4096)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseEDNSWithoutECS(expectedResponse, receivedResponse)

    def testWithEDNSShorterInitialECS(self):
        """
        ECS Override: Existing EDNS with ECS (short)

        Send a query with EDNS and a crafted ECS value.
        Check that the query received by the responder
        has an overwritten ECS value (not the initial one)
        and that the response received from dnsdist contains
        an EDNS pseudo-RR.
        The initial ECS value is shorter than the one it will be
        replaced with.
        """
        name = 'withednsecs.overridden.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 8)
        rewrittenEcso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[rewrittenEcso])
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=4096, options=[rewrittenEcso])
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseEDNSWithECS(response, receivedResponse)

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
        name = 'withednsecs.overridden.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        rewrittenEcso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[rewrittenEcso])
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=4096, options=[rewrittenEcso])
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseEDNSWithECS(response, receivedResponse)

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
        name = 'withednsecs.overridden.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 24)
        rewrittenEcso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[rewrittenEcso])
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=4096, options=[rewrittenEcso])
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseEDNSWithECS(response, receivedResponse)

    def testWithECSFollowedByAnother(self):
        """
        ECS: Existing EDNS with ECS, followed by another record

        Send a query with EDNS and an existing ECS value.
        The OPT record is not the last one in the query
        and is followed by another one.
        Check that the query received by the responder
        has a valid ECS value and that the response
        received from dnsdist contains an EDNS pseudo-RR.
        """
        name = 'withecs-followedbyanother.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 24)
        eco = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        rewrittenEcso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[eco,ecso,eco])
        # I would have loved to use a TSIG here but I can't find how to make dnspython ignore
        # it while parsing the message in the receiver :-/
        query.additional.append(rrset)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[eco,eco,rewrittenEcso])
        expectedQuery.additional.append(rrset)

        response = dns.message.make_response(expectedQuery)
        response.use_edns(edns=True, payload=4096, options=[eco, ecso, eco])
        expectedResponse = dns.message.make_response(query)
        expectedResponse.use_edns(edns=True, payload=4096, options=[eco, ecso, eco])
        response.answer.append(rrset)
        response.additional.append(rrset)
        expectedResponse.answer.append(rrset)
        expectedResponse.additional.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery, 2)
            self.checkResponseEDNSWithECS(expectedResponse, receivedResponse, 2)

    def testWithAnswerThenECS(self):
        """
        ECS: Record in answer followed by an existing EDNS with ECS

        Send a query with a record in the answer section, EDNS and an existing ECS value.
        Check that the query received by the responder
        has a valid ECS value and that the response
        received from dnsdist contains an EDNS pseudo-RR.
        """
        name = 'record-in-an-withecs.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 24)
        eco = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        rewrittenEcso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[eco,ecso,eco])
        query.answer.append(rrset)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[eco,eco,rewrittenEcso])
        expectedQuery.answer.append(rrset)

        response = dns.message.make_response(expectedQuery)
        response.use_edns(edns=True, payload=4096, options=[eco, ecso, eco])
        expectedResponse = dns.message.make_response(query)
        expectedResponse.use_edns(edns=True, payload=4096, options=[eco, ecso, eco])
        response.answer.append(rrset)
        response.additional.append(rrset)
        expectedResponse.answer.append(rrset)
        expectedResponse.additional.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery, 2)
            self.checkResponseEDNSWithECS(expectedResponse, receivedResponse, 2)

    def testWithAuthThenECS(self):
        """
        ECS: Record in authority followed by an existing EDNS with ECS

        Send a query with a record in the authority section, EDNS and an existing ECS value.
        Check that the query received by the responder
        has a valid ECS value and that the response
        received from dnsdist contains an EDNS pseudo-RR.
        """
        name = 'record-in-an-withecs.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 24)
        eco = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        rewrittenEcso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[eco,ecso,eco])
        query.authority.append(rrset)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[eco,eco,rewrittenEcso])
        expectedQuery.authority.append(rrset)

        response = dns.message.make_response(expectedQuery)
        response.use_edns(edns=True, payload=4096, options=[eco, ecso, eco])
        expectedResponse = dns.message.make_response(query)
        expectedResponse.use_edns(edns=True, payload=4096, options=[eco, ecso, eco])
        response.answer.append(rrset)
        response.additional.append(rrset)
        expectedResponse.answer.append(rrset)
        expectedResponse.additional.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery, 2)
            self.checkResponseEDNSWithECS(expectedResponse, receivedResponse, 2)

    def testWithEDNSNoECSFollowedByAnother(self):
        """
        ECS: Existing EDNS without ECS, followed by another record

        Send a query with EDNS but no ECS value.
        The OPT record is not the last one in the query
        and is followed by another one.
        Check that the query received by the responder
        has a valid ECS value and that the response
        received from dnsdist contains an EDNS pseudo-RR.
        """
        name = 'withedns-no-ecs-followedbyanother.ecs.tests.powerdns.com.'
        eco = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        rewrittenEcso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[eco])
        # I would have loved to use a TSIG here but I can't find how to make dnspython ignore
        # it while parsing the message in the receiver :-/
        query.additional.append(rrset)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[eco,rewrittenEcso])
        expectedQuery.additional.append(rrset)

        response = dns.message.make_response(expectedQuery)
        response.use_edns(edns=True, payload=4096, options=[eco, rewrittenEcso, eco])
        expectedResponse = dns.message.make_response(query)
        expectedResponse.use_edns(edns=True, payload=4096, options=[eco, eco])
        response.answer.append(rrset)
        response.additional.append(rrset)
        expectedResponse.answer.append(rrset)
        expectedResponse.additional.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery, 1)
            self.checkResponseEDNSWithoutECS(expectedResponse, receivedResponse, 2)

class TestECSDisabledByRuleOrLua(DNSDistTest):
    """
    dnsdist is configured to add the EDNS0 Client Subnet
    option, but we disable it via SetDisableECSAction()
    or Lua.
    """

    _config_template = """
    setECSOverride(false)
    setECSSourcePrefixV4(16)
    setECSSourcePrefixV6(16)
    newServer{address="127.0.0.1:%s", useClientSubnet=true}
    addAction(SuffixMatchNodeRule("disabled.ecsrules.tests.powerdns.com."), SetDisableECSAction())
    function disableECSViaLua(dq)
        dq.useECS = false
        return DNSAction.None, ""
    end
    addAction("disabledvialua.ecsrules.tests.powerdns.com.", LuaAction(disableECSViaLua))
    """

    def testWithECSNotDisabled(self):
        """
        ECS Disable: ECS enabled in the backend
        """
        name = 'notdisabled.ecsrules.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 16)
        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, options=[ecso], payload=512)
        response = dns.message.make_response(expectedQuery)
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseNoEDNS(expectedResponse, receivedResponse)

    def testWithECSDisabledViaRule(self):
        """
        ECS Disable: ECS enabled in the backend, but disabled by a rule
        """
        name = 'disabled.ecsrules.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.checkQueryNoEDNS(query, receivedQuery)
            self.checkResponseNoEDNS(response, receivedResponse)

    def testWithECSDisabledViaLua(self):
        """
        ECS Disable: ECS enabled in the backend, but disabled via Lua
        """
        name = 'disabledvialua.ecsrules.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.checkQueryNoEDNS(query, receivedQuery)
            self.checkResponseNoEDNS(response, receivedResponse)

class TestECSOverrideSetByRuleOrLua(DNSDistTest):
    """
    dnsdist is configured to set the EDNS0 Client Subnet
    option without overriding an existing one, but we
    force the overriding via SetECSOverrideAction() or Lua.
    """

    _config_template = """
    setECSOverride(false)
    setECSSourcePrefixV4(24)
    setECSSourcePrefixV6(56)
    newServer{address="127.0.0.1:%s", useClientSubnet=true}
    addAction(SuffixMatchNodeRule("overridden.ecsrules.tests.powerdns.com."), SetECSOverrideAction(true))
    function overrideECSViaLua(dq)
        dq.ecsOverride = true
        return DNSAction.None, ""
    end
    addAction("overriddenvialua.ecsrules.tests.powerdns.com.", LuaAction(overrideECSViaLua))
    """

    def testWithECSOverrideNotSet(self):
        """
        ECS Override: not set via Lua or a rule
        """
        name = 'notoverridden.ecsrules.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=4096, options=[ecso])
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.checkQueryEDNSWithECS(query, receivedQuery)
            self.checkResponseEDNSWithECS(response, receivedResponse)

    def testWithECSOverrideSetViaRule(self):
        """
        ECS Override: set with a rule
        """
        name = 'overridden.ecsrules.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 24)
        rewrittenEcso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[rewrittenEcso])
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=4096, options=[rewrittenEcso])
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseEDNSWithECS(response, receivedResponse)

    def testWithECSOverrideSetViaLua(self):
        """
        ECS Override: set via Lua
        """
        name = 'overriddenvialua.ecsrules.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 24)
        rewrittenEcso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[rewrittenEcso])
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=4096, options=[rewrittenEcso])
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseEDNSWithECS(response, receivedResponse)

class TestECSPrefixLengthSetByRuleOrLua(DNSDistTest):
    """
    dnsdist is configured to set the EDNS0 Client Subnet
    option with a prefix length of 24 for IPv4 and 56 for IPv6,
    but we override that to 32 and 128 via SetECSPrefixLengthAction() or Lua.
    """

    _config_template = """
    setECSOverride(false)
    setECSSourcePrefixV4(24)
    setECSSourcePrefixV6(56)
    newServer{address="127.0.0.1:%s", useClientSubnet=true}
    addAction(SuffixMatchNodeRule("overriddenprefixlength.ecsrules.tests.powerdns.com."), SetECSPrefixLengthAction(32, 128))
    function overrideECSPrefixLengthViaLua(dq)
        dq.ecsPrefixLength = 32
        return DNSAction.None, ""
    end
    addAction("overriddenprefixlengthvialua.ecsrules.tests.powerdns.com.", LuaAction(overrideECSPrefixLengthViaLua))
    """

    def testWithECSPrefixLengthNotOverridden(self):
        """
        ECS Prefix Length: not overridden via Lua or a rule
        """
        name = 'notoverriddenprefixlength.ecsrules.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, options=[ecso], payload=512)
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=4096, options=[ecso])
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseNoEDNS(expectedResponse, receivedResponse)

    def testWithECSPrefixLengthOverriddenViaRule(self):
        """
        ECS Prefix Length: overridden with a rule
        """
        name = 'overriddenprefixlength.ecsrules.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 32)
        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, options=[ecso], payload=512)
        response = dns.message.make_response(expectedQuery)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseNoEDNS(expectedResponse, receivedResponse)

    def testWithECSPrefixLengthOverriddenViaLua(self):
        """
        ECS Prefix Length: overridden via Lua
        """
        name = 'overriddenprefixlengthvialua.ecsrules.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 32)
        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, options=[ecso], payload=512)
        response = dns.message.make_response(expectedQuery)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseNoEDNS(expectedResponse, receivedResponse)

class TestECSPrefixSetByRule(DNSDistTest):
    """
    dnsdist is configured to set the EDNS0 Client Subnet
    option for incoming queries to the actual source IP,
    but we override it for some queries via SetECSAction().
    """

    _config_template = """
    setECSOverride(false)
    setECSSourcePrefixV4(32)
    setECSSourcePrefixV6(128)
    newServer{address="127.0.0.1:%s", useClientSubnet=true}
    addAction(SuffixMatchNodeRule("setecsaction.ecsrules.tests.powerdns.com."), SetECSAction("192.0.2.1/32"))
    """

    def testWithRegularECS(self):
        """
        ECS Prefix: not set
        """
        name = 'notsetecsaction.ecsrules.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 32)
        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, options=[ecso], payload=512)
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=4096, options=[ecso])
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseNoEDNS(expectedResponse, receivedResponse)

    def testWithECSSetByRule(self):
        """
        ECS Prefix: set with SetECSAction
        """
        name = 'setecsaction.ecsrules.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, options=[ecso], payload=512)
        response = dns.message.make_response(expectedQuery)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
            self.checkResponseNoEDNS(expectedResponse, receivedResponse)
