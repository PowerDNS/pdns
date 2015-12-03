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
    DNSdist is configured to add the EDNS0 Client Subnet
    option, but only if it's not already present in the
    original query.
    """

    _dnsDistPort = 5340
    _config_template = """
    truncateTC(true)
    block=newDNSName("powerdns.org.")
    function blockFilter(remote, qname, qtype, dh)
        if(qname:isPartOf(block))
        then
            print("Blocking *.powerdns.org")
            return true
        end
        return false
    end
    newServer{address="127.0.0.1:%s", useClientSubnet=true}
    """

    _dnsdistcmd = (os.environ['DNSDISTBIN'] + " -C dnsdist_ecs_no_override.conf --acl 127.0.0.1/32 -l 127.0.0.1:" + str(_dnsDistPort)).split()

    @classmethod
    def startDNSDist(cls, shutUp=True):
        print("Launching dnsdist..")
        with open('dnsdist_ecs_no_override.conf', 'w') as conf:
            conf.write(cls._config_template % str(cls._testServerPort))

        print(' '.join(cls._dnsdistcmd))
        if shutUp:
            with open(os.devnull, 'w') as fdDevNull:
                cls._dnsdist = subprocess.Popen(cls._dnsdistcmd, close_fds=True, stdout=fdDevNull, stderr=fdDevNull)
        else:
            cls._dnsdist = subprocess.Popen(cls._dnsdistcmd, close_fds=True)

        time.sleep(1)

        if cls._dnsdist.poll() is not None:
            cls._dnsdist.terminate()
            cls._dnsdist.wait()
            sys.exit(cls._dnsdist.returncode)

    def testWithoutEDNS(self):
        """
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
    DNSdist is configured to add the EDNS0 Client Subnet
    option, overwriting any existing value.
    """

    _dnsDistPort = 5340
    _config_template = """
    truncateTC(true)
    block=newDNSName("powerdns.org.")
    function blockFilter(remote, qname, qtype, dh)
        if(qname:isPartOf(block))
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

    _dnsdistcmd = (os.environ['DNSDISTBIN'] + " -C dnsdist_ecs_override.conf --acl 127.0.0.1/32 -l 127.0.0.1:" + str(_dnsDistPort)).split()

    @classmethod
    def startDNSDist(cls, shutUp=True):
        print("Launching dnsdist..")
        with open('dnsdist_ecs_override.conf', 'w') as conf:
            conf.write(cls._config_template % str(cls._testServerPort))

        print(' '.join(cls._dnsdistcmd))
        if shutUp:
            with open(os.devnull, 'w') as fdDevNull:
                cls._dnsdist = subprocess.Popen(cls._dnsdistcmd, close_fds=True, stdout=fdDevNull, stderr=fdDevNull)
        else:
            cls._dnsdist = subprocess.Popen(cls._dnsdistcmd, close_fds=True)

        time.sleep(1)

        if cls._dnsdist.poll() is not None:
            cls._dnsdist.terminate()
            cls._dnsdist.wait()
            sys.exit(cls._dnsdist.returncode)

    def testWithoutEDNS(self):
        """
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

    def testWithEDNSECS(self):
        """
        Send a query with EDNS and a crafted ECS value.
        Check that the query received by the responder
        has an overwritten ECS value (not the initial one)
        and that the response received from dnsdist contains
        an EDNS pseudo-RR.
        """
        name = 'withednsecs.overriden.ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('1.2.3.4', 24)
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
