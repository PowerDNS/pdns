#!/usr/bin/env python
import threading
import clientsubnetoption
import dns
from dnsdisttests import DNSDistTest

def responseCallback(request):
    if len(request.question) != 1:
        print("Skipping query with question count %d" % (len(request.question)))
        return None
    healthCheck = str(request.question[0].name).endswith('a.root-servers.net.')
    if healthCheck:
        response = dns.message.make_response(request)
        return response.to_wire()
    # now we create a broken response
    response = dns.message.make_response(request)
    ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 32)
    response.use_edns(edns=True, payload=4096, options=[ecso])
    rrset = dns.rrset.from_text(request.question[0].name,
                                3600,
                                dns.rdataclass.IN,
                                dns.rdatatype.A,
                                '127.0.0.1')
    response.answer.append(rrset)
    raw = response.to_wire()
    # first label length of this rrset is at 12 (dnsheader) + length(qname) + 2 (leading label length + trailing 0) + 2 (qtype) + 2 (qclass)
    offset = 12 + len(str(request.question[0].name)) + 2 + 2 + 2
    altered = raw[:offset] + b'\xff' + raw[offset+1:]
    return altered

class TestBrokenAnswerECS(DNSDistTest):

    # this test suite uses a different responder port
    # because, contrary to the other ones, its
    # responders send raw, broken data
    _testServerPort = 5400
    _config_template = """
    setECSSourcePrefixV4(32)
    newServer{address="127.0.0.1:%s", useClientSubnet=true}
    """
    @classmethod
    def startResponders(cls):
        print("Launching responders..")

        # Returns broken data for non-healthcheck queries
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, responseCallback])
        cls._UDPResponder.setDaemon(True)
        cls._UDPResponder.start()

        # Returns broken data for non-healthcheck queries
        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, responseCallback])
        cls._TCPResponder.setDaemon(True)
        cls._TCPResponder.start()

    def testUDPWithInvalidAnswer(self):
        """
        Broken Answer: Invalid UDP answer with ECS
        """
        name = 'invalid-ecs-udp.broken-answer.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertFalse(receivedQuery)
        self.assertFalse(receivedResponse)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertFalse(receivedQuery)
        self.assertFalse(receivedResponse)

    def testTCPWithInvalidAnswer(self):
        """
        Broken Answer: Invalid TCP answer with ECS
        """
        name = 'invalid-ecs-tcp.broken-answer.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertFalse(receivedQuery)
        self.assertFalse(receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertFalse(receivedQuery)
        self.assertFalse(receivedResponse)
