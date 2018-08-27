#!/usr/bin/env python
import threading
import dns
from dnsdisttests import DNSDistTest

class TestTrailingDataToBackend(DNSDistTest):

    # this test suite uses a different responder port
    # because, contrary to the other ones, its
    # responders allow trailing data and we don't want
    # to mix things up.
    _testServerPort = 5360
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    """
    @classmethod
    def startResponders(cls):
        print("Launching responders..")

        # Respond SERVFAIL to queries with trailing data.
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue, dns.rcode.SERVFAIL])
        cls._UDPResponder.setDaemon(True)
        cls._UDPResponder.start()

        # Respond SERVFAIL to queries with trailing data.
        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue, dns.rcode.SERVFAIL])
        cls._TCPResponder.setDaemon(True)
        cls._TCPResponder.start()

    def testTrailingPassthrough(self):
        """
        Trailing data: Pass through

        """
        name = 'passthrough.trailing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.SERVFAIL)

        raw = query.to_wire()
        raw = raw + b'A'* 20

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            # (receivedQuery, receivedResponse) = self.sendUDPQuery(raw, response, rawQuery=True)
            # (receivedQuery, receivedResponse) = self.sendTCPQuery(raw, response, rawQuery=True)
            (receivedQuery, receivedResponse) = sender(raw, response, rawQuery=True)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(receivedQuery, query)
            self.assertEquals(receivedResponse, expectedResponse)

class TestTrailingDataToDnsdist(DNSDistTest):
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    addAction(AndRule({QNameRule("dropped.trailing.tests.powerdns.com."), TrailingDataRule()}), DropAction())
    """

    def testTrailingDropped(self):
        """
        Trailing data: Drop query

        """
        name = 'dropped.trailing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        raw = query.to_wire()
        raw = raw + b'A'* 20

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)

            # Verify that queries with no trailing data make it through.
            # (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            # (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

            # Verify that queries with trailing data don't make it through.
            # (_, receivedResponse) = self.sendUDPQuery(raw, response, rawQuery=True)
            # (_, receivedResponse) = self.sendTCPQuery(raw, response, rawQuery=True)
            (_, receivedResponse) = sender(raw, response, rawQuery=True)
            self.assertEquals(receivedResponse, None)
