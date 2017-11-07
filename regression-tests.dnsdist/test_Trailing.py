#!/usr/bin/env python
import threading
import dns
from dnsdisttests import DNSDistTest

class TestTrailing(DNSDistTest):

    # this test suite uses a different responder port
    # because, contrary to the other ones, its
    # responders allow trailing data and we don't want
    # to mix things up.
    _testServerPort = 5360
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    addAction(AndRule({QTypeRule(dnsdist.AAAA), TrailingDataRule()}), DropAction())
    """
    @classmethod
    def startResponders(cls):
        print("Launching responders..")

        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue, True])
        cls._UDPResponder.setDaemon(True)
        cls._UDPResponder.start()

        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue, True])
        cls._TCPResponder.setDaemon(True)
        cls._TCPResponder.start()

    def testTrailingAllowed(self):
        """
        Trailing: Allowed

        """
        name = 'allowed.trailing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        raw = query.to_wire()
        raw = raw + 'A'* 20
        (receivedQuery, receivedResponse) = self.sendUDPQuery(raw, response, rawQuery=True)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(raw, response, rawQuery=True)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testTrailingDropped(self):
        """
        Trailing: dropped

        """
        name = 'dropped.trailing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')

        raw = query.to_wire()
        raw = raw + 'A'* 20

        (_, receivedResponse) = self.sendUDPQuery(raw, response=None, rawQuery=True)
        self.assertEquals(receivedResponse, None)
        (_, receivedResponse) = self.sendTCPQuery(raw, response=None, rawQuery=True)
        self.assertEquals(receivedResponse, None)
