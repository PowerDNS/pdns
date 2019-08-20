#!/usr/bin/env python
import threading
import dns
from dnsdisttests import DNSDistTest

class TestAXFR(DNSDistTest):

    # this test suite uses a different responder port
    # because, contrary to the other ones, its
    # TCP responder allows multiple responses and we don't want
    # to mix things up.
    _testServerPort = 5370
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    """
    @classmethod
    def startResponders(cls):
        print("Launching responders..")

        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder.setDaemon(True)
        cls._UDPResponder.start()
        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, True])
        cls._TCPResponder.setDaemon(True)
        cls._TCPResponder.start()

    def testOneMessageAXFR(self):
        """
        AXFR: One message
        """
        name = 'one.axfr.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AXFR', 'IN')
        response = dns.message.make_response(query)
        soa = dns.rrset.from_text(name,
                                  60,
                                  dns.rdataclass.IN,
                                  dns.rdatatype.SOA,
                                  'ns.' + name + ' hostmaster.' + name + ' 1 3600 3600 3600 60')
        response.answer.append(soa)
        response.answer.append(dns.rrset.from_text(name,
                                                   60,
                                                   dns.rdataclass.IN,
                                                   dns.rdatatype.A,
                                                   '192.0.2.1'))
        response.answer.append(soa)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

    def testOneNoSOAAXFR(self):
        """
        AXFR: One message, no SOA
        """
        name = 'onenosoa.axfr.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AXFR', 'IN')
        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text(name,
                                                   60,
                                                   dns.rdataclass.IN,
                                                   dns.rdatatype.A,
                                                   '192.0.2.1'))

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

    def testFourMessagesAXFR(self):
        """
        AXFR: Four messages
        """
        name = 'four.axfr.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AXFR', 'IN')
        responses = []
        soa = dns.rrset.from_text(name,
                                  60,
                                  dns.rdataclass.IN,
                                  dns.rdatatype.SOA,
                                  'ns.' + name + ' hostmaster.' + name + ' 1 3600 3600 3600 60')
        response = dns.message.make_response(query)
        response.answer.append(soa)
        responses.append(response)

        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text(name,
                                                   60,
                                                   dns.rdataclass.IN,
                                                   dns.rdatatype.A,
                                                   '192.0.2.1'))
        responses.append(response)

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '2001:DB8::1')
        response.answer.append(rrset)
        responses.append(response)

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    'dummy')
        response.answer.append(rrset)
        responses.append(response)

        response = dns.message.make_response(query)
        response.answer.append(soa)
        responses.append(response)

        (receivedQuery, receivedResponses) = self.sendTCPQueryWithMultipleResponses(query, responses)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(len(receivedResponses), len(responses))

    def testFourNoFinalSOAAXFR(self):
        """
        AXFR: Four messages, no final SOA
        """
        name = 'fournosoa.axfr.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AXFR', 'IN')
        responses = []
        soa = dns.rrset.from_text(name,
                                  60,
                                  dns.rdataclass.IN,
                                  dns.rdatatype.SOA,
                                  'ns.' + name + ' hostmaster.' + name + ' 1 3600 3600 3600 60')
        response = dns.message.make_response(query)
        response.answer.append(soa)
        responses.append(response)

        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text(name,
                                                   60,
                                                   dns.rdataclass.IN,
                                                   dns.rdatatype.A,
                                                   '192.0.2.1'))
        responses.append(response)

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '2001:DB8::1')
        response.answer.append(rrset)
        responses.append(response)

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    'dummy')
        response.answer.append(rrset)
        responses.append(response)

        (receivedQuery, receivedResponses) = self.sendTCPQueryWithMultipleResponses(query, responses)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(len(receivedResponses), len(responses))

    # def testFourNoFirstSOAAXFR(self):
    #     """
    #     AXFR: Four messages, no SOA in the first one
    #     """
    #     name = 'fournosoainfirst.axfr.tests.powerdns.com.'
    #     query = dns.message.make_query(name, 'AXFR', 'IN')
    #     responses = []
    #     soa = dns.rrset.from_text(name,
    #                               60,
    #                               dns.rdataclass.IN,
    #                               dns.rdatatype.SOA,
    #                               'ns.' + name + ' hostmaster.' + name + ' 1 3600 3600 3600 60')
    #     response = dns.message.make_response(query)
    #     response.answer.append(dns.rrset.from_text(name,
    #                                                60,
    #                                                dns.rdataclass.IN,
    #                                                dns.rdatatype.A,
    #                                                '192.0.2.1'))
    #     responses.append(response)

    #     response = dns.message.make_response(query)
    #     rrset = dns.rrset.from_text(name,
    #                                 60,
    #                                 dns.rdataclass.IN,
    #                                 dns.rdatatype.AAAA,
    #                                 '2001:DB8::1')
    #     response.answer.append(soa)
    #     response.answer.append(rrset)
    #     responses.append(response)

    #     response = dns.message.make_response(query)
    #     rrset = dns.rrset.from_text('dummy.' + name,
    #                                 60,
    #                                 dns.rdataclass.IN,
    #                                 dns.rdatatype.AAAA,
    #                                 '2001:DB8::1')
    #     response.answer.append(rrset)
    #     responses.append(response)

    #     response = dns.message.make_response(query)
    #     rrset = dns.rrset.from_text(name,
    #                                 60,
    #                                 dns.rdataclass.IN,
    #                                 dns.rdatatype.TXT,
    #                                 'dummy')
    #     response.answer.append(rrset)
    #     response.answer.append(soa)
    #     responses.append(response)

    #     (receivedQuery, receivedResponses) = self.sendTCPQueryWithMultipleResponses(query, responses)
    #     receivedQuery.id = query.id
    #     self.assertEqual(query, receivedQuery)
    #     self.assertEqual(len(receivedResponses), 1)

    # def testFourLastSOAInSecondAXFR(self):
    #     """
    #     AXFR: Four messages, SOA in the first one and the second one
    #     """
    #     name = 'foursecondsoainsecond.axfr.tests.powerdns.com.'
    #     query = dns.message.make_query(name, 'AXFR', 'IN')
    #     responses = []
    #     soa = dns.rrset.from_text(name,
    #                               60,
    #                               dns.rdataclass.IN,
    #                               dns.rdatatype.SOA,
    #                               'ns.' + name + ' hostmaster.' + name + ' 1 3600 3600 3600 60')

    #     response = dns.message.make_response(query)
    #     response.answer.append(soa)
    #     response.answer.append(dns.rrset.from_text(name,
    #                                                60,
    #                                                dns.rdataclass.IN,
    #                                                dns.rdatatype.A,
    #                                                '192.0.2.1'))
    #     responses.append(response)

    #     response = dns.message.make_response(query)
    #     response.answer.append(soa)
    #     rrset = dns.rrset.from_text(name,
    #                                 60,
    #                                 dns.rdataclass.IN,
    #                                 dns.rdatatype.AAAA,
    #                                 '2001:DB8::1')
    #     response.answer.append(rrset)
    #     responses.append(response)

    #     response = dns.message.make_response(query)
    #     rrset = dns.rrset.from_text('dummy.' + name,
    #                                 60,
    #                                 dns.rdataclass.IN,
    #                                 dns.rdatatype.AAAA,
    #                                 '2001:DB8::1')
    #     response.answer.append(rrset)
    #     responses.append(response)

    #     response = dns.message.make_response(query)
    #     rrset = dns.rrset.from_text(name,
    #                                 60,
    #                                 dns.rdataclass.IN,
    #                                 dns.rdatatype.TXT,
    #                                 'dummy')
    #     response.answer.append(rrset)
    #     responses.append(response)

    #     (receivedQuery, receivedResponses) = self.sendTCPQueryWithMultipleResponses(query, responses)
    #     receivedQuery.id = query.id
    #     self.assertEqual(query, receivedQuery)
    #     self.assertEqual(len(receivedResponses), 2)
