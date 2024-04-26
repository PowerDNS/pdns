#!/usr/bin/env python
import threading
import time
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort

class TestAXFR(DNSDistTest):

    # this test suite uses a different responder port
    # because, contrary to the other ones, its
    # TCP responder allows multiple responses and we don't want
    # to mix things up.
    _testServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    """

    @classmethod
    def startResponders(cls):
        print("Launching responders..")

        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder.daemon = True
        cls._UDPResponder.start()
        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, True, None, None, True])
        cls._TCPResponder.daemon = True
        cls._TCPResponder.start()

    def setUp(self):
        # This function is called before every test
        super(TestAXFR, self).setUp()
        # make sure the TCP connection handlers from the previous test
        # are not going to read our queue
        time.sleep(1)

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

    def testThreePlusTrailingAXFR(self):
        """
        AXFR: Three messages including the final SOA, plus a trailing one
        """
        name = 'threeplustrailing.axfr.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AXFR', 'IN')
        responses = []
        soa = dns.rrset.from_text(name,
                                  60,
                                  dns.rdataclass.IN,
                                  dns.rdatatype.SOA,
                                  'ns.' + name + ' hostmaster.' + name + ' 1 3600 3600 3600 60')

        # the SOA starts the AXFR
        response = dns.message.make_response(query)
        response.answer.append(soa)
        responses.append(response)

        # one A
        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text(name,
                                                   60,
                                                   dns.rdataclass.IN,
                                                   dns.rdatatype.A,
                                                   '192.0.2.1'))
        responses.append(response)

        # one AAAA
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '2001:DB8::1')
        response.answer.append(rrset)
        responses.append(response)

        # one TXT then the SOA that ends the AXFR
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    "Some text")
        response.answer.append(rrset)
        response.answer.append(soa)
        responses.append(response)

        # and we add a final, dummy TXT message that will
        # be sent by the backend but that dnsdist should not
        # pass along to the client
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
        self.assertEqual(len(receivedResponses), len(responses) - 1)

    def testThreePlusTrailingIXFR(self):
        """
        IXFR: Three messages including the final SOA, plus a trailing one
        """
        name = 'threeplustrailing.ixfr.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AXFR', 'IN')
        responses = []

        finalSoa = dns.rrset.from_text(name,
                                       60,
                                       dns.rdataclass.IN,
                                       dns.rdatatype.SOA,
                                       'ns.' + name + ' hostmaster.' + name + ' 3 3600 3600 3600 60')

        # the final SOA starts the IXFR, with first an update from 1 to 2 (one removal, two additions)
        response = dns.message.make_response(query)
        response.answer.append(finalSoa)
        # update from 1 to 2
        response.answer.append(dns.rrset.from_text(name,
                                                   60,
                                                   dns.rdataclass.IN,
                                                   dns.rdatatype.SOA,
                                                   'ns.' + name + ' hostmaster.' + name + ' 1 3600 3600 3600 60'))
        # one removal
        response.answer.append(dns.rrset.from_text(name,
                                                   60,
                                                   dns.rdataclass.IN,
                                                   dns.rdatatype.A,
                                                   '192.0.2.1'))
        # then additions
        response.answer.append(dns.rrset.from_text(name,
                                                   60,
                                                   dns.rdataclass.IN,
                                                   dns.rdatatype.SOA,
                                                   'ns.' + name + ' hostmaster.' + name + ' 2 3600 3600 3600 60'))
        # new message in the middle of the additions
        responses.append(response)
        response = dns.message.make_response(query)

        response.answer.append(dns.rrset.from_text_list(name,
                                                        60,
                                                        dns.rdataclass.IN,
                                                        dns.rdatatype.A,
                                                        ['192.0.2.2', '192.0.2.3']))
        # done with 1 -> 2
        response.answer.append(dns.rrset.from_text(name,
                                                   60,
                                                   dns.rdataclass.IN,
                                                   dns.rdatatype.SOA,
                                                   'ns.' + name + ' hostmaster.' + name + ' 2 3600 3600 3600 60'))
        # new message
        responses.append(response)
        response = dns.message.make_response(query)

        # then upgrade to 3
        # no removals
        response.answer.append(finalSoa)

        # and one addition
        response.answer.append(dns.rrset.from_text(name,
                                                   60,
                                                   dns.rdataclass.IN,
                                                   dns.rdatatype.A,
                                                   '192.0.2.4'))
        # and the final SOA
        response.answer.append(finalSoa)
        responses.append(response)

        # and we add a final, dummy TXT message that will
        # be sent by the backend but that dnsdist should not
        # pass along to the client
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
        self.assertEqual(len(receivedResponses), len(responses) - 1)
