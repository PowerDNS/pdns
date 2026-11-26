#!/usr/bin/env python
import struct
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
        query.authority.append(
            dns.rrset.from_text(
                name,
                60,
                dns.rdataclass.IN,
                dns.rdatatype.SOA,
                "ns." + name + " hostmaster." + name + " 1 3600 3600 3600 60",
            )
        )
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

    def testEmptyIXFR(self):
        """
        IXFR: Empty IXFR
        """
        name = "empty.ixfr.tests.powerdns.com."
        query = dns.message.make_query(name, "IXFR", "IN")

        finalSoa = dns.rrset.from_text(
            name,
            60,
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            "ns." + name + " hostmaster." + name + " 3 3600 3600 3600 60",
        )

        query.authority.append(finalSoa)
        responses = []

        response = dns.message.make_response(query)
        response.answer.append(finalSoa)
        responses.append(response)

        # and we add a final, dummy TXT message that will
        # be sent by the backend but that dnsdist should not
        # pass along to the client
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.TXT, "dummy")
        response.answer.append(rrset)
        responses.append(response)

        (receivedQuery, receivedResponses) = self.sendTCPQueryWithMultipleResponses(query, responses)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(len(receivedResponses), len(responses) - 1)

    def testIXFRClientHasMostRecent(self):
        """
        IXFR: Client has more recent
        """
        name = "client-has-most-recent.ixfr.tests.powerdns.com."
        query = dns.message.make_query(name, "IXFR", "IN")

        clientSoa = dns.rrset.from_text(
            name,
            60,
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            "ns." + name + " hostmaster." + name + " 4 3600 3600 3600 60",
        )
        serverSoa = dns.rrset.from_text(
            name,
            60,
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            "ns." + name + " hostmaster." + name + " 3 3600 3600 3600 60",
        )

        query.authority.append(clientSoa)
        responses = []

        response = dns.message.make_response(query)
        response.answer.append(serverSoa)
        responses.append(response)

        # and we add a final, dummy TXT message that will
        # be sent by the backend but that dnsdist should not
        # pass along to the client
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.TXT, "dummy")
        response.answer.append(rrset)
        responses.append(response)

        (receivedQuery, receivedResponses) = self.sendTCPQueryWithMultipleResponses(query, responses)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(len(receivedResponses), len(responses) - 1)


class TestQueriesSharingAnXFRConnection(DNSDistTest):
    _testServerPort = pickAvailablePort()
    _heldXFRName = "held.xfr.tests.powerdns.com."
    _config_template = """
    -- one TCP worker so that both clients share its backend connection
    setMaxTCPClientThreads(1)
    -- more than one query in flight on the backend connection, or the XFR would own it
    newServer{address="127.0.0.1:%d", maxInFlight=100}
    """

    # the stock TCP responder serves one query per connection, so it cannot keep an XFR pending
    # while a second query shares the connection
    @classmethod
    def startResponders(cls):
        print("Launching responders..")

        cls._UDPResponder = threading.Thread(
            name="UDP Responder",
            target=cls.UDPResponder,
            args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue],
        )
        cls._UDPResponder.daemon = True
        cls._UDPResponder.start()
        cls._TCPResponder = threading.Thread(
            name="TCP Responder",
            target=cls.TCPResponder,
            args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, None, True],
        )
        cls._TCPResponder.daemon = True
        cls._TCPResponder.start()

    @classmethod
    def handleTCPConnection(cls, conn, _fromQueue, toQueue, *_):
        try:
            while True:
                query = cls.recvTCPResponseOverConnection(conn, useQueue=False, timeout=None)
                if not query:
                    break
                toQueue.put(query)
                responses = [dns.message.make_response(query)]
                if query.question[0].rdtype == dns.rdatatype.AXFR:
                    responses[0].set_rcode(dns.rcode.REFUSED)
                    if query.question[0].name.to_text() == cls._heldXFRName:
                        # the XFR ends only once a second query shares the connection, directly followed by its answer
                        sharingQuery = cls.recvTCPResponseOverConnection(conn, useQueue=False, timeout=None)
                        toQueue.put(sharingQuery)
                        responses.append(dns.message.make_response(sharingQuery))
                payload = b""
                for response in responses:
                    wire = response.to_wire()
                    payload += struct.pack("!H", len(wire)) + wire
                conn.sendall(payload)
        except (OSError, dns.exception.DNSException) as err:
            print(f"Error in the XFR TCP responder thread {err=}, {type(err)=}")
        finally:
            conn.close()

    def sendXFRQuery(self, name):
        query = dns.message.make_query(name, "AXFR", "IN", use_edns=False)
        conn = self.openTCPConnection()
        self.addCleanup(conn.close)
        self.sendTCPQueryOverConnection(conn, query)
        return conn

    def testQueryAfterRefusedXFRIsAnswered(self):
        """
        XFR: a query sent after a refused XFR has ended is answered
        """
        xfrConn = self.sendXFRQuery("axfr.xfr.tests.powerdns.com.")
        self.assertEqual(dns.rcode.REFUSED, self.recvTCPResponseOverConnection(xfrConn).rcode())

        query = dns.message.make_query("after.xfr.tests.powerdns.com.", "A", "IN", use_edns=False)
        expectedResponse = dns.message.make_response(query)
        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEqual(expectedResponse, receivedResponse)

    def testQueryInFlightDuringXFRIsAnswered(self):
        """
        XFR: a query in flight on the XFR's backend connection is answered when the XFR is refused
        """
        xfrConn = self.sendXFRQuery(self._heldXFRName)
        # the XFR must reach the backend first, or the next query gets a connection of its own
        xfrQuery = self._fromResponderQueue.get(True, self._queueTimeout)
        self.assertEqual(xfrQuery.question[0].rdtype, dns.rdatatype.AXFR)

        query = dns.message.make_query("during.xfr.tests.powerdns.com.", "A", "IN", use_edns=False)
        expectedResponse = dns.message.make_response(query)
        conn = self.openTCPConnection()
        self.addCleanup(conn.close)
        self.sendTCPQueryOverConnection(conn, query)

        # the backend sends the XFR's end only after reading the second query on that same connection
        (receivedQuery, response) = self.recvTCPResponseOverConnection(xfrConn, useQueue=True)
        self.assertEqual(dns.rcode.REFUSED, response.rcode())
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(expectedResponse, self.recvTCPResponseOverConnection(conn))
