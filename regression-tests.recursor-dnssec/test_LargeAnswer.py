import dns
import os
import socket
import struct
import threading
import time

from recursortests import RecursorTest
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

largeReactorRunning = False

class LargeAnswerTest(RecursorTest):
    """
    This test makes sure that we correctly process an answer matching our exact
    udp-truncation-threshold buffer size.
    """
    _confdir = 'LargeAnswer'
    _udpTruncationThreshold = 1680

    _config_template = """
forward-zones=large-answer.example=%s.22
udp-truncation-threshold=%d
    """ % (os.environ['PREFIX'], _udpTruncationThreshold)

    @classmethod
    def startResponders(cls):
        global largeReactorRunning
        print("Launching responders..")

        address = cls._PREFIX + '.22'
        port = 53

        if not largeReactorRunning:
            reactor.listenUDP(port, UDPLargeResponder(), interface=address)
            largeReactorRunning = True

        if not reactor.running:
            cls._UDPResponder = threading.Thread(name='UDP Responder', target=reactor.run, args=(False,))
            cls._UDPResponder.setDaemon(True)
            cls._UDPResponder.start()

    def checkResponseContent(self, rawResponse, value):
       self.assertEquals(len(rawResponse), self._udpTruncationThreshold)
       response = dns.message.from_wire(rawResponse)

       self.assertRcodeEqual(response, dns.rcode.NOERROR)
       self.assertFalse(response.flags & dns.flags.TC)

       for record in response.answer:
           self.assertEquals(record.rdtype, dns.rdatatype.TXT)
           for part in record:
               for string in part.strings:
                   self.assertTrue(len(string) == 255 or len(string) == 16)
                   for c in string:
                       self.assertEquals(c, value)

    def testLargeAnswer(self):
        # why the same query 10 times, do you ask? because if we are reading from
        # unintialized buffer memory, there is small risk that we find exactly the
        # value we expected by chance so let's  massage our buffer a bit
        query = dns.message.make_query('AAAA.large-answer.example.', 'TXT', 'IN', use_edns=True, payload=4096)
        for _ in range(10):
            raw = self.sendUDPQuery(query, decode=False)
            self.checkResponseContent(raw, 'A')

        query = dns.message.make_query('ZZZZ.large-answer.example.', 'TXT', 'IN', use_edns=True, payload=4096)
        for _ in range(10):
            raw = self.sendUDPQuery(query, decode=False)
            self.checkResponseContent(raw, 'Z')

class UDPLargeResponder(DatagramProtocol):

    def datagramReceived(self, datagram, address):
        request = dns.message.from_wire(datagram)

        response = dns.message.make_response(request)
        response.use_edns(edns=False)
        response.flags |= dns.flags.AA

        if request.question[0].name == dns.name.from_text('AAAA.large-answer.example.'):
            value = 'A'
        else:
            value = 'Z'

        answer = dns.rrset.from_text(request.question[0].name, 0, dns.rdataclass.IN, 'TXT', value*255)
        for _ in range(6):
            response.answer.append(answer)
        answer = dns.rrset.from_text(request.question[0].name, 0, dns.rdataclass.IN, 'TXT', value*16)
        response.answer.append(answer)
        self.transport.write(response.to_wire(max_size=65535), address)
