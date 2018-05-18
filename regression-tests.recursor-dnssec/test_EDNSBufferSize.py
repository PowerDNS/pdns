import dns
import os
import socket
import struct
import threading
import time

from recursortests import RecursorTest
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

ednsBufferReactorRunning = False

class EDNSBufferTest(RecursorTest):
    """
    The tests derived from this one test several truncation related issues.
    As an overview, this is what can be tested:

        udp-truncation-threshold      edns-outgoing-bufsize
                  |                           |
    +------+      v      +----------+         v             +------------+
    | stub | <=========> | recursor | <===================> | responders |
    +------+             +----------+                       +------------+
                 ^
                 |
      client bufsize (stub => recursor)
     bufsize to client (recursor => stub)

    The subclasses will test the following scenarios:

    test | udp-trunc | edns-outgoing | client bufsize | response size   | result to client | bufsize to client |
    -----+-----------+---------------+----------------+-----------------+------------------+-------------------+
     01  | 1680      | 1680          | 4096           | 1680 (inc EDNS) | 1680 (inc EDNS)  | 1680              |
     02  | 1680      | 1680          | 1679           | 1680 (inc EDNS) | TC (+EDNS)       | 1680              |
     03  | 1680      | 1681          | 4096           | 1681 (inc EDNS) | TC (+EDNS)       | 1680              |
     04  | 1680      | 1679          | 4096           | 1679 (inc EDNS) | 1679 (inc EDNS)  | 1680              |
     05  | 1680      | 1680          | 1680           | 1680 (inc EDNS) | 1680 (inc EDNS)  | 1680              |
     06  | 1680      | 1680          | 512 (No EDNS)  | 512 (+EDNS)     | 512 (no EDNS)    | (no EDNS)         |
     07  | 1680      | 1680          | 512 (No EDNS)  | 513 (+EDNS)     | TC (no EDNS)     | (no EDNS)         |
     08  | 1680      | 1680          | 511            | 501 (+EDNS)     | 512 (inc EDNS)   | 1680              |

    The qname is $testnum.edns-tests.example.
    """
    _confdir = 'EDNSBuffer'
    _udpTruncationThreshold = 1680
    _ednsOutgoingBufsize = 1680
    _qnameSuffix = '.edns-tests.example.'

    _config_template = """
forward-zones=edns-tests.example=%s.22
udp-truncation-threshold=%d
edns-outgoing-bufsize=%d
    """ % (os.environ['PREFIX'], _udpTruncationThreshold, _ednsOutgoingBufsize)

    @classmethod
    def startResponders(cls):
        global ednsBufferReactorRunning
        print("Launching responders..")

        address = cls._PREFIX + '.22'
        port = 53

        if not ednsBufferReactorRunning:
            reactor.listenUDP(port, UDPLargeResponder(), interface=address)
            ednsBufferReactorRunning = True

        if not reactor.running:
            cls._UDPResponder = threading.Thread(
                name='UDP Responder', target=reactor.run, args=(False,))
            cls._UDPResponder.setDaemon(True)
            cls._UDPResponder.start()

    def getMessage(self, testnum, payload=0):
        do_edns = payload > 0
        return dns.message.make_query(testnum + self._qnameSuffix, 'TXT', 'IN',
                                      use_edns=do_edns, payload=payload)

    def checkResponseContent(self, rawResponse, value, size, txt_final):
        """
        Tests the rawResponse (bytes that represent the DNS packet) has size
        number of bytes. And that the content of all TXT records is of value
        and has total_txt_val characters.
        """
        response = dns.message.from_wire(rawResponse)

        self.assertEquals(len(rawResponse), size)
        self.assertRcodeEqual(response, dns.rcode.NOERROR)

        self.assertMessageHasFlags(response, ['QR', 'RD', 'RA'])

        for record in response.answer:
            self.assertEquals(record.rdtype, dns.rdatatype.TXT)
            for part in record:
                for string in part.strings:
                    self.assertTrue(len(string) == 255 or
                                    len(string) == txt_final)

    def checkTruncatedResponse(self, message):
        self.assertMessageHasFlags(message, ['QR', 'RD', 'RA', 'TC'])

    def checkEDNS(self, message, bufsize=0):
        """
        Checks that the DNSMessage message has EDNS if bufsize > 0 and that
        the buffer size is correct.
        """
        if bufsize > 0:
            self.assertEqual(message.edns, 0)
            self.assertEqual(message.payload, bufsize)
        else:
            self.assertEqual(message.edns, -1)


class EDNSBufferTest16801680(EDNSBufferTest):
    """
    Runs test cases 1, 2, 5, 6, 7, 8
    """

    def testEdnsBufferTestCase01(self):
        query = self.getMessage('01', 4096)
        for _ in range(10):
            raw = self.sendUDPQuery(query, decode=False)
            self.checkResponseContent(raw, 'A',
                                      self._udpTruncationThreshold, 9)
            message = dns.message.from_wire(raw)
            self.checkEDNS(message, 512)

    def testEdnsBufferTestCase02(self):
        query = self.getMessage('02', 1679)
        for _ in range(10):
            message = self.sendUDPQuery(query)
            self.checkTruncatedResponse(message)
            self.checkEDNS(message, 512)

    def testEdnsBufferTestCase05(self):
        query = self.getMessage('05', 1680)
        for _ in range(10):
            raw = self.sendUDPQuery(query, decode=False)
            self.checkResponseContent(raw, 'E',
                                      self._udpTruncationThreshold, 9)
            message = dns.message.from_wire(raw)
            self.checkEDNS(message, 512)

    def testEdnsBufferTestCase06(self):
        query = self.getMessage('06', 0)
        for _ in range(10):
            raw = self.sendUDPQuery(query, decode=False)
            self.checkResponseContent(raw, 'F', 512, 192)
            message = dns.message.from_wire(raw)
            self.checkEDNS(message, 0)

    def testEdnsBufferTestCase07(self):
        query = self.getMessage('07', 0)
        for _ in range(10):
            message = self.sendUDPQuery(query)
            self.checkTruncatedResponse(message)
            self.checkEDNS(message, 0)

    def testEdnsBufferTestCase08(self):
        query = self.getMessage('08', 511)
        for _ in range(10):
            raw = self.sendUDPQuery(query, decode=False)
            self.checkResponseContent(raw, 'H', 512, 181)
            message = dns.message.from_wire(raw)
            self.checkEDNS(message, 512)

class EDNSBufferTest16801681(EDNSBufferTest):
    """
    Runs test case 3
    """
    _confdir = 'EDNSBuffer16801681'
    _udpTruncationThreshold = 1680
    _ednsOutgoingBufsize = 1681
    _qnameSuffix = '.edns-tests.example.'

    _config_template = """
forward-zones=edns-tests.example=%s.22
udp-truncation-threshold=%d
edns-outgoing-bufsize=%d
    """ % (os.environ['PREFIX'], _udpTruncationThreshold, _ednsOutgoingBufsize)

    def testEdnsBufferTestCase03(self):
        query = self.getMessage('03', 4096)
        for _ in range(10):
            message = self.sendUDPQuery(query)
            self.checkTruncatedResponse(message)
            self.checkEDNS(message, 512)


class EDNSBufferTest16801679(EDNSBufferTest):
    """
    Runs test case 4
    """
    _confdir = 'EDNSBuffer16801679'
    _udpTruncationThreshold = 1680
    _ednsOutgoingBufsize = 1679
    _qnameSuffix = '.edns-tests.example.'

    _config_template = """
forward-zones=edns-tests.example=%s.22
udp-truncation-threshold=%d
edns-outgoing-bufsize=%d
    """ % (os.environ['PREFIX'], _udpTruncationThreshold, _ednsOutgoingBufsize)

    def testEdnsBufferTestCase04(self):
        query = self.getMessage('04', 4096)
        for _ in range(10):
            raw = self.sendUDPQuery(query, decode=False)
            self.checkResponseContent(raw, 'D',
                                      self._ednsOutgoingBufsize, 8)
            message = dns.message.from_wire(raw)
            self.checkEDNS(message, 512)


class UDPLargeResponder(DatagramProtocol):
    def datagramReceived(self, datagram, address):
        request = dns.message.from_wire(datagram)
        # The outgoing packet should be EDNS buffersize bytes
        packet_size = request.payload

        testnum = int(str(request.question[0].name).split('.')[0])

        # Unless we have special tests
        if testnum == 6:
            packet_size = 512 + 11
        if testnum == 7:
            packet_size = 513 + 11
        if testnum == 8:
            packet_size = 501 + 11

        # An EDNS(0) RR without options is 11 bytes:
        # NAME:  1
        # TYPE:  2
        # CLASS: 2
        # TTL:   4
        # RDLEN: 2
        # RDATA: 0
        packet_size -= 11

        # But the header also counts, which is 12 bytes
        packet_size -= 12

        # The packet has a question section
        packet_size -= 27

        # Make the response
        response = dns.message.make_response(request)
        # This is an authoritative answer
        response.flags |= dns.flags.AA
        # We pretend to do EDNS with a 4096 buffer size
        response.edns = 0
        response.payload = 4096

        # What we use to fill the TXT records
        # Test number + 64, so 01 = 'A', 02 = 'B' etc...
        value = chr(testnum + 64)

        # Each pre-RDATA answer RR is 12 bytes
        # NAME:  2 (ptr to begin of packet, 0xC00C)
        # TYPE:  2
        # CLASS: 2
        # TTL:   4
        # RDLEN: 2
        while packet_size > 0:
            # Remove the pre-RDATA length
            packet_size -= 12
            # And the TXT size indicator (first byte in the TXT record)
            packet_size -= 1
            txt_size = min(packet_size, 255)
            answer = dns.rrset.from_text(request.question[0].name,
                                         0, dns.rdataclass.IN, 'TXT',
                                         value*txt_size)

            response.answer.append(answer)
            packet_size -= txt_size

        assert(packet_size == 0)

        self.transport.write(response.to_wire(max_size=65535), address)
