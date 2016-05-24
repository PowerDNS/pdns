import dns
import socket
import copy
from recursortests import RecursorTest
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import threading

class testInterop(RecursorTest):
    _confdir = 'Interop'

    _config_template = """dnssec=validate"""

    def testFORMERR(self):
        """
        #3841, when we encounter a server that does not understands OPT records
        (or something else), we don't retry without EDNS in dnssec=validate mode
        """
        expected = dns.rrset.from_text('host1.insecure-formerr.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')

        query = dns.message.make_query('cname-to-formerr.secure.example.', 'A')
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)

    @classmethod
    def startResponders(cls):
        print("Launching responders..")

        address = cls._PREFIX + '.2'
        port = 53

        reactor.listenUDP(port, UDPResponder(), interface=address)

        cls._UDPResponder = threading.Thread(name='UDP Responder', target=reactor.run, args=(False,))
        cls._UDPResponder.setDaemon(True)
        cls._UDPResponder.start()

    @classmethod
    def tearDownResponders(cls):
        reactor.stop()

class UDPResponder(DatagramProtocol):
    def datagramReceived(self, datagram, address):
        request = dns.message.from_wire(datagram)

        response = dns.message.make_response(request)
        response.flags = dns.flags.AA + dns.flags.QR

        if request.edns != -1:
            response.set_rcode(dns.rcode.FORMERR)
            response.edns = -1
            response.additional = []
        else:
            answer = dns.rrset.from_text('host1.insecure-formerr.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            response.answer.append(answer)

        self.transport.write(response.to_wire(), address)
