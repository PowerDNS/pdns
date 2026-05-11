import dns
import os
import time
import subprocess

from twisted.internet.protocol import Factory
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

from recursortests import RecursorTest

malformedReactorRunning = False

class MalformedTest(RecursorTest):
    _confdir = 'Malformed'
    _config_template = """
recursor:
  forward_zones:
  - zone: malformed.example
    forwarders: [%s.27]
  devonly_regression_test_mode: true
packetcache:
  disable: true
logging:
    quiet: false
    common_errors: true
outgoing:
    dont_throttle_netmasks: ['127.0.0.27']
""" % (os.environ['PREFIX'])

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(MalformedTest, cls).generateRecursorYamlConfig(confdir)

    @classmethod
    def setUpClass(cls):
        cls.setUpSockets()

        cls.startResponders()

        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)

        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

        print("Launching tests..")

    @classmethod
    def startResponders(cls):
        global malformedReactorRunning
        print("Launching responders..")

        address1 = cls._PREFIX + '.27'
        port = 53

        if not malformedReactorRunning:
            reactor.listenUDP(port, UDPResponder(), interface=address1)
            reactor.listenTCP(port, TCPFactory(), interface=address1)
            malformedReactorRunning = True

        cls.startReactor()

    def getCache(self, name):
        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % 'configs/' + self._confdir,
                          'dump-cache',
                          '-']
        try:
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT, text=True)
            for i in ret.splitlines():
                pieces = i.split(' ')
                #print(pieces)
                if pieces[0] == name:
                    return pieces
            return []

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

    def testOKAnswer(self):
        # Case: rec gets a proper answer
        query = dns.message.make_query('proper.malformed.example.', 'A')
        expected = dns.rrset.from_text('proper.malformed.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def testQR0Answer(self):
        # Case: rec gets a QR=0 answer
        query = dns.message.make_query('qr0.malformed.example.', 'A')
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

    def testQR0PoisonAnswer(self):
        # Case: rec gets a QR=0 answer
        query = dns.message.make_query('qr0poison.malformed.example.', 'A')
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            lines = self.getCache("qr0poison.malformed.example")
            self.assertEqual(lines, [])
            self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

    def testHeaderOnlyAnswer(self):
        # Case: rec gets a header-only answer
        query = dns.message.make_query('headeronly.malformed.example.', 'A')
        res = self.sendUDPQuery(query)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

class UDPResponder(DatagramProtocol):

    def question(self, datagram, tcp=False):
        request = dns.message.from_wire(datagram)

        response = dns.message.make_response(request)
        response.flags = dns.flags.AA + dns.flags.QR

        question = request.question[0]

        # Case: send proper answer back
        if question.name == dns.name.from_text('proper.malformed.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('proper.malformed.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            response.answer.append(answer)

        # Case: send qr=0 answer back
        elif question.name == dns.name.from_text('qr0.malformed.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('qr0.malformed.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            response.answer.append(answer)
            response.flags &= ~dns.flags.QR

        # Case: send qr=0 poison answer back
        elif question.name == dns.name.from_text('qr0poison.malformed.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('www.poision.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            response.answer.append(answer)
            response.flags &= ~dns.flags.QR

        # Case: send header only back
        elif dns.name.from_text('headeronly.malformed.example.') and question.rdtype == dns.rdatatype.A:
            response.question = []
            response.use_edns(False)
        else:
            self.assertEqual(0, 1)
        return response.to_wire()

    def datagramReceived(self, datagram, address):
        response = self.question(datagram)
        self.transport.write(response, address)

class TCPResponder(Protocol):
    def dataReceived(self, data):
        handler = UDPResponder()
        response = handler.question(data[2:], True)
        length = len(response)
        header = length.to_bytes(2, 'big')
        self.transport.write(header + response)

class TCPFactory(Factory):
    def buildProtocol(self, addr):
        return TCPResponder()
