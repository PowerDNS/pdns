import dns
import socket
import os
import time

from twisted.internet.protocol import Factory
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

import clientsubnetoption
import cookiesoption

from recursortests import RecursorTest

cookieReactorRunning = False

class CookiesTest(RecursorTest):
    _confdir = 'Cookies'
    _config_template = """
recursor:
  forward_zones:
  - zone: cookies.example
    forwarders: [%s.25, %s.26]
outgoing:
  cookies: true""" % (os.environ['PREFIX'], os.environ['PREFIX'])

    _expectedCookies = 'no'
    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(CookiesTest, cls).generateRecursorYamlConfig(confdir)

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
    def tearDownClass(cls):
        cls.tearDownRecursor()

    @classmethod
    def startResponders(cls):
        global cookieReactorRunning
        print("Launching responders..")

        address1 = cls._PREFIX + '.25'
        address2 = cls._PREFIX + '.26'
        port = 53

        if not cookieReactorRunning:
            reactor.listenUDP(port, UDPResponder(), interface=address1)
            reactor.listenTCP(port, TCPFactory(), interface=address1)
            reactor.listenUDP(port, UDPResponder(), interface=address2)
            reactor.listenTCP(port, TCPFactory(), interface=address2)
            cookieReactorRunning = True

        cls.startReactor()

    def checkCookies(self, support, server='127.0.0.25'):
        confdir = os.path.join('configs', self._confdir)
        output = self.recControl(confdir, 'dump-cookies', '-')
        for line in output.splitlines():
            tokens = line.split()
            if tokens[0] != server:
                continue
            #print(tokens)
            self.assertEqual(len(tokens), 5)
            self.assertEqual(tokens[3], support)

    def testAuthDoesnotSendCookies(self):
        confdir = os.path.join('configs', self._confdir)
        # Case: rec does not get a cookie back
        expected = dns.rrset.from_text('a.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
        query = dns.message.make_query('a.cookies.example.', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkCookies('Unsupported')

    def testAuthRepliesWithCookies(self):
        confdir = os.path.join('configs', self._confdir)
        # Case: rec gets a proper client and server cookie back
        self.recControl(confdir, 'clear-cookies')
        query = dns.message.make_query('b.cookies.example.', 'A')
        expected = dns.rrset.from_text('b.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkCookies('Supported')

        # Case: we get a an correct client and server cookie back
        # We do not clear the cookie tables, so the old server cookie gets re-used
        query = dns.message.make_query('c.cookies.example.', 'A')
        expected = dns.rrset.from_text('c.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkCookies('Supported')

    def testAuthSendsIncorrectClientCookie(self):
        confdir = os.path.join('configs', self._confdir)
        # Case: rec gets a an incorrect client cookie back, we ignore that over TCP
        self.recControl(confdir, 'clear-cookies')
        query = dns.message.make_query('d.cookies.example.', 'A')
        expected = dns.rrset.from_text('d.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkCookies('Probing')

    def testAuthSendsBADCOOKIEOverUDP(self):
        confdir = os.path.join('configs', self._confdir)
        # Case: rec gets a BADCOOKIE, even on retry and should fall back to TCP
        self.recControl(confdir, 'clear-cookies')
        query = dns.message.make_query('e.cookies.example.', 'A')
        expected = dns.rrset.from_text('e.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkCookies('Supported')

    def testAuthSendsMalformedCookie(self):
        confdir = os.path.join('configs', self._confdir)
        # Case: rec gets a malformed cookie, should ignore packet
        self.recControl(confdir, 'clear-cookies')
        query = dns.message.make_query('f.cookies.example.', 'A')
        expected = dns.rrset.from_text('f.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkCookies('Probing', '127.0.0.25')
        self.checkCookies('Supported', '127.0.0.26')


class UDPResponder(DatagramProtocol):
    def getCookie(self, message):
        for option in message.options:
            if option.otype == dns.edns.COOKIE and isinstance(option, cookiesoption.CookiesOption):
                data = option.client
                if option.server is not None:
                    data += option.server
                return data
        return None

    def createCookie(self, clientcookie):
        clientcookie = clientcookie[0:8]
        timestamp = int(time.time())
        server = clientcookie + b'\x01\x00\x00\x00' + timestamp.to_bytes(4, 'big')
        h = hash(server +  b'\x01\x00\x00\x7f' + b'secret') % pow(2, 64)
        full = dns.edns.GenericOption(dns.edns.COOKIE, server + h.to_bytes(8, 'big'))
        return full

    def question(self, datagram, tcp=False):
        request = dns.message.from_wire(datagram)

        response = dns.message.make_response(request)
        response.flags = dns.flags.AA + dns.flags.QR

        question = request.question[0]

        # Case: do not send cookie back
        if question.name == dns.name.from_text('a.cookies.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('a.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            response.answer.append(answer)

        # Case: do send cookie back
        elif question.name == dns.name.from_text('b.cookies.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('b.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            clientcookie = self.getCookie(request)
            if clientcookie is not None:
                response.use_edns(options = [self.createCookie(clientcookie)])
            response.answer.append(answer)

        # We get a good client and server cookie
        elif question.name == dns.name.from_text('c.cookies.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('c.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            clientcookie = self.getCookie(request)
            if len(clientcookie) != 24:
                raise AssertionError("expected full cookie, got len " + str(len(clientcookie)))
            if clientcookie is not None:
                response.use_edns(options = [self.createCookie(clientcookie)])
            response.answer.append(answer)

        # Case: do send incorrect client cookie back
        elif question.name == dns.name.from_text('d.cookies.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('d.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            clientcookie = self.getCookie(request)
            if clientcookie is not None:
                mod = bytearray(clientcookie)
                mod[0] = 1
                response.use_edns(options = [self.createCookie(bytes(mod))])
            response.answer.append(answer)

        # Case: do send BADCOOKIE cookie back if UDP
        elif question.name == dns.name.from_text('e.cookies.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('e.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            clientcookie = self.getCookie(request)
            if clientcookie is not None:
                response.use_edns(options = [self.createCookie(clientcookie)])
                if not tcp:
                    response.set_rcode(23) # BADCOOKIE
            response.answer.append(answer)

        # Case send malformed cookie for server .25
        elif question.name == dns.name.from_text('f.cookies.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('f.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            clientcookie = self.getCookie(request)
            print(self.transport.getHost().host)
            if self.transport.getHost().host == os.environ['PREFIX'] + '.26':
                if clientcookie is not None:
                    response.use_edns(options = [self.createCookie(clientcookie)])
            else:
                full = dns.edns.GenericOption(dns.edns.COOKIE, '')
                response.use_edns(options = [full])
            response.answer.append(answer)

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
