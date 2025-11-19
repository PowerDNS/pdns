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
  devonly_regression_test_mode: true
outgoing:
  cookies: true
packetcache:
  disable: true
""" % (os.environ['PREFIX'], os.environ['PREFIX'])

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

    def checkAtLeastOneCookies(self, support):
        confdir = os.path.join('configs', self._confdir)
        output = self.recControl(confdir, 'dump-cookies', '-')
        ok = False
        for line in output.splitlines():
            tokens = line.split()
            if len(tokens) != 5:
                continue
            if tokens[3] == support:
                ok = True
        assert(ok)

    def testAuthDoesnotSendCookies(self):
        # Case: rec does not get a cookie back
        expected = dns.rrset.from_text('unsupported.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
        query = dns.message.make_query('unsupported.cookies.example.', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkCookies('Unsupported')

    def testAuthRepliesWithCookie(self):
        confdir = os.path.join('configs', self._confdir)
        # Case: rec gets a proper client and server cookie back
        self.recControl(confdir, 'clear-cookies', '*')
        tcp1 = self.recControl(confdir, 'get tcp-outqueries')
        query = dns.message.make_query('supported.cookies.example.', 'A')
        expected = dns.rrset.from_text('supported.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkAtLeastOneCookies('Supported')
        tcp2 = self.recControl(confdir, 'get tcp-outqueries')
        self.assertEqual(tcp1, tcp2)

        # Case: we get a correct client and server cookie back
        # We do not clear the cookie tables, so the old server cookie gets re-used
        query = dns.message.make_query('supported2.cookies.example.', 'A')
        expected = dns.rrset.from_text('supported2.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkAtLeastOneCookies('Supported')

    def testAuthSendsIncorrectClientCookie(self):
        confdir = os.path.join('configs', self._confdir)
        # Case: rec gets an incorrect client cookie back, we ignore that and go to TCP
        self.recControl(confdir, 'clear-cookies', '*')
        tcp1 = self.recControl(confdir, 'get tcp-outqueries')
        query = dns.message.make_query('wrongcc.cookies.example.', 'A')
        expected = dns.rrset.from_text('wrongcc.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkCookies('Probing')
        tcp2 = int(self.recControl(confdir, 'get tcp-outqueries'))
        self.assertEqual(int(tcp1) + 1, int(tcp2))

    def testAuthSendsBADCOOKIEOverUDP(self):
        confdir = os.path.join('configs', self._confdir)
        # Case: rec gets a BADCOOKIE, even on retry and should fall back to TCP
        self.recControl(confdir, 'clear-cookies', '*')
        tcp1 = self.recControl(confdir, 'get tcp-outqueries')
        query = dns.message.make_query('badcookie.cookies.example.', 'A')
        expected = dns.rrset.from_text('badcookie.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkCookies('Supported')
        tcp2 = int(self.recControl(confdir, 'get tcp-outqueries'))
        self.assertEqual(int(tcp1) + 1, int(tcp2))

    def testAuthSendsMalformedCookie(self):
        confdir = os.path.join('configs', self._confdir)
        # Case: rec gets a malformed cookie, should ignore packet
        self.recControl(confdir, 'clear-cookies', '*')
        query = dns.message.make_query('malformed.cookies.example.', 'A')
        expected = dns.rrset.from_text('malformed.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkCookies('Probing', '127.0.0.25')
        self.checkCookies('Supported', '127.0.0.26')

    def testForgottenCookie(self):
        confdir = os.path.join('configs', self._confdir)
        # Case: rec gets a proper client and server cookie back
        self.recControl(confdir, 'clear-cookies', '*')
        query = dns.message.make_query('supported3.cookies.example.', 'A')
        expected = dns.rrset.from_text('supported3.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkCookies('Supported')

        # Case: we get a correct client and server cookie back
        # We HAVE cleared the cookie tables, so the old server cookie is forgotten
        self.recControl(confdir, 'clear-cookies', '*')
        query = dns.message.make_query('supported4.cookies.example.', 'A')
        expected = dns.rrset.from_text('supported4.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkCookies('Supported')

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
        if question.name == dns.name.from_text('unsupported.cookies.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('unsupported.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            response.answer.append(answer)

        # Case: do send cookie back
        elif question.name == dns.name.from_text('supported.cookies.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('supported.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            clientcookie = self.getCookie(request)
            if clientcookie is not None:
                response.use_edns(options = [self.createCookie(clientcookie)])
            response.answer.append(answer)

        # We get a good client and server cookie
        elif question.name == dns.name.from_text('supported2.cookies.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('supported2.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            clientcookie = self.getCookie(request)
            if clientcookie is not None:
                response.use_edns(options = [self.createCookie(clientcookie)])
            response.answer.append(answer)

        # Case: do send cookie back
        elif question.name == dns.name.from_text('supported3.cookies.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('supported3.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            clientcookie = self.getCookie(request)
            if clientcookie is not None:
                response.use_edns(options = [self.createCookie(clientcookie)])
            response.answer.append(answer)

        # We get a new client cookie as the cookie store was cleared
        elif question.name == dns.name.from_text('supported4.cookies.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('supported4.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            clientcookie = self.getCookie(request)
            if clientcookie is not None:
                response.use_edns(options = [self.createCookie(clientcookie)])
            response.answer.append(answer)

        # Case: do send incorrect client cookie back
        elif question.name == dns.name.from_text('wrongcc.cookies.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('wrongcc.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            clientcookie = self.getCookie(request)
            if clientcookie is not None:
                mod = bytearray(clientcookie)
                mod[0] = 1
                response.use_edns(options = [self.createCookie(bytes(mod))])
            response.answer.append(answer)

        # Case: do send BADCOOKIE cookie back if UDP
        elif question.name == dns.name.from_text('badcookie.cookies.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('badcookie.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
            clientcookie = self.getCookie(request)
            if clientcookie is not None:
                response.use_edns(options = [self.createCookie(clientcookie)])
                if not tcp:
                    response.set_rcode(23) # BADCOOKIE
            response.answer.append(answer)

        # Case send malformed cookie for server .25
        elif question.name == dns.name.from_text('malformed.cookies.example.') and question.rdtype == dns.rdatatype.A:
            answer = dns.rrset.from_text('malformed.cookies.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
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
