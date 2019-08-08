import dns
import os
import socket
import struct
import threading
import time
import clientsubnetoption
from recursortests import RecursorTest
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

emptyECSText = 'No ECS received'
nameECS = 'ecs-echo.example.'
nameECSInvalidScope = 'invalid-scope.ecs-echo.example.'
ttlECS = 60
ecsReactorRunning = False

class ECSTest(RecursorTest):
    _config_template_default = """
daemon=no
trace=yes
dont-query=
ecs-add-for=0.0.0.0/0
local-address=127.0.0.1
packetcache-ttl=0
packetcache-servfail-ttl=0
max-cache-ttl=600
threads=1
loglevel=9
disable-syslog=yes
"""

    def sendECSQuery(self, query, expected, expectedFirstTTL=None):
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        # this will break if you are not looking for the first RR, sorry!
        if expectedFirstTTL is not None:
            self.assertEqual(res.answer[0].ttl, expectedFirstTTL)
        else:
            expectedFirstTTL = res.answer[0].ttl

        # wait one second, check that the TTL has been
        # decreased indicating a cache hit
        time.sleep(1)

        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.assertLess(res.answer[0].ttl, expectedFirstTTL)

    def checkECSQueryHit(self, query, expected):
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        # this will break if you are not looking for the first RR, sorry!
        self.assertLess(res.answer[0].ttl, ttlECS)

    @classmethod
    def startResponders(cls):
        global ecsReactorRunning
        print("Launching responders..")

        address = cls._PREFIX + '.21'
        port = 53

        if not ecsReactorRunning:
            reactor.listenUDP(port, UDPECSResponder(), interface=address)
            ecsReactorRunning = True

        if not reactor.running:
            cls._UDPResponder = threading.Thread(name='UDP Responder', target=reactor.run, args=(False,))
            cls._UDPResponder.setDaemon(True)
            cls._UDPResponder.start()

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

class testNoECS(ECSTest):
    _confdir = 'NoECS'

    _config_template = """edns-subnet-whitelist=
forward-zones=ecs-echo.example=%s.21
    """ % (os.environ['PREFIX'])

    def testSendECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', emptyECSText)
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

    def testNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', emptyECSText)
        query = dns.message.make_query(nameECS, 'TXT')
        self.sendECSQuery(query, expected)

    def testRequireNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', emptyECSText)

        ecso = clientsubnetoption.ClientSubnetOption('0.0.0.0', 0)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

class testIncomingNoECS(ECSTest):
    _confdir = 'IncomingNoECS'

    _config_template = """edns-subnet-whitelist=
use-incoming-edns-subnet=yes
forward-zones=ecs-echo.example=%s.21
    """ % (os.environ['PREFIX'])

    def testSendECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', emptyECSText)

        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

    def testNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', emptyECSText)

        query = dns.message.make_query(nameECS, 'TXT')
        self.sendECSQuery(query, expected)

    def testRequireNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', emptyECSText)

        ecso = clientsubnetoption.ClientSubnetOption('0.0.0.0', 0)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

class testECSByName(ECSTest):
    _confdir = 'ECSByName'

    _config_template = """edns-subnet-whitelist=ecs-echo.example.
forward-zones=ecs-echo.example=%s.21
    """ % (os.environ['PREFIX'])

    def testSendECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.0/24')
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

        # check that a query in a different ECS range is a hit, because we don't use the incoming ECS
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.2', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.checkECSQueryHit(query, expected)

    def testNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.0/24')
        query = dns.message.make_query(nameECS, 'TXT')
        self.sendECSQuery(query, expected)

    def testRequireNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.0/24')

        # the request for no ECS is ignored because use-incoming-edns-subnet is not set
        ecso = clientsubnetoption.ClientSubnetOption('0.0.0.0', 0)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

class testECSByNameLarger(ECSTest):
    _confdir = 'ECSByNameLarger'

    _config_template = """edns-subnet-whitelist=ecs-echo.example.
ecs-ipv4-bits=32
forward-zones=ecs-echo.example=%s.21
ecs-ipv4-cache-bits=32
ecs-ipv6-cache-bits=128
    """ % (os.environ['PREFIX'])

    def testSendECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.1/32')
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

        # check that a query in a different range is a miss
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.2', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

    def testNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.1/32')
        query = dns.message.make_query(nameECS, 'TXT')
        self.sendECSQuery(query, expected)

    def testRequireNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.1/32')

        # the request for no ECS is ignored because use-incoming-edns-subnet is not set
        ecso = clientsubnetoption.ClientSubnetOption('0.0.0.0', 0)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

class testECSByNameSmaller(ECSTest):
    _confdir = 'ECSByNameLarger'

    _config_template = """edns-subnet-whitelist=ecs-echo.example.
ecs-ipv4-bits=16
forward-zones=ecs-echo.example=%s.21
    """ % (os.environ['PREFIX'])

    def testSendECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.0/16')
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

    def testNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.0/16')
        query = dns.message.make_query(nameECS, 'TXT')
        self.sendECSQuery(query, expected)

    def testRequireNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.0/16')

        # the request for no ECS is ignored because use-incoming-edns-subnet is not set
        ecso = clientsubnetoption.ClientSubnetOption('0.0.0.0', 0)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

class testIncomingECSByName(ECSTest):
    _confdir = 'ECSIncomingByName'

    _config_template = """edns-subnet-whitelist=ecs-echo.example.
use-incoming-edns-subnet=yes
forward-zones=ecs-echo.example=%s.21
ecs-scope-zero-address=2001:db8::42
ecs-ipv4-cache-bits=32
ecs-ipv6-cache-bits=128
    """ % (os.environ['PREFIX'])

    def testSendECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '192.0.2.0/24')
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected, ttlECS)

        # check that a query in the same ECS range is a hit
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.2', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.checkECSQueryHit(query, expected)

        # check that a query in a different ECS range is a miss
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '192.1.2.0/24')
        ecso = clientsubnetoption.ClientSubnetOption('192.1.2.2', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

    def testNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.0/24')
        query = dns.message.make_query(nameECS, 'TXT')
        self.sendECSQuery(query, expected, ttlECS)

    def testRequireNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', "2001:db8::42/128")

        ecso = clientsubnetoption.ClientSubnetOption('0.0.0.0', 0)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected, ttlECS)

class testIncomingECSByNameLarger(ECSTest):
    _confdir = 'ECSIncomingByNameLarger'

    _config_template = """edns-subnet-whitelist=ecs-echo.example.
use-incoming-edns-subnet=yes
ecs-ipv4-bits=32
forward-zones=ecs-echo.example=%s.21
ecs-scope-zero-address=192.168.0.1
ecs-ipv4-cache-bits=32
ecs-ipv6-cache-bits=128
    """ % (os.environ['PREFIX'])

    def testSendECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '192.0.2.1/32')

        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected, ttlECS)

    def testNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.1/32')

        query = dns.message.make_query(nameECS, 'TXT')
        self.sendECSQuery(query, expected, ttlECS)

    def testRequireNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '192.168.0.1/32')

        ecso = clientsubnetoption.ClientSubnetOption('0.0.0.0', 0)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected, ttlECS)

class testIncomingECSByNameSmaller(ECSTest):
    _confdir = 'ECSIncomingByNameSmaller'

    _config_template = """edns-subnet-whitelist=ecs-echo.example.
use-incoming-edns-subnet=yes
ecs-ipv4-bits=16
forward-zones=ecs-echo.example=%s.21
ecs-scope-zero-address=192.168.0.1
ecs-ipv4-cache-bits=32
ecs-ipv6-cache-bits=128
    """ % (os.environ['PREFIX'])

    def testSendECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '192.0.0.0/16')
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

    def testNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.0/16')
        query = dns.message.make_query(nameECS, 'TXT')
        self.sendECSQuery(query, expected)

    def testRequireNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '192.168.0.1/32')

        ecso = clientsubnetoption.ClientSubnetOption('0.0.0.0', 0)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected, ttlECS)

class testIncomingECSByNameV6(ECSTest):
    _confdir = 'ECSIncomingByNameV6'

    _config_template = """edns-subnet-whitelist=ecs-echo.example.
use-incoming-edns-subnet=yes
ecs-ipv6-bits=128
ecs-ipv4-cache-bits=32
ecs-ipv6-cache-bits=128
forward-zones=ecs-echo.example=%s.21
query-local-address6=::1
    """ % (os.environ['PREFIX'])

    def testSendECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '2001:db8::1/128')
        ecso = clientsubnetoption.ClientSubnetOption('2001:db8::1', 128)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected, ttlECS)

    def testNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.0/24')

        query = dns.message.make_query(nameECS, 'TXT')
        res = self.sendUDPQuery(query)
        self.sendECSQuery(query, expected, ttlECS)

    def testRequireNoECS(self):
        # we should get ::1/128 because neither ecs-scope-zero-addr nor query-local-address are set,
        # but query-local-address6 is set to ::1
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', "::1/128")

        ecso = clientsubnetoption.ClientSubnetOption('0.0.0.0', 0)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected, ttlECS)

class testECSNameMismatch(ECSTest):
    _confdir = 'ECSNameMismatch'

    _config_template = """edns-subnet-whitelist=not-the-right-name.example.
forward-zones=ecs-echo.example=%s.21
    """ % (os.environ['PREFIX'])

    def testSendECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', emptyECSText)
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

    def testNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', emptyECSText)
        query = dns.message.make_query(nameECS, 'TXT')
        self.sendECSQuery(query, expected)

    def testRequireNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', emptyECSText)

        ecso = clientsubnetoption.ClientSubnetOption('0.0.0.0', 0)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

class testECSByIP(ECSTest):
    _confdir = 'ECSByIP'

    _config_template = """edns-subnet-whitelist=%s.21
forward-zones=ecs-echo.example=%s.21
    """ % (os.environ['PREFIX'], os.environ['PREFIX'])

    def testSendECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.0/24')
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

    def testNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.0/24')
        query = dns.message.make_query(nameECS, 'TXT')
        self.sendECSQuery(query, expected)

    def testRequireNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.0/24')

        # the request for no ECS is ignored because use-incoming-edns-subnet is not set
        ecso = clientsubnetoption.ClientSubnetOption('0.0.0.0', 0)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

class testIncomingECSByIP(ECSTest):
    _confdir = 'ECSIncomingByIP'

    _config_template = """edns-subnet-whitelist=%s.21
use-incoming-edns-subnet=yes
forward-zones=ecs-echo.example=%s.21
ecs-scope-zero-address=::1
ecs-ipv4-cache-bits=32
ecs-ipv6-cache-bits=128
    """ % (os.environ['PREFIX'], os.environ['PREFIX'])

    def testSendECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '192.0.2.0/24')

        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

    def testNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.0/24')
        query = dns.message.make_query(nameECS, 'TXT')
        self.sendECSQuery(query, expected)

    def testRequireNoECS(self):
        # we will get ::1 because ecs-scope-zero-addr is set to ::1
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '::1/128')

        ecso = clientsubnetoption.ClientSubnetOption('0.0.0.0', 0)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected, ttlECS)

    def testSendECSInvalidScope(self):
        # test that the recursor does not cache with a more specific scope than the source it sent
        expected = dns.rrset.from_text(nameECSInvalidScope, ttlECS, dns.rdataclass.IN, 'TXT', '192.0.2.0/24')

        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(nameECSInvalidScope, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)

        self.sendECSQuery(query, expected)

class testECSIPMismatch(ECSTest):
    _confdir = 'ECSIPMismatch'

    _config_template = """edns-subnet-whitelist=192.0.2.1
forward-zones=ecs-echo.example=%s.21
    """ % (os.environ['PREFIX'])

    def testSendECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', emptyECSText)
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

    def testNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', emptyECSText)
        query = dns.message.make_query(nameECS, 'TXT')
        res = self.sendUDPQuery(query)
        self.sendECSQuery(query, expected)

    def testRequireNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', emptyECSText)

        ecso = clientsubnetoption.ClientSubnetOption('0.0.0.0', 0)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected)

class UDPECSResponder(DatagramProtocol):
    @staticmethod
    def ipToStr(option):
        if option.family == clientsubnetoption.FAMILY_IPV4:
            ip = socket.inet_ntop(socket.AF_INET, struct.pack('!L', option.ip))
        elif option.family == clientsubnetoption.FAMILY_IPV6:
            ip = socket.inet_ntop(socket.AF_INET6,
                                  struct.pack('!QQ',
                                              option.ip >> 64,
                                              option.ip & (2 ** 64 - 1)))
        return ip

    def datagramReceived(self, datagram, address):
        request = dns.message.from_wire(datagram)

        response = dns.message.make_response(request)
        response.flags |= dns.flags.AA
        ecso = None

        if (request.question[0].name == dns.name.from_text(nameECS) or request.question[0].name == dns.name.from_text(nameECSInvalidScope)) and request.question[0].rdtype == dns.rdatatype.TXT:

            text = emptyECSText
            for option in request.options:
                if option.otype == clientsubnetoption.ASSIGNED_OPTION_CODE and isinstance(option, clientsubnetoption.ClientSubnetOption):
                    text = self.ipToStr(option) + '/' + str(option.mask)

                    # Send a scope more specific than the received source for nameECSInvalidScope
                    if request.question[0].name == dns.name.from_text(nameECSInvalidScope):
                        ecso = clientsubnetoption.ClientSubnetOption("192.0.42.42", 32, 32)
                    else:
                        ecso = clientsubnetoption.ClientSubnetOption(self.ipToStr(option), option.mask, option.mask)

            answer = dns.rrset.from_text(request.question[0].name, ttlECS, dns.rdataclass.IN, 'TXT', text)
            response.answer.append(answer)

        elif request.question[0].name == dns.name.from_text(nameECS) and request.question[0].rdtype == dns.rdatatype.NS:
            answer = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'NS', 'ns1.ecs-echo.example.')
            response.answer.append(answer)
            additional = dns.rrset.from_text('ns1.ecs-echo.example.', 15, dns.rdataclass.IN, 'A', os.environ['PREFIX'] + '.21')
            response.additional.append(additional)

        if ecso:
            response.options = [ecso]

        self.transport.write(response.to_wire(), address)
