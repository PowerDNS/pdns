import dns
import os
import socket
import struct
import threading
import time
import clientsubnetoption
import unittest
from recursortests import RecursorTest, have_ipv6
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

emptyECSText = 'No ECS received'
nameECS = 'ecs-echo.example.'
nameECSInvalidScope = 'invalid-scope.ecs-echo.example.'
ttlECS = 60
ecsReactorRunning = False
ecsReactorv6Running = False

class ECSTest(RecursorTest):
    _config_template_default = """
daemon=no
trace=yes
dont-query=
local-address=127.0.0.1
packetcache-ttl=15
packetcache-servfail-ttl=15
max-cache-ttl=600
threads=2
loglevel=9
disable-syslog=yes
log-common-errors=yes
statistics-interval=0
ecs-add-for=0.0.0.0/0
"""

    def sendECSQuery(self, query, expected, expectedFirstTTL=None, scopeZeroResponse=None):
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        # this will break if you are not looking for the first RR, sorry!
        if expectedFirstTTL is not None:
            self.assertTrue(res.answer[0].ttl == expectedFirstTTL or res.answer[0].ttl == expectedFirstTTL - 1)
        else:
            expectedFirstTTL = res.answer[0].ttl
        self.assertEqual(res.edns, query.edns)

        if scopeZeroResponse is not None:
            self.assertEqual(res.edns, 0)
            if scopeZeroResponse:
                self.assertEqual(len(res.options), 1)
                self.assertEqual(res.options[0].otype, 8)
                self.assertEqual(res.options[0].scope, 0)
            else:
                self.assertEqual(len(res.options), 1)
                self.assertEqual(res.options[0].otype, 8)
                self.assertNotEqual(res.options[0].scope, 0)

        # wait one second, check that the TTL has been
        # decreased indicating a cache hit
        time.sleep(1)

        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.assertLess(res.answer[0].ttl, expectedFirstTTL)
        self.assertEqual(res.edns, query.edns)

    def checkECSQueryHit(self, query, expected):
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        # this will break if you are not looking for the first RR, sorry!
        self.assertLess(res.answer[0].ttl, ttlECS)

    @classmethod
    def startResponders(cls):
        global ecsReactorRunning
        global ecsReactorv6Running
        print("Launching responders..")

        address = cls._PREFIX + '.21'
        port = 53

        if not ecsReactorRunning:
            reactor.listenUDP(port, UDPECSResponder(), interface=address)
            ecsReactorRunning = True

        if not ecsReactorv6Running and have_ipv6():
            reactor.listenUDP(53000, UDPECSResponder(), interface='::1')
            ecsReactorv6Running = True

        if not reactor.running:
            cls._UDPResponder = threading.Thread(name='UDP Responder', target=reactor.run, args=(False,))
            cls._UDPResponder.daemon = True
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

class NoECSTest(ECSTest):
    _confdir = 'NoECS'

    _config_template = """edns-subnet-allow-list=
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

class IncomingNoECSTest(ECSTest):
    _confdir = 'IncomingNoECS'

    _config_template = """edns-subnet-allow-list=
use-incoming-edns-subnet=yes
forward-zones=ecs-echo.example=%s.21
    """ % (os.environ['PREFIX'])

    def testSendECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', emptyECSText)

        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected, scopeZeroResponse=True)

    def testNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', emptyECSText)

        query = dns.message.make_query(nameECS, 'TXT')
        self.sendECSQuery(query, expected)

    def testRequireNoECS(self):
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', emptyECSText)

        ecso = clientsubnetoption.ClientSubnetOption('0.0.0.0', 0)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected, scopeZeroResponse=True)

class ECSByNameTest(ECSTest):
    _confdir = 'ECSByName'

    _config_template = """edns-subnet-allow-list=ecs-echo.example.
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

class ECSByNameLargerTest(ECSTest):
    _confdir = 'ECSByNameLarger'

    _config_template = """edns-subnet-allow-list=ecs-echo.example.
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

class ECSByNameSmallerTest(ECSTest):
    _confdir = 'ECSByNameSmaller'

    _config_template = """edns-subnet-allow-list=ecs-echo.example.
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

class IncomingECSByNameTest(ECSTest):
    _confdir = 'IncomingECSByName'

    _config_template = """edns-subnet-allow-list=ecs-echo.example.
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

class IncomingECSByNameLargerTest(ECSTest):
    _confdir = 'IncomingECSByNameLarger'

    _config_template = """edns-subnet-allow-list=ecs-echo.example.
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

class IncomingECSByNameSmallerTest(ECSTest):
    _confdir = 'IncomingECSByNameSmaller'

    _config_template = """edns-subnet-allow-list=ecs-echo.example.
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

@unittest.skipIf(not have_ipv6(), "No IPv6")
class IncomingECSByNameV6Test(ECSTest):
    _confdir = 'IncomingECSByNameV6'

    _config_template = """edns-subnet-allow-list=ecs-echo.example.
use-incoming-edns-subnet=yes
ecs-ipv6-bits=128
ecs-ipv4-cache-bits=32
ecs-ipv6-cache-bits=128
query-local-address=::1
forward-zones=ecs-echo.example=[::1]:53000
    """

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
        # we should get ::1/128 because ecs-scope-zero-addr is unset and query-local-address is set to ::1
        expected = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', "::1/128")

        ecso = clientsubnetoption.ClientSubnetOption('0.0.0.0', 0)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected, ttlECS)

class ECSNameMismatchTest(ECSTest):
    _confdir = 'ECSNameMismatch'

    _config_template = """edns-subnet-allow-list=not-the-right-name.example.
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

class ECSByIPTest(ECSTest):
    _confdir = 'ECSByIP'

    _config_template = """edns-subnet-allow-list=%s.21
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

class IncomingECSByIPTest(ECSTest):
    _confdir = 'IncomingECSByIP'

    _config_template = """edns-subnet-allow-list=%s.21
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
        expected = dns.rrset.from_text(nameECSInvalidScope, ttlECS, dns.rdataclass.IN, 'TXT', '192.0.2.0/24/25')

        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 24)
        query = dns.message.make_query(nameECSInvalidScope, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)

        self.sendECSQuery(query, expected)

class ECSIPMismatchTest(ECSTest):
    _confdir = 'ECSIPMismatch'

    _config_template = """edns-subnet-allow-list=192.0.2.1
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

class ECSWithProxyProtocolRecursorTest(ECSTest):
    _confdir = 'ECSWithProxyProtocolRecursor'
    _config_template = """
    ecs-add-for=2001:db8::1/128
    edns-subnet-allow-list=ecs-echo.example.
    forward-zones=ecs-echo.example=%s.21
    proxy-protocol-from=127.0.0.1/32
    allow-from=2001:db8::1/128
""" % (os.environ['PREFIX'])

    def testProxyProtocolPlusECS(self):
        qname = nameECS
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'TXT', '2001:db8::/56')

        query = dns.message.make_query(qname, 'TXT', use_edns=True)
        for method in ("sendUDPQueryWithProxyProtocol", "sendTCPQueryWithProxyProtocol"):
            sender = getattr(self, method)
            res = sender(query, True, '2001:db8::1', '2001:db8::2', 0, 65535)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

class TooLargeToAddZeroScopeTest(RecursorTest):

    _confdir = 'TooLargeToAddZeroScope'
    _config_template = """
use-incoming-edns-subnet=yes
dnssec=validate
"""
    _lua_dns_script_file = """
    function preresolve(dq)
      if dq.qname == newDN('toolarge.ecs.') then
        dq:addRecord(pdns.TXT, '%s', pdns.place.ANSWER)
        return true
      end
      return false
    end
    """ % ('A'*447)

    _roothints = None

    @classmethod
    def setUpClass(cls):

        # we don't need all the auth stuff
        cls.setUpSockets()
        cls.startResponders()

        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)

        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

    @classmethod
    def tearDownClass(cls):
        cls.tearDownRecursor()

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(TooLargeToAddZeroScopeTest, cls).generateRecursorConfig(confdir)

    def testTooLarge(self):
        qname = 'toolarge.ecs.'
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 24)
        query = dns.message.make_query(qname, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)

        # should not have an ECS Option since the packet is too large already
        res = self.sendUDPQuery(query, timeout=5.0)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(len(res.answer), 1)
        self.assertEqual(res.edns, 0)
        self.assertEqual(len(res.options), 0)

        res = self.sendTCPQuery(query, timeout=5.0)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(len(res.answer), 1)
        self.assertEqual(res.edns, 0)
        self.assertEqual(len(res.options), 1)
        self.assertEqual(res.options[0].otype, 8)
        self.assertEqual(res.options[0].scope, 0)

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
                        ecso = clientsubnetoption.ClientSubnetOption("192.0.2.1", 24, 25)
                        text += "/25"
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
            response.use_edns(options = [ecso])

        self.transport.write(response.to_wire(), address)
