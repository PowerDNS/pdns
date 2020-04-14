import dns
import os
import socket
import struct
import threading
import time
import clientsubnetoption
import subprocess
from recursortests import RecursorTest
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

emptyECSText = 'No ECS received'
nameECS = 'ecs-echo.example.'
nameECSInvalidScope = 'invalid-scope.ecs-echo.example.'
ttlECS = 60
routingReactorRunning = False

class RoutingTagTest(RecursorTest):
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

    def setRoutingTag(self, tag):
        # This value is picked up by the gettag()
        file = open('tagfile', 'w')
        if tag:
            file.write(tag)
        file.close();

    @classmethod
    def startResponders(cls):
        global routingReactorRunning
        print("Launching responders..")

        address = cls._PREFIX + '.24'
        port = 53

        if not routingReactorRunning:
            reactor.listenUDP(port, UDPRoutingResponder(), interface=address)
            routingReactorRunning = True

        if not reactor.running:
            cls._UDPResponder = threading.Thread(name='UDP Routing Responder', target=reactor.run, args=(False,))
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
        os.unlink('tagfile')

class testRoutingTag(RoutingTagTest):
    _confdir = 'RoutingTag'

    _config_template = """
log-common-errors=yes
use-incoming-edns-subnet=yes
edns-subnet-whitelist=ecs-echo.example.
forward-zones=ecs-echo.example=%s.24
    """ % (os.environ['PREFIX'])
    _lua_dns_script_file = """

function gettag(remote, ednssubnet, localip, qname, qtype, ednsoptions, tcp, proxyProtocolValues)
  local rtag
  for line in io.lines('tagfile') do
    rtag = line
    break
  end
  return 0, nil, nil, nil, nil, nil, rtag
end
"""

    def testSendECS(self):
        # First send an ECS query with routingTag
        self.setRoutingTag('foo')
        expected1 = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '192.0.2.0/24')
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected1)

        # Now check a cache hit withg the same routingTag (but no ECS)
        query = dns.message.make_query(nameECS, 'TXT', 'IN')
        self.checkECSQueryHit(query, expected1)

        expected2 = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.0/24')
        # And see if a different tag does *not* hit the first one
        self.setRoutingTag('bar')
        query = dns.message.make_query(nameECS, 'TXT', 'IN')
        self.sendECSQuery(query, expected2)

        # And see if a *no* tag does *not* hit the firts one
        expected3 = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '192.0.3.0/24')
        self.setRoutingTag(None)
        ecso = clientsubnetoption.ClientSubnetOption('192.0.3.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected3)

        # And see if an unknown tag does hit the last
        self.setRoutingTag('baz')
        query = dns.message.make_query(nameECS, 'TXT', 'IN')
        self.checkECSQueryHit(query, expected3)

        return # remove this line to peek at cache
        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % 'configs/' + self._confdir,
                          'dump-cache x']
        try:
            expected = 'dumped 5 records\n'
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
            self.assertEqual(ret, expected)

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

class testRoutingTagFFI(RoutingTagTest):
    _confdir = 'RoutingTagFFI'

    _config_template = """
log-common-errors=yes
use-incoming-edns-subnet=yes
edns-subnet-whitelist=ecs-echo.example.
forward-zones=ecs-echo.example=%s.24
    """ % (os.environ['PREFIX'])
    _lua_dns_script_file = """

local ffi = require("ffi")
ffi.cdef[[
  typedef struct pdns_ffi_param pdns_ffi_param_t;

  const char* pdns_ffi_param_get_qname(pdns_ffi_param_t* ref);
  void pdns_ffi_param_set_routingtag(pdns_ffi_param_t* ref, const char* rtag);
]]

function gettag_ffi(obj)
  for line in io.lines('tagfile') do
    local rtag = ffi.string(line)
    ffi.C.pdns_ffi_param_set_routingtag(obj, rtag)
    break
  end
  return 0
end
"""
    def testSendECS(self):
        # First send an ECS query with routingTag
        self.setRoutingTag('foo')
        expected1 = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '192.0.2.0/24')
        ecso = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected1)

        # Now check a cache hit withg the same routingTag (but no ECS)
        query = dns.message.make_query(nameECS, 'TXT', 'IN')
        self.checkECSQueryHit(query, expected1)

        expected2 = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '127.0.0.0/24')
        # And see if a different tag does *not* hit the first one
        self.setRoutingTag('bar')
        query = dns.message.make_query(nameECS, 'TXT', 'IN')
        self.sendECSQuery(query, expected2)

        # And see if a *no* tag does *not* hit the firts one
        expected3 = dns.rrset.from_text(nameECS, ttlECS, dns.rdataclass.IN, 'TXT', '192.0.3.0/24')
        self.setRoutingTag(None)
        ecso = clientsubnetoption.ClientSubnetOption('192.0.3.1', 32)
        query = dns.message.make_query(nameECS, 'TXT', 'IN', use_edns=True, options=[ecso], payload=512)
        self.sendECSQuery(query, expected3)

        # And see if an unknown tag does hit the last
        self.setRoutingTag('baz')
        query = dns.message.make_query(nameECS, 'TXT', 'IN')
        self.checkECSQueryHit(query, expected3)

        return #remove this line to peek at cache
        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % 'configs/' + self._confdir,
                          'dump-cache y']
        try:
            expected = 'dumped 5 records\n'
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
            self.assertEqual(ret, expected)

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

class UDPRoutingResponder(DatagramProtocol):
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
            additional = dns.rrset.from_text('ns1.ecs-echo.example.', 15, dns.rdataclass.IN, 'A', os.environ['PREFIX'] + '.24')
            response.additional.append(additional)

        if ecso:
            response.options = [ecso]

        self.transport.write(response.to_wire(), address)
