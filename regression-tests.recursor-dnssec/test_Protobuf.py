import dns
import dnsmessage_pb2
import os
import socket
import struct
import sys
import threading
import time
import clientsubnetoption

# Python2/3 compatibility hacks
try:
  from queue import Queue
except ImportError:
  from Queue import Queue

try:
  range = xrange
except NameError:
  pass

from recursortests import RecursorTest

def ProtobufConnectionHandler(queue, conn):
    data = None
    while True:
        data = conn.recv(2)
        if not data:
            break
        (datalen,) = struct.unpack("!H", data)
        data = conn.recv(datalen)
        if not data:
            break

        queue.put_nowait(data)

    conn.close()

def ProtobufListener(queue, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    try:
        sock.bind(("127.0.0.1", port))
    except socket.error as e:
        print("Error binding in the protobuf listener: %s" % str(e))
        sys.exit(1)

    sock.listen(100)
    while True:
        try:
            (conn, _) = sock.accept()
            thread = threading.Thread(name='Connection Handler',
                                      target=ProtobufConnectionHandler,
                                      args=[queue, conn])
            thread.daemon = True
            thread.start()

        except socket.error as e:
            print('Error in protobuf socket: %s' % str(e))

    sock.close()


class ProtobufServerParams:
  def __init__(self, port):
    self.queue = Queue()
    self.port = port

protobufServersParameters = [ProtobufServerParams(4243), ProtobufServerParams(4244)]
protobufListeners = []
for param in protobufServersParameters:
  listener = threading.Thread(name='Protobuf Listener', target=ProtobufListener, args=[param.queue, param.port])
  listener.daemon = True
  listener.start()
  protobufListeners.append(listener)

class TestRecursorProtobuf(RecursorTest):

    _lua_config_file = """
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"})
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)

    _auth_zones = {
        '8': {'threads': 1,
              'zones': ['ROOT']},
        '9': {'threads': 1,
              'zones': ['secure.example', 'islandofsecurity.example']},
        '10': {'threads': 1,
               'zones': ['example']},
        '18': {'threads': 1,
               'zones': ['example']}
    }

    def getFirstProtobufMessage(self, retries=10, waitTime=0.1):
        msg = None
        #print("in getFirstProtobufMessage")
        for param in protobufServersParameters:
          failed = 0

          while param.queue.empty():
            if failed >= retries:
              break
            failed = failed + 1
            #print(str(failed) + '...')
            time.sleep(waitTime)

          #print(str(failed) + ' ' + str(param.queue.empty()))
          self.assertFalse(param.queue.empty())
          data = param.queue.get(False)
          self.assertTrue(data)
          oldmsg = msg
          msg = dnsmessage_pb2.PBDNSMessage()
          msg.ParseFromString(data)
          if oldmsg is not None:
            self.assertEqual(msg, oldmsg)
        return msg

    def emptyProtoBufQueue(self):
        for param in protobufServersParameters:
            while not param.queue.empty():
                param.queue.get(False)

    def checkNoRemainingMessage(self):
        for param in protobufServersParameters:
          self.assertTrue(param.queue.empty())

    def checkProtobufBase(self, msg, protocol, query, initiator, normalQueryResponse=True, expectedECS=None, receivedSize=None):
        self.assertTrue(msg)
        self.assertTrue(msg.HasField('timeSec'))
        self.assertTrue(msg.HasField('socketFamily'))
        self.assertEqual(msg.socketFamily, dnsmessage_pb2.PBDNSMessage.INET)
        self.assertTrue(msg.HasField('from'))
        fromvalue = getattr(msg, 'from')
        self.assertEqual(socket.inet_ntop(socket.AF_INET, fromvalue), initiator)
        self.assertTrue(msg.HasField('socketProtocol'))
        self.assertEqual(msg.socketProtocol, protocol)
        self.assertTrue(msg.HasField('messageId'))
        self.assertTrue(msg.HasField('serverIdentity'))
        self.assertTrue(msg.HasField('id'))
        self.assertEqual(msg.id, query.id)
        self.assertTrue(msg.HasField('inBytes'))
        if normalQueryResponse:
            # compare inBytes with length of query/response
            # Note that for responses, the size we received might differ
            # because dnspython might compress labels differently from
            # the recursor
            if receivedSize:
                self.assertEqual(msg.inBytes, receivedSize)
            else:
                self.assertEqual(msg.inBytes, len(query.to_wire()))
        if expectedECS is not None:
            self.assertTrue(msg.HasField('originalRequestorSubnet'))
            # v4 only for now
            self.assertEqual(len(msg.originalRequestorSubnet), 4)
            self.assertEqual(socket.inet_ntop(socket.AF_INET, msg.originalRequestorSubnet), '127.0.0.1')

    def checkOutgoingProtobufBase(self, msg, protocol, query, initiator, length=None, expectedECS=None):
        self.assertTrue(msg)
        self.assertTrue(msg.HasField('timeSec'))
        self.assertTrue(msg.HasField('socketFamily'))
        self.assertEqual(msg.socketFamily, dnsmessage_pb2.PBDNSMessage.INET)
        self.assertTrue(msg.HasField('socketProtocol'))
        self.assertEqual(msg.socketProtocol, protocol)
        self.assertTrue(msg.HasField('messageId'))
        self.assertTrue(msg.HasField('serverIdentity'))
        self.assertTrue(msg.HasField('id'))
        self.assertNotEqual(msg.id, query.id)
        self.assertTrue(msg.HasField('inBytes'))
        if length is not None:
          self.assertEqual(msg.inBytes, length)
        else:
          # compare inBytes with length of query/response
          self.assertEqual(msg.inBytes, len(query.to_wire()))
        if expectedECS is not None:
            self.assertTrue(msg.HasField('originalRequestorSubnet'))
            # v4 only for now
            self.assertEqual(len(msg.originalRequestorSubnet), 4)
            self.assertEqual(socket.inet_ntop(socket.AF_INET, msg.originalRequestorSubnet), expectedECS)

    def checkProtobufQuery(self, msg, protocol, query, qclass, qtype, qname, initiator='127.0.0.1', to='127.0.0.1'):
        self.assertEqual(msg.type, dnsmessage_pb2.PBDNSMessage.DNSQueryType)
        self.checkProtobufBase(msg, protocol, query, initiator)
        # dnsdist doesn't fill the responder field for responses
        # because it doesn't keep the information around.
        self.assertTrue(msg.HasField('to'))
        self.assertEqual(socket.inet_ntop(socket.AF_INET, msg.to), to)
        self.assertTrue(msg.HasField('workerId'))
        self.assertTrue(msg.HasField('question'))
        self.assertTrue(msg.question.HasField('qClass'))
        self.assertEqual(msg.question.qClass, qclass)
        self.assertTrue(msg.question.HasField('qType'))
        self.assertEqual(msg.question.qClass, qtype)
        self.assertTrue(msg.question.HasField('qName'))
        self.assertEqual(msg.question.qName, qname)

    # This method takes wire format values to check
    def checkProtobufHeaderFlagsAndEDNSVersion(self, msg, flags, ednsVersion):
        self.assertTrue(msg.HasField('headerFlags'))
        self.assertEqual(msg.headerFlags, socket.htons(flags))
        self.assertTrue(msg.HasField('ednsVersion'))
        self.assertEqual(msg.ednsVersion, socket.htonl(ednsVersion))

    def checkProtobufResponse(self, msg, protocol, response, initiator='127.0.0.1', receivedSize=None, vstate=dnsmessage_pb2.PBDNSMessage.VState.Indeterminate):
        self.assertEqual(msg.type, dnsmessage_pb2.PBDNSMessage.DNSResponseType)
        self.checkProtobufBase(msg, protocol, response, initiator, receivedSize=receivedSize)
        self.assertTrue(msg.HasField('workerId'))
        self.assertTrue(msg.HasField('packetCacheHit'))
        self.assertTrue(msg.HasField('response'))
        self.assertTrue(msg.response.HasField('queryTimeSec'))
        self.assertTrue(msg.response.HasField('validationState'))
        self.assertEqual(msg.response.validationState, vstate)

    def checkProtobufResponseRecord(self, record, rclass, rtype, rname, rttl, checkTTL=True):
        self.assertTrue(record.HasField('class'))
        self.assertEqual(getattr(record, 'class'), rclass)
        self.assertTrue(record.HasField('type'))
        self.assertEqual(record.type, rtype)
        self.assertTrue(record.HasField('name'))
        self.assertEqual(record.name, rname)
        self.assertTrue(record.HasField('ttl'))
        if checkTTL:
            self.assertEqual(record.ttl, rttl)
        self.assertTrue(record.HasField('rdata'))

    def checkProtobufPolicy(self, msg, policyType, reason, trigger, hit, kind):
        self.assertEqual(msg.type, dnsmessage_pb2.PBDNSMessage.DNSResponseType)
        self.assertTrue(msg.response.HasField('appliedPolicyType'))
        self.assertTrue(msg.response.HasField('appliedPolicy'))
        self.assertTrue(msg.response.HasField('appliedPolicyTrigger'))
        self.assertTrue(msg.response.HasField('appliedPolicyHit'))
        self.assertTrue(msg.response.HasField('appliedPolicyKind'))
        self.assertEqual(msg.response.appliedPolicy, reason)
        self.assertEqual(msg.response.appliedPolicyType, policyType)
        self.assertEqual(msg.response.appliedPolicyTrigger, trigger)
        self.assertEqual(msg.response.appliedPolicyHit, hit)
        self.assertEqual(msg.response.appliedPolicyKind, kind)

    def checkProtobufTags(self, msg, tags):
        #print(tags)
        #print('---')
        #print(msg.response.tags)
        self.assertEqual(len(msg.response.tags), len(tags))
        for tag in msg.response.tags:
            self.assertTrue(tag in tags)

    def checkProtobufMetas(self, msg, metas):
        #print(metas)
        #print('---')
        #print(msg.meta)
        self.assertEqual(len(msg.meta), len(metas))
        for m in msg.meta:
            self.assertTrue(m.HasField('key'))
            self.assertTrue(m.HasField('value'))
            self.assertTrue(m.key in metas)
            for i in m.value.intVal :
              self.assertTrue(i in metas[m.key]['intVal'])
            for s in m.value.stringVal :
              self.assertTrue(s in metas[m.key]['stringVal'])

    def checkProtobufOutgoingQuery(self, msg, protocol, query, qclass, qtype, qname, initiator='127.0.0.1', length=None, expectedECS=None):
        self.assertEqual(msg.type, dnsmessage_pb2.PBDNSMessage.DNSOutgoingQueryType)
        self.checkOutgoingProtobufBase(msg, protocol, query, initiator, length=length, expectedECS=expectedECS)
        self.assertTrue(msg.HasField('to'))
        self.assertTrue(msg.HasField('question'))
        self.assertTrue(msg.question.HasField('qClass'))
        self.assertEqual(msg.question.qClass, qclass)
        self.assertTrue(msg.question.HasField('qType'))
        self.assertEqual(msg.question.qType, qtype)
        self.assertTrue(msg.question.HasField('qName'))
        self.assertEqual(msg.question.qName, qname)

    def checkProtobufIncomingResponse(self, msg, protocol, response, initiator='127.0.0.1', length=None):
        self.assertEqual(msg.type, dnsmessage_pb2.PBDNSMessage.DNSIncomingResponseType)
        self.checkOutgoingProtobufBase(msg, protocol, response, initiator, length=length)
        self.assertTrue(msg.HasField('response'))
        self.assertTrue(msg.response.HasField('rcode'))
        self.assertTrue(msg.response.HasField('queryTimeSec'))

    def checkProtobufIncomingNetworkErrorResponse(self, msg, protocol, response, initiator='127.0.0.1'):
        self.checkProtobufIncomingResponse(msg, protocol, response, initiator, length=0)
        self.assertEqual(msg.response.rcode, 65536)

    def checkProtobufIdentity(self, msg, requestorId, deviceId, deviceName):
        #print(msg)
        self.assertTrue((requestorId == '') == (not msg.HasField('requestorId')))
        self.assertTrue((deviceId == b'') == (not msg.HasField('deviceId')))
        self.assertTrue((deviceName == '') == (not msg.HasField('deviceName')))
        self.assertEqual(msg.requestorId, requestorId)
        self.assertEqual(msg.deviceId, deviceId)
        self.assertEqual(msg.deviceName, deviceName)

    def checkProtobufEDE(self, msg, ede, edeText):
        print(msg)
        self.assertTrue((ede == 0) == (not msg.HasField('ede')))
        self.assertTrue((edeText == '') == (not msg.HasField('edeText')))
        self.assertEqual(msg.ede, ede)
        self.assertEqual(msg.edeText, edeText)

    def checkProtobufOT(self, msg, openTelemetryData, openTelemetryTraceID):
        self.assertTrue(openTelemetryData == msg.HasField('openTelemetryData'))
        self.assertTrue(openTelemetryTraceID == msg.HasField('openTelemetryTraceID'))

    def setUp(self):
        super(TestRecursorProtobuf, self).setUp()
        # Make sure the queue is empty, in case
        # a previous test failed
        self.emptyProtoBufQueue()

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'example.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN example.
@ 3600 IN SOA {soa}
a 3600 IN A 192.0.2.42
tagged 3600 IN A 192.0.2.84
taggedtcp 3600 IN A 192.0.2.87
meta 3600 IN A 192.0.2.85
query-selected 3600 IN A 192.0.2.84
answer-selected 3600 IN A 192.0.2.84
types 3600 IN A 192.0.2.84
types 3600 IN AAAA 2001:DB8::1
types 3600 IN TXT "Lorem ipsum dolor sit amet"
types 3600 IN MX 10 a.example.
types 3600 IN SPF "v=spf1 -all"
types 3600 IN SRV 10 20 443 a.example.
cname 3600 IN CNAME a.example.

""".format(soa=cls._SOA))
        super(TestRecursorProtobuf, cls).generateRecursorConfig(confdir)

    @classmethod
    def generateRecursorYamlConfig(cls, confdir, flag):
        authzonepath = os.path.join(confdir, 'example.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN example.
@ 3600 IN SOA {soa}
a 3600 IN A 192.0.2.42
tagged 3600 IN A 192.0.2.84
taggedtcp 3600 IN A 192.0.2.87
meta 3600 IN A 192.0.2.85
query-selected 3600 IN A 192.0.2.84
answer-selected 3600 IN A 192.0.2.84
types 3600 IN A 192.0.2.84
types 3600 IN AAAA 2001:DB8::1
types 3600 IN TXT "Lorem ipsum dolor sit amet"
types 3600 IN MX 10 a.example.
types 3600 IN SPF "v=spf1 -all"
types 3600 IN SRV 10 20 443 a.example.
cname 3600 IN CNAME a.example.

""".format(soa=cls._SOA))
        super(TestRecursorProtobuf, cls).generateRecursorYamlConfig(confdir, flag)


class ProtobufDefaultTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export queries and response over protobuf.
    """

    _confdir = 'ProtobufDefault'
    _config_template = """
recursor:
    auth_zones:
    - zone: example
      file: configs/%s/example.zone
    event_trace_enabled: 4
logging:
  protobuf_servers:
    - servers: [127.0.0.1:%s, 127.0.0.1:%s]
  opentelemetry_trace_conditions:
    - acls: ['0.0.0.0/0']
""" % (_confdir, protobufServersParameters[0].port, protobufServersParameters[1].port)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(ProtobufDefaultTest, cls).generateRecursorYamlConfig(confdir, False)

    def testA(self):
        name = 'a.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)

        self.assertRRsetInAnswer(res, expected)

        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        # wire format, RD and CD set in headerflags, plus DO bit in flags part of EDNS Version
        self.checkProtobufHeaderFlagsAndEDNSVersion(msg, 0x0110, 0x00008000)
        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res, '127.0.0.1')
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.42')
        self.checkNoRemainingMessage()
        #
        # again, for a PC cache hit
        #
        res = self.sendUDPQuery(query)

        self.assertRRsetInAnswer(res, expected)

        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        # wire format, RD and CD set in headerflags, plus DO bit in flags part of EDNS Version
        self.checkProtobufHeaderFlagsAndEDNSVersion(msg, 0x0110, 0x00008000)
        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res, '127.0.0.1')
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.42')
        self.checkProtobufOT(msg, True, True)
        self.checkProtobufEDE(msg, 0, '')
        self.checkNoRemainingMessage()

    def testCNAME(self):
        name = 'cname.example.'
        expectedCNAME = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'CNAME', 'a.example.')
        expectedA = dns.rrset.from_text('a.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        raw = self.sendUDPQuery(query, decode=False)
        res = dns.message.from_wire(raw)
        self.assertRRsetInAnswer(res, expectedCNAME)
        self.assertRRsetInAnswer(res, expectedA)

        # check the protobuf messages corresponding to the UDP query and answer
        # but first let the protobuf messages the time to get there
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res, '127.0.0.1', receivedSize=len(raw))
        self.assertEqual(len(msg.response.rrs), 2)
        rr = msg.response.rrs[0]
        # we don't want to check the TTL for the A record, it has been cached by the previous test
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.CNAME, name, 15)
        self.assertEqual(rr.rdata, b'a.example.')
        rr = msg.response.rrs[1]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, 'a.example.', 15, checkTTL=False)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.42')
        self.checkProtobufOT(msg, True, True)
        self.checkProtobufEDE(msg, 0, '')
        self.checkNoRemainingMessage()

class ProtobufProxyMappingTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export queries and response over protobuf with a proxyMapping
    """

    _confdir = 'ProtobufProxyMapping'
    _config_template = """
    auth-zones=example=configs/%s/example.zone
    allow-from=3.4.5.0/24
    """ % _confdir

    _lua_config_file = """
    addProxyMapping("127.0.0.1/24", "3.4.5.6:99")
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"})
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)

    def testA(self):
        name = 'a.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)

        self.assertRRsetInAnswer(res, expected)

        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res, '127.0.0.1')
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.42')
        self.checkNoRemainingMessage()

class ProtobufProxyMappingLogMappedTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export queries and response over protobuf.
    """

    _confdir = 'ProtobufProxyMappingLogMapped'
    _config_template = """
    auth-zones=example=configs/%s/example.zone
    allow-from=3.4.5.0/0"
    """ % _confdir

    _lua_config_file = """
    addProxyMapping("127.0.0.1/24", "3.4.5.6:99")
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"}, { logMappedFrom = true })
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)

    def testA(self):
        name = 'a.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)

        self.assertRRsetInAnswer(res, expected)

        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name, '3.4.5.6')
        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res, '3.4.5.6')
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.42')
        self.checkNoRemainingMessage()

class ProtobufProxyTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export addresses over protobuf when the proxy protocol is used.
    """

    _confdir = 'ProtobufProxy'
    _config_template = """
auth-zones=example=configs/%s/example.zone
proxy-protocol-from=127.0.0.1/32
allow-from=127.0.0.1,6.6.6.6
""" % _confdir

    def testA(self):
        name = 'a.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQueryWithProxyProtocol(query, False, '6.6.6.6', '7.7.7.7', 666, 777)

        self.assertRRsetInAnswer(res, expected)

        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name, '6.6.6.6', '7.7.7.7')
        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res, '6.6.6.6')
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.42')
        self.checkNoRemainingMessage()

class ProtobufProxyWithProxyByTableTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export addresses over protobuf when the proxy protocol and a proxy table mapping is used
    """

    _confdir = 'ProtobufProxyWithProxyByTable'
    _config_template = """
auth-zones=example=configs/%s/example.zone
proxy-protocol-from=127.0.0.1/32
allow-from=3.4.5.6
""" % _confdir

    _lua_config_file = """
    addProxyMapping("6.6.6.6/24", "3.4.5.6:99")
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"})
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)

    def testA(self):
        name = 'a.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQueryWithProxyProtocol(query, False, '6.6.6.6', '7.7.7.7', 666, 777)

        self.assertRRsetInAnswer(res, expected)

        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name, '6.6.6.6', '7.7.7.7')
        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res, '6.6.6.6')
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.42')
        self.checkNoRemainingMessage()

class ProtobufProxyWithProxyByTableLogMappedTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export addresses over protobuf when the proxy protocol and a proxy table mapping is used
    """

    _confdir = 'ProtobufProxyWithProxyByTableLogMapped'
    _config_template = """
auth-zones=example=configs/%s/example.zone
proxy-protocol-from=127.0.0.1/32
allow-from=3.4.5.6
""" % _confdir

    _lua_config_file = """
    addProxyMapping("6.6.6.6/24", "3.4.5.6:99")
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"}, { logMappedFrom = true })
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)

    def testA(self):
        name = 'a.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQueryWithProxyProtocol(query, False, '6.6.6.6', '7.7.7.7', 666, 777)

        self.assertRRsetInAnswer(res, expected)

        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name, '3.4.5.6', '7.7.7.7')
        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res, '3.4.5.6')
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.42')
        self.checkNoRemainingMessage()


class OutgoingProtobufDefaultTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export outgoing queries over protobuf.
    It must be improved and setup env so we can check for incoming responses, but makes sure for now
    that the recursor at least connects to the protobuf server.
    """

    _confdir = 'OutgoingProtobufDefault'
    _config_template = """
    # Switch off QName Minimization, it generates much more protobuf messages
    # (or make the test much more smart!)
    qname-minimization=no
    max-cache-ttl=600
    loglevel=9
"""
    _lua_config_file = """
    outgoingProtobufServer({"127.0.0.1:%d", "127.0.0.1:%d"})
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)

    def testA(self):
        # There is a race in priming (having the . DNSKEY in cache in particular) and this code.
        # So make sure we have the . DNSKEY in cache
        query = dns.message.make_query('.', 'A', want_dnssec=True)
        query.flags |= dns.flags.RD
        res = self.sendUDPQuery(query)
        time.sleep(1)
        self.emptyProtoBufQueue()

        name = 'host1.secure.example.'
        expected = list()

        for qname, qtype, proto, responseSize in [
                ('host1.secure.example.', dns.rdatatype.A, dnsmessage_pb2.PBDNSMessage.UDP, 248),
                ('host1.secure.example.', dns.rdatatype.A, dnsmessage_pb2.PBDNSMessage.UDP, 221),
                ('example.', dns.rdatatype.DNSKEY, dnsmessage_pb2.PBDNSMessage.UDP, 219),
                ('host1.secure.example.', dns.rdatatype.A, dnsmessage_pb2.PBDNSMessage.UDP, 175),
                ('secure.example.', dns.rdatatype.DNSKEY, dnsmessage_pb2.PBDNSMessage.UDP, 233),
        ]:
            if not qname:
                expected.append((None, None, None, None, None, None))
                continue
            query = dns.message.make_query(qname, qtype, use_edns=True, want_dnssec=True)
            resp = dns.message.make_response(query)
            expected.append((
                qname, qtype, query, resp, proto, responseSize
            ))

        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.RD
        res = self.sendUDPQuery(query)

        for qname, qtype, qry, ans, proto, responseSize in expected:
            if not qname:
                self.getFirstProtobufMessage()
                self.getFirstProtobufMessage()
                continue

            msg = self.getFirstProtobufMessage()
            self.checkProtobufOutgoingQuery(msg, proto, qry, dns.rdataclass.IN, qtype, qname)

            # Check the answer
            msg = self.getFirstProtobufMessage()
            self.checkProtobufIncomingResponse(msg, proto, ans, length=responseSize)

        self.checkNoRemainingMessage()

class OutgoingProtobufWithECSMappingTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export outgoing queries over protobuf.
    It must be improved and setup env so we can check for incoming responses, but makes sure for now
    that the recursor at least connects to the protobuf server.
    """

    _confdir = 'OutgoingProtobufWithECSMapping'
    _config_template = """
    # Switch off QName Minimization, it generates much more protobuf messages
    # (or make the test much more smart!)
    qname-minimization=no
    edns-subnet-allow-list=example
    allow-from=1.2.3.4/32
    # this is to not let . queries interfere
    max-cache-ttl=600
    loglevel=9
"""
    _lua_config_file = """
    outgoingProtobufServer({"127.0.0.1:%d", "127.0.0.1:%d"})
    addProxyMapping("127.0.0.0/8", "1.2.3.4", { "host1.secure.example." })
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)

    def testA(self):
        # There is a race in priming (having the . DNSKEY in cache in particular) and this code.
        # So make sure we have the . DNSKEY in cache
        query = dns.message.make_query('.', 'A', want_dnssec=True)
        query.flags |= dns.flags.RD
        res = self.sendUDPQuery(query)
        time.sleep(1)
        self.emptyProtoBufQueue()

        name = 'host1.secure.example.'
        expected = list()

        for qname, qtype, proto, responseSize, ecs in [
                ('host1.secure.example.', dns.rdatatype.A, dnsmessage_pb2.PBDNSMessage.UDP, 248, "1.2.3.0"),
                ('host1.secure.example.', dns.rdatatype.A, dnsmessage_pb2.PBDNSMessage.UDP, 221, "1.2.3.0"),
                ('example.', dns.rdatatype.DNSKEY, dnsmessage_pb2.PBDNSMessage.UDP, 219, "1.2.3.0"),
                ('host1.secure.example.', dns.rdatatype.A, dnsmessage_pb2.PBDNSMessage.UDP, 175, "1.2.3.0"),
                ('secure.example.', dns.rdatatype.DNSKEY, dnsmessage_pb2.PBDNSMessage.UDP, 233, "1.2.3.0"),
        ]:
            if not qname:
                expected.append((None, None, None, None, None, None, None))
                continue
            ecso = clientsubnetoption.ClientSubnetOption('9.10.11.12', 24)
            query = dns.message.make_query(qname, qtype, use_edns=True, want_dnssec=True, options=[ecso], payload=512)
            resp = dns.message.make_response(query)
            expected.append((
                qname, qtype, query, resp, proto, responseSize, ecs
            ))

        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.RD
        res = self.sendUDPQuery(query)

        for qname, qtype, qry, ans, proto, responseSize, ecs in expected:
            if not qname:
                self.getFirstProtobufMessage()
                self.getFirstProtobufMessage()
                continue

            msg = self.getFirstProtobufMessage()
            self.checkProtobufOutgoingQuery(msg, proto, qry, dns.rdataclass.IN, qtype, qname, "127.0.0.1", None, ecs)
            # Check the answer
            msg = self.getFirstProtobufMessage()
            self.checkProtobufIncomingResponse(msg, proto, ans, length=responseSize)

        self.checkNoRemainingMessage()

        # this query should use the unmapped ECS
        name = 'mx1.secure.example.'
        expected = list()

        for qname, qtype, proto, responseSize, ecs in [
                ('mx1.secure.example.', dns.rdatatype.A, dnsmessage_pb2.PBDNSMessage.UDP, 173, "127.0.0.1"),
        ]:
            if not qname:
                expected.append((None, None, None, None, None, None, None))
                continue
            ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 32)
            query = dns.message.make_query(qname, qtype, use_edns=True, want_dnssec=True, options=[ecso], payload=512)
            resp = dns.message.make_response(query)
            expected.append((
                qname, qtype, query, resp, proto, responseSize, ecs
            ))

        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.RD
        res = self.sendUDPQuery(query)

        for qname, qtype, qry, ans, proto, responseSize, ecs in expected:
            if not qname:
                self.getFirstProtobufMessage()
                self.getFirstProtobufMessage()
                continue

            msg = self.getFirstProtobufMessage()
            self.checkProtobufOutgoingQuery(msg, proto, qry, dns.rdataclass.IN, qtype, qname, "127.0.0.1", None, ecs)
            # Check the answer
            msg = self.getFirstProtobufMessage()
            self.checkProtobufIncomingResponse(msg, proto, ans, length=responseSize)

        self.checkNoRemainingMessage()

class OutgoingProtobufNoQueriesTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export incoming responses but not outgoing queries over protobuf.
    It must be improved and setup env so we can check for incoming responses, but makes sure for now
    that the recursor at least connects to the protobuf server.
    """

    _confdir = 'OutgoingProtobufNoQueries'
    _config_template = """
    # Switch off QName Minimization, it generates much more protobuf messages
    # (or make the test much more smart!)
    qname-minimization=no
    max-cache-ttl=600
    loglevel=9
"""
    _lua_config_file = """
    outgoingProtobufServer({"127.0.0.1:%d", "127.0.0.1:%d"}, { logQueries=false, logResponses=true })
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)

    def testA(self):
        # There is a race in priming (having the . DNSKEY in cache in particular) and this code.
        # So make sure we have the . DNSKEY in cache
        query = dns.message.make_query('.', 'A', want_dnssec=True)
        query.flags |= dns.flags.RD
        res = self.sendUDPQuery(query)
        time.sleep(1)
        self.emptyProtoBufQueue()

        name = 'host1.secure.example.'
        expected = list()
        # the root DNSKEY has been learned with priming the root NS already
        # ('.', dns.rdatatype.DNSKEY, dnsmessage_pb2.PBDNSMessage.UDP, 201),
        for qname, qtype, proto, size in [
                ('host1.secure.example.', dns.rdatatype.A, dnsmessage_pb2.PBDNSMessage.UDP, 248),
                ('host1.secure.example.', dns.rdatatype.A, dnsmessage_pb2.PBDNSMessage.UDP, 221),
                ('example.', dns.rdatatype.DNSKEY, dnsmessage_pb2.PBDNSMessage.UDP, 219),
                ('host1.secure.example.', dns.rdatatype.A, dnsmessage_pb2.PBDNSMessage.UDP, 175),
                ('secure.example.', dns.rdatatype.DNSKEY, dnsmessage_pb2.PBDNSMessage.UDP, 233),
        ]:
            if not qname:
                expected.append((None, None, None, None, None, None))
                continue
            query = dns.message.make_query(qname, qtype, use_edns=True, want_dnssec=True)
            resp = dns.message.make_response(query)
            expected.append((
                qname, qtype, query, resp, proto, size
            ))

        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.RD
        res = self.sendUDPQuery(query)

        for qname, qtype, qry, ans, proto, size in expected:
            if not qname:
                self.getFirstProtobufMessage()
                continue

            # check the response
            msg = self.getFirstProtobufMessage()
            self.checkProtobufIncomingResponse(msg, proto, ans, length=size)

        self.checkNoRemainingMessage()

class ProtobufMasksTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export queries and response over protobuf, respecting the configured initiator masking.
    """

    _confdir = 'ProtobufMasks'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    _protobufMaskV4 = 4
    _protobufMaskV6 = 128
    _lua_config_file = """
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"})
    setProtobufMasks(%d, %d)
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port, _protobufMaskV4, _protobufMaskV6)

    def testA(self):
        name = 'a.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        # check the protobuf messages corresponding to the UDP query and answer
        # but first let the protobuf messages the time to get there
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name, '112.0.0.0')
        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res, '112.0.0.0')
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.42')
        self.checkNoRemainingMessage()

class ProtobufQueriesOnlyTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export queries but not responses over protobuf.
    """

    _confdir = 'ProtobufQueriesOnly'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    _lua_config_file = """
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"}, { logQueries=true, logResponses=false } )
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)

    def testA(self):
        name = 'a.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        # check the protobuf message corresponding to the UDP query
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        # no response
        self.checkNoRemainingMessage()

class ProtobufResponsesOnlyTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export responses but not queries over protobuf.
    """

    _confdir = 'ProtobufResponsesOnly'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    _lua_config_file = """
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"}, { logQueries=false, logResponses=true } )
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)

    def testA(self):
        name = 'a.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        # check the protobuf message corresponding to the UDP response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res)
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.42')
        # nothing else in the queue
        self.checkNoRemainingMessage()

class ProtobufTaggedOnlyTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export queries and responses but only if they have been tagged.
    """

    _confdir = 'ProtobufTaggedOnly'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    _lua_config_file = """
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"}, { logQueries=true, logResponses=true, taggedOnly=true } )
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)
    _tags = ['tag1', 'tag2']
    _tag_from_gettag = 'tag-from-gettag'
    _lua_dns_script_file = """
    function gettag(remote, ednssubnet, localip, qname, qtype, ednsoptions, tcp)
      if qname:equal('tagged.example.') then
        return 0, { '%s' }
      end
      return 0
    end
    function preresolve(dq)
      if dq.qname:equal('tagged.example.') then
        dq:addPolicyTag('%s')
        dq:addPolicyTag('%s')
      end
      return false
    end
    """ % (_tag_from_gettag, _tags[0], _tags[1])

    def testA(self):
        name = 'a.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        for method in ("sendUDPQuery", "sendTCPQuery"):
          sender = getattr(self, method)
          res = sender(query)
          self.assertRRsetInAnswer(res, expected)

          # check the protobuf message corresponding to the UDP response
          # the first query and answer are not tagged, so there is nothing in the queue
          #time.sleep(1)

          self.checkNoRemainingMessage()
          # Again to check PC case
          res = sender(query)
          #time.sleep(1)
          self.checkNoRemainingMessage()

    def testTagged(self):
        name = 'tagged.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.84')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        first = True
        for method in ("sendUDPQuery", "sendTCPQuery"):
          messagetype = dnsmessage_pb2.PBDNSMessage.UDP
          if not first:
             messagetype = dnsmessage_pb2.PBDNSMessage.TCP
          sender = getattr(self, method)
          res = sender(query)
          self.assertRRsetInAnswer(res, expected)

          # check the protobuf messages corresponding to the query and answer
          msg = self.getFirstProtobufMessage()
          self.checkProtobufQuery(msg, messagetype, query, dns.rdataclass.IN, dns.rdatatype.A, name)
          self.checkProtobufTags(msg, [ self._tag_from_gettag ])
          # then the response
          msg = self.getFirstProtobufMessage()
          self.checkProtobufResponse(msg, messagetype, res)
          self.assertEqual(len(msg.response.rrs), 1)
          rr = msg.response.rrs[0]
          # we have max-cache-ttl set to 15, but only check it first iteration
          self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15, checkTTL=first)
          self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.84')
          tags = [ self._tag_from_gettag ] + self._tags
          self.checkProtobufTags(msg, tags)
          self.checkNoRemainingMessage()

          # Again to check PC case
          res = sender(query)
          self.assertRRsetInAnswer(res, expected)

          # check the protobuf messages corresponding to the query and answer
          msg = self.getFirstProtobufMessage()
          self.checkProtobufQuery(msg, messagetype, query, dns.rdataclass.IN, dns.rdatatype.A, name)
          self.checkProtobufTags(msg, [ self._tag_from_gettag ])
          # then the response
          msg = self.getFirstProtobufMessage()
          self.checkProtobufResponse(msg, messagetype, res)
          self.assertEqual(len(msg.response.rrs), 1)
          rr = msg.response.rrs[0]
          # time may have passed, so do not check TTL
          self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15, checkTTL=False)
          self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.84')
          tags = [ self._tag_from_gettag ] + self._tags
          self.checkProtobufTags(msg, tags)
          self.checkNoRemainingMessage()
          first = False

class ProtobufTagCacheBase(TestRecursorProtobuf):
    __test__ = False

    def testTagged(self):
        name = 'tagged.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.84')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res)
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.84')
        self.checkNoRemainingMessage()
        self.assertEqual(len(msg.response.tags), 1)
        ts1 = msg.response.tags[0]

        # Again to check PC case
        res = self.sendUDPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res)
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # time may have passed, so do not check TTL
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15, checkTTL=False)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.84')
        self.checkNoRemainingMessage()
        self.assertEqual(len(msg.response.tags), 1)
        ts2 = msg.response.tags[0]
        self.assertNotEqual(ts1, ts2)

    def testTaggedTCP(self):
        name = 'taggedtcp.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.87')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendTCPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.TCP, res)
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.87')
        self.checkNoRemainingMessage()
        print(msg.response)
        self.assertEqual(len(msg.response.tags), 1)
        ts1 = msg.response.tags[0]

        # Again to check PC case
        res = self.sendTCPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.TCP, res)
        print(msg.response)
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # time may have passed, so do not check TTL
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15, checkTTL=False)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.87')
        self.checkNoRemainingMessage()
        self.assertEqual(len(msg.response.tags), 1)
        ts2 = msg.response.tags[0]
        self.assertNotEqual(ts1, ts2)

class ProtobufTagCacheTest(ProtobufTagCacheBase):
    """
    This test makes sure that we correctly cache tags (actually not cache them)
    """

    __test__ = True
    _confdir = 'ProtobufTagCache'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    _lua_config_file = """
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"}, { logQueries=false, logResponses=true } )
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)
    _lua_dns_script_file = """
    function gettag(remote, ednssubnet, localip, qname, qtype, ednsoptions, tcp)
      if qname:equal('tagged.example.') or qname:equal('taggedtcp.example.') then
        return 0, { '' .. math.random() }
      end
      return 0
    end
    """

class ProtobufTagCacheFFITest(ProtobufTagCacheBase):
    """
    This test makes sure that we correctly cache tags (actually not cache them) for the FFI case
    """

    __test__ = True
    _confdir = 'ProtobufTagCacheFFI'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    _lua_config_file = """
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"}, { logQueries=false, logResponses=true } )
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)
    _lua_dns_script_file = """
    local ffi = require("ffi")

    ffi.cdef[[
      typedef struct pdns_ffi_param pdns_ffi_param_t;

      const char* pdns_ffi_param_get_qname(pdns_ffi_param_t* ref);
      void pdns_ffi_param_add_policytag(pdns_ffi_param_t* ref, const char* name);
    ]]

    function gettag_ffi(obj)
      qname = ffi.string(ffi.C.pdns_ffi_param_get_qname(obj))
      if qname == 'tagged.example' or qname == 'taggedtcp.example' then
        ffi.C.pdns_ffi_param_add_policytag(obj, '' .. math.random())
      end
      return 0
    end
    """

class ProtobufSelectedFromLuaTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export queries and responses but only if they have been selected from Lua.
    """

    _confdir = 'ProtobufSelectedFromLua'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    _lua_config_file = """
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"}, { logQueries=false, logResponses=false } )
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)
    _lua_dns_script_file = """
    local ffi = require("ffi")

    ffi.cdef[[
      typedef struct pdns_ffi_param pdns_ffi_param_t;

      const char* pdns_ffi_param_get_qname(pdns_ffi_param_t* ref);
      void pdns_ffi_param_set_log_query(pdns_ffi_param_t* ref, bool logQuery);
    ]]

    function gettag_ffi(obj)
      qname = ffi.string(ffi.C.pdns_ffi_param_get_qname(obj))
      if qname == 'query-selected.example' then
        ffi.C.pdns_ffi_param_set_log_query(obj, true)
      end
      return 0
    end

    function preresolve(dq)
      if dq.qname:equal('answer-selected.example.') then
        dq.logResponse = true
      end
      return false
    end
    """

    def testA(self):
        name = 'a.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        # check the protobuf message corresponding to the UDP response
        # the first query and answer are not selected, so there is nothing in the queue
        self.checkNoRemainingMessage()

    def testQuerySelected(self):
        name = 'query-selected.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.84')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        # check the protobuf messages corresponding to the UDP query
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        # there should be no response
        self.checkNoRemainingMessage()

    def testResponseSelected(self):
        name = 'answer-selected.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.84')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        # check the protobuf messages corresponding to the UDP response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res)
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.84')
        self.checkNoRemainingMessage()

class ProtobufExportTypesTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export other types than A, AAAA and CNAME over protobuf.
    """

    _confdir = 'ProtobufExportTypes'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    _lua_config_file = """
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"}, { exportTypes={"AAAA", "MX", "SPF", "SRV", "TXT"} } )
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)

    def testA(self):
        name = 'types.example.'
        expected = [dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.84'),
                    dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'AAAA', '2001:DB8::1'),
                    dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'MX', '10 a.example.'),
                    dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'SPF', '"v=spf1 -all"'),
                    dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'SRV', '10 20 443 a.example.'),
                    dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'TXT', '"Lorem ipsum dolor sit amet"'),
                   ]
        query = dns.message.make_query(name, 'ANY', want_dnssec=True)
        query.flags |= dns.flags.CD
        raw = self.sendUDPQuery(query, decode=False)
        res = dns.message.from_wire(raw)

        for rrset in expected:
            self.assertRRsetInAnswer(res, rrset)

        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res, '127.0.0.1', receivedSize=len(raw))
        self.assertEqual(len(msg.response.rrs), 5)
        for rr in msg.response.rrs:
            self.assertTrue(rr.type in [dns.rdatatype.AAAA, dns.rdatatype.TXT, dns.rdatatype.MX, dns.rdatatype.SPF, dns.rdatatype.SRV])

            if rr.type == dns.rdatatype.AAAA:
                self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.AAAA, name, 15)
                self.assertEqual(socket.inet_ntop(socket.AF_INET6, rr.rdata), '2001:db8::1')
            elif rr.type == dns.rdatatype.TXT:
                self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.TXT, name, 15)
                self.assertEqual(rr.rdata, b'"Lorem ipsum dolor sit amet"')
            elif rr.type == dns.rdatatype.MX:
                self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.MX, name, 15)
                self.assertEqual(rr.rdata, b'a.example.')
            elif rr.type == dns.rdatatype.SPF:
                self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.SPF, name, 15)
                self.assertEqual(rr.rdata, b'"v=spf1 -all"')
            elif rr.type == dns.rdatatype.SRV:
                self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.SRV, name, 15)
                self.assertEqual(rr.rdata, b'a.example.')

        self.checkNoRemainingMessage()

class ProtobufTaggedExtraFieldsTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export extra fields that may have been set while being tagged.
    """

    _confdir = 'ProtobufTaggedExtraFields'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    _lua_config_file = """
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"}, { logQueries=true, logResponses=true } )
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)
    _requestorId = 'S-000001727'
    _deviceId = 'd1:0a:91:dc:cc:82'
    _deviceName = 'Joe'
    _lua_dns_script_file = """
    function gettag(remote, ednssubnet, localip, qname, qtype, ednsoptions, tcp)
      if qname:equal('tagged.example.') then
        -- tag number, policy tags, data, requestorId, deviceId, deviceName
        return 0, {}, {}, '%s:'..remote:getPort(), '%s:'..remote:getPort(), '%s:'..remote:getPort()
      end
      return 0
    end
    """ % (_requestorId, _deviceId, _deviceName)

    def testA(self):
        name = 'a.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        # check the protobuf message corresponding to the UDP response
        # the first query and answer are not tagged, so there is nothing in the queue
        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        self.checkProtobufIdentity(msg, '', b'', '')

        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res, '127.0.0.1')
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.42')
        self.checkProtobufIdentity(msg, '', b'', '')
        self.checkNoRemainingMessage()

    def testTagged(self):
        name = 'tagged.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.84')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        port = ':' + str(msg.fromPort)
        self.checkProtobufIdentity(msg, self._requestorId + port, (self._deviceId + port).encode('ascii'), self._deviceName + port)

        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res)
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.84')
        self.checkProtobufIdentity(msg, self._requestorId + port, (self._deviceId + port).encode('ascii'), self._deviceName + port)
        self.checkNoRemainingMessage()

        # Again, but now the PC is involved
        # check the protobuf messages corresponding to the UDP query and answer
        # Re-init socket so we get a different port
        self.setUpSockets();
        res = self.sendUDPQuery(query)
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        port2 = ':' + str(msg.fromPort)
        self.assertNotEqual(port, port2)
        self.checkProtobufIdentity(msg, self._requestorId + port2, (self._deviceId + port2).encode('ascii'), self._deviceName + port2)

        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res)
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.84')
        self.checkProtobufIdentity(msg, self._requestorId + port2, (self._deviceId + port2).encode('ascii'), self._deviceName + port2)
        self.checkNoRemainingMessage()

class ProtobufTaggedExtraFieldsFFITest(ProtobufTaggedExtraFieldsTest):
    """
    This test makes sure that we correctly export extra fields that may have been set while being tagged (FFI version).
    """
    _confdir = 'ProtobufTaggedExtraFieldsFFI'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    _lua_config_file = """
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"}, { logQueries=true, logResponses=true } )
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)
    _lua_dns_script_file = """
    local ffi = require("ffi")

    ffi.cdef[[
      typedef struct pdns_ffi_param pdns_ffi_param_t;

      const char* pdns_ffi_param_get_qname(pdns_ffi_param_t* ref);
      uint16_t pdns_ffi_param_get_remote_port(pdns_ffi_param_t* ref);
      void pdns_ffi_param_set_tag(pdns_ffi_param_t* ref, unsigned int tag);
      void pdns_ffi_param_set_requestorid(pdns_ffi_param_t* ref, const char* name);
      void pdns_ffi_param_set_devicename(pdns_ffi_param_t* ref, const char* name);
      void pdns_ffi_param_set_deviceid(pdns_ffi_param_t* ref, size_t len, const void* name);
    ]]

    function gettag_ffi(obj)
      qname = ffi.string(ffi.C.pdns_ffi_param_get_qname(obj))
      if qname == 'tagged.example' then
        port = ':'..tostring(ffi.C.pdns_ffi_param_get_remote_port(obj))
        ffi.C.pdns_ffi_param_set_requestorid(obj, "%s"..port)
        deviceid = "%s"..port
        ffi.C.pdns_ffi_param_set_deviceid(obj, string.len(deviceid), deviceid)
        ffi.C.pdns_ffi_param_set_devicename(obj, "%s"..port)
      end
      return 0
    end
    """ % (ProtobufTaggedExtraFieldsTest._requestorId, ProtobufTaggedExtraFieldsTest._deviceId, ProtobufTaggedExtraFieldsTest._deviceName)

class ProtobufRPZTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export the RPZ applied policy in our protobuf messages
    """

    _confdir = 'ProtobufRPZ'
    _config_template = """
auth-zones=example=configs/%s/example.rpz.zone""" % _confdir
    _lua_config_file = """
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"}, { logQueries=true, logResponses=true } )
    rpzFile('configs/%s/zone.rpz', { policyName="zone.rpz.", extendedErrorCode=99, extendedErrorExtra="EDEText"})
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port, _confdir)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'example.rpz.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN example.
@ 3600 IN SOA {soa}
sub.test 3600 IN A 192.0.2.42
ip  3600 IN A 33.22.11.99
""".format(soa=cls._SOA))

        rpzFilePath = os.path.join(confdir, 'zone.rpz')
        with open(rpzFilePath, 'w') as rpzZone:
            rpzZone.write("""$ORIGIN zone.rpz.
@ 3600 IN SOA {soa}
*.test.example.zone.rpz. 60 IN CNAME rpz-passthru.
24.0.11.22.33.rpz-ip     60 IN A 1.2.3.4
""".format(soa=cls._SOA))

        super(ProtobufRPZTest, cls).generateRecursorConfig(confdir)

    def testA(self):
        name = 'sub.test.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)

        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res)
        self.checkProtobufPolicy(msg, dnsmessage_pb2.PBDNSMessage.PolicyType.QNAME, 'zone.rpz.', '*.test.example.', 'sub.test.example', dnsmessage_pb2.PBDNSMessage.PolicyKind.NoAction)
        self.checkProtobufEDE(msg, 99, 'EDEText')
        self.checkProtobufOT(msg, False, False)
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.42')
        self.checkNoRemainingMessage()

    def testB(self):
        name = 'ip.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '1.2.3.4')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)

        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res)
        self.checkProtobufPolicy(msg, dnsmessage_pb2.PBDNSMessage.PolicyType.RESPONSEIP, 'zone.rpz.', '24.0.11.22.33.rpz-ip.', '33.22.11.99', dnsmessage_pb2.PBDNSMessage.PolicyKind.Custom)
        self.checkProtobufEDE(msg, 99, 'EDEText')
        self.checkProtobufOT(msg, False, False)
        self.assertEqual(len(msg.response.rrs), 1)
        self.checkNoRemainingMessage()

class ProtobufRPZTagsTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export the RPZ tags in our protobuf messages
    """

    _confdir = 'ProtobufRPZTags'
    _config_template = """
auth-zones=example=configs/%s/example.rpz.zone""" % _confdir
    _tags = ['tag1', 'tag2']
    _tags_from_gettag = ['tag1-from-gettag', 'tag2-from-gettag']
    _tags_from_rpz = ['tag1-from-rpz', 'tag2-from-rpz' ]
    _lua_config_file = """
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"}, { logQueries=true, logResponses=true, tags={'tag1', 'tag2'} } )
    rpzFile('configs/%s/zone.rpz', { policyName="zone.rpz.", tags={ '%s', '%s'} })
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port, _confdir, _tags_from_rpz[0], _tags_from_rpz[1])
    _lua_dns_script_file = """
    function gettag(remote, ednssubnet, localip, qname, qtype, ednsoptions, tcp)
      return 0, { '%s', '%s' }
    end
    function preresolve(dq)
      dq:addPolicyTag('%s')
      dq:addPolicyTag('%s')
      return false
    end
    """ % (_tags_from_gettag[0], _tags_from_gettag[1], _tags[0], _tags[1])

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'example.rpz.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN example.
@ 3600 IN SOA {soa}
sub.test 3600 IN A 192.0.2.42
""".format(soa=cls._SOA))

        rpzFilePath = os.path.join(confdir, 'zone.rpz')
        with open(rpzFilePath, 'w') as rpzZone:
            rpzZone.write("""$ORIGIN zone.rpz.
@ 3600 IN SOA {soa}
*.test.example.zone.rpz. 60 IN CNAME rpz-passthru.
""".format(soa=cls._SOA))

        super(ProtobufRPZTagsTest, cls).generateRecursorConfig(confdir)

    def testA(self):
        name = 'sub.test.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)

        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res)
        self.checkProtobufPolicy(msg, dnsmessage_pb2.PBDNSMessage.PolicyType.QNAME, 'zone.rpz.', '*.test.example.', 'sub.test.example', dnsmessage_pb2.PBDNSMessage.PolicyKind.NoAction)
        self.checkProtobufTags(msg, self._tags + self._tags_from_gettag + self._tags_from_rpz)
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.42')
        self.checkNoRemainingMessage()


class ProtobufMetaFFITest(TestRecursorProtobuf):
    """
    This test makes sure that we can correctly add extra meta fields (FFI version).
    """
    _confdir = 'ProtobufMetaFFI'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    _lua_config_file = """
    protobufServer({"127.0.0.1:%d", "127.0.0.1:%d"}, { logQueries=true, logResponses=true } )
    """ % (protobufServersParameters[0].port, protobufServersParameters[1].port)
    _lua_dns_script_file = """
    local ffi = require("ffi")

    ffi.cdef[[
      typedef struct pdns_ffi_param pdns_ffi_param_t;

      const char* pdns_ffi_param_get_qname(pdns_ffi_param_t* ref);
      void pdns_ffi_param_add_meta_single_string_kv(pdns_ffi_param_t *ref, const char* key, const char* val);
      void pdns_ffi_param_add_meta_single_int64_kv(pdns_ffi_param_t *ref, const char* key, int64_t val);
    ]]

    function gettag_ffi(obj)
      qname = ffi.string(ffi.C.pdns_ffi_param_get_qname(obj))
      if qname == 'meta.example' then
        ffi.C.pdns_ffi_param_add_meta_single_string_kv(obj, "meta-str", "keyword")
        ffi.C.pdns_ffi_param_add_meta_single_int64_kv(obj, "meta-int", 42)
        ffi.C.pdns_ffi_param_add_meta_single_string_kv(obj, "meta-str", "content")
        ffi.C.pdns_ffi_param_add_meta_single_int64_kv(obj, "meta-int", 21)
      end
      return 0
    end
    """
    def testMeta(self):
        name = 'meta.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.85')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        self.checkProtobufMetas(msg, {'meta-str': { "stringVal" : ["content", "keyword"]}, 'meta-int': {"intVal" : [21, 42]}})

        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res)
        self.assertEqual(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.85')
        self.checkProtobufMetas(msg, {'meta-str': { "stringVal" : ["content", "keyword"]}, 'meta-int': {"intVal" : [21, 42]}})

        self.checkNoRemainingMessage()
