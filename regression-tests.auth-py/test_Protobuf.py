# carefully plagiarised from regression-tests.recursor-dnssec/test_Protobuf.py
# if we add more features, we can grab more inspiration there

import dns
import dnsmessage_pb2
import os
import socket
import struct
import sys
import threading
import time
import clientsubnetoption
from queue import Queue

from authtests import AuthTest

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

protobufServersParameters = [ProtobufServerParams(4243)]
protobufListeners = []
for param in protobufServersParameters:
  listener = threading.Thread(name='Protobuf Listener', target=ProtobufListener, args=[param.queue, param.port])
  listener.daemon = True
  listener.start()
  protobufListeners.append(listener)

class TestAuthProtobuf(AuthTest):

    _config_template = """
expand-alias=yes
launch={backend}
protobuf-servers=127.0.0.1:%s
""" % (protobufServersParameters[0].port,)

    _zones = {
        'example': """
example.                 3600 IN SOA  {soa}
example.                 3600 IN NS   ns1.example.
example.                 3600 IN NS   ns2.example.
ns1.example.             3600 IN A    {prefix}.10
ns2.example.             3600 IN A    {prefix}.11

a.example.               3600 IN A    192.0.2.80
        """,
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

    def checkProtobufResponse(self, msg, protocol, response, initiator='127.0.0.1', receivedSize=None):
        self.assertEqual(msg.type, dnsmessage_pb2.PBDNSMessage.DNSResponseType)
        self.checkProtobufBase(msg, protocol, response, initiator, receivedSize=receivedSize)

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

    def setUp(self):
        super(TestAuthProtobuf, self).setUp()
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
        super(TestAuthProtobuf, cls).generateRecursorConfig(confdir)


class ProtobufDefaultTest(TestAuthProtobuf):
    """
    This test makes sure that we correctly export queries and response over protobuf.
    """

    _confdir = 'ProtobufDefault'

    def testA(self):
        name = 'a.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)

        res = self.sendUDPQuery(query)

        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        self.checkProtobufHeaderFlagsAndEDNSVersion(msg, 0x0100, 0x00000000)
        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res, '127.0.0.1')
        self.checkNoRemainingMessage()
        #
        # again, for a PC cache hit
        #
        res = self.sendUDPQuery(query)

        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        self.checkProtobufHeaderFlagsAndEDNSVersion(msg, 0x0100, 0x00000000)
        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res, '127.0.0.1')
        self.checkNoRemainingMessage()

    def testCNAME(self):
        name = 'cname.example.'
        expectedCNAME = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'CNAME', 'a.example.')
        expectedA = dns.rrset.from_text('a.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        raw = self.sendUDPQuery(query, decode=False)
        res = dns.message.from_wire(raw)

        # check the protobuf messages corresponding to the UDP query and answer
        # but first let the protobuf messages the time to get there
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res, '127.0.0.1', receivedSize=len(raw))
        self.checkNoRemainingMessage()
