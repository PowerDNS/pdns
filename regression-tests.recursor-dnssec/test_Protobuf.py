import dns
import dnsmessage_pb2
import os
import socket
import struct
import sys
import threading
import time

# Python2/3 compatibility hacks
if sys.version_info[0] == 2:
  from Queue import Queue
  range = xrange
else:
  from queue import Queue
  range = range  # allow re-export of the builtin name

from recursortests import RecursorTest

protobufQueue = Queue()
protobufServerPort = 4243

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

        queue.put(data, True, timeout=2.0)

    conn.close()

def ProtobufListener(port):
    global protobufQueue
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
                                      args=[protobufQueue, conn])
            thread.setDaemon(True)
            thread.start()

        except socket.error as e:
            print('Error in protobuf socket: %s' % str(e))

    sock.close()


protobufListener = threading.Thread(name='Protobuf Listener', target=ProtobufListener, args=[protobufServerPort])
protobufListener.setDaemon(True)
protobufListener.start()

class TestRecursorProtobuf(RecursorTest):

    global protobufServerPort
    _lua_config_file = """
    protobufServer("127.0.0.1:%d")
    """ % (protobufServerPort)


    def getFirstProtobufMessage(self, retries=1, waitTime=1):
        global protobufQueue
        failed = 0

        while protobufQueue.empty:
          if failed >= retries:
            break

          failed = failed + 1
          time.sleep(waitTime)

        self.assertFalse(protobufQueue.empty())
        data = protobufQueue.get(False)
        self.assertTrue(data)
        msg = dnsmessage_pb2.PBDNSMessage()
        msg.ParseFromString(data)
        return msg

    def checkNoRemainingMessage(self):
        global protobufQueue
        self.assertTrue(protobufQueue.empty())

    def checkProtobufBase(self, msg, protocol, query, initiator, normalQueryResponse=True, expectedECS=None):
        self.assertTrue(msg)
        self.assertTrue(msg.HasField('timeSec'))
        self.assertTrue(msg.HasField('socketFamily'))
        self.assertEquals(msg.socketFamily, dnsmessage_pb2.PBDNSMessage.INET)
        self.assertTrue(msg.HasField('from'))
        fromvalue = getattr(msg, 'from')
        self.assertEquals(socket.inet_ntop(socket.AF_INET, fromvalue), initiator)
        self.assertTrue(msg.HasField('socketProtocol'))
        self.assertEquals(msg.socketProtocol, protocol)
        self.assertTrue(msg.HasField('messageId'))
        self.assertTrue(msg.HasField('serverIdentity'))
        self.assertTrue(msg.HasField('id'))
        self.assertEquals(msg.id, query.id)
        self.assertTrue(msg.HasField('inBytes'))
        if normalQueryResponse:
            # compare inBytes with length of query/response
            self.assertEquals(msg.inBytes, len(query.to_wire()))
        if expectedECS is not None:
            self.assertTrue(msg.HasField('originalRequestorSubnet'))
            # v4 only for now
            self.assertEquals(len(msg.originalRequestorSubnet), 4)
            self.assertEquals(socket.inet_ntop(socket.AF_INET, msg.originalRequestorSubnet), '127.0.0.1')

    def checkOutgoingProtobufBase(self, msg, protocol, query, initiator):
        self.assertTrue(msg)
        self.assertTrue(msg.HasField('timeSec'))
        self.assertTrue(msg.HasField('socketFamily'))
        self.assertEquals(msg.socketFamily, dnsmessage_pb2.PBDNSMessage.INET)
        self.assertTrue(msg.HasField('socketProtocol'))
        self.assertEquals(msg.socketProtocol, protocol)
        self.assertTrue(msg.HasField('messageId'))
        self.assertTrue(msg.HasField('serverIdentity'))
        self.assertTrue(msg.HasField('id'))
        self.assertNotEquals(msg.id, query.id)
        self.assertTrue(msg.HasField('inBytes'))
        # compare inBytes with length of query/response
        self.assertEquals(msg.inBytes, len(query.to_wire()))

    def checkProtobufQuery(self, msg, protocol, query, qclass, qtype, qname, initiator='127.0.0.1'):
        self.assertEquals(msg.type, dnsmessage_pb2.PBDNSMessage.DNSQueryType)
        self.checkProtobufBase(msg, protocol, query, initiator)
        # dnsdist doesn't fill the responder field for responses
        # because it doesn't keep the information around.
        self.assertTrue(msg.HasField('to'))
        self.assertEquals(socket.inet_ntop(socket.AF_INET, msg.to), '127.0.0.1')
        self.assertTrue(msg.HasField('question'))
        self.assertTrue(msg.question.HasField('qClass'))
        self.assertEquals(msg.question.qClass, qclass)
        self.assertTrue(msg.question.HasField('qType'))
        self.assertEquals(msg.question.qClass, qtype)
        self.assertTrue(msg.question.HasField('qName'))
        self.assertEquals(msg.question.qName, qname)

    def checkProtobufResponse(self, msg, protocol, response, initiator='127.0.0.1'):
        self.assertEquals(msg.type, dnsmessage_pb2.PBDNSMessage.DNSResponseType)
        self.checkProtobufBase(msg, protocol, response, initiator)
        self.assertTrue(msg.HasField('response'))
        self.assertTrue(msg.response.HasField('queryTimeSec'))

    def checkProtobufResponseRecord(self, record, rclass, rtype, rname, rttl):
        self.assertTrue(record.HasField('class'))
        self.assertEquals(getattr(record, 'class'), rclass)
        self.assertTrue(record.HasField('type'))
        self.assertEquals(record.type, rtype)
        self.assertTrue(record.HasField('name'))
        self.assertEquals(record.name, rname)
        self.assertTrue(record.HasField('ttl'))
        self.assertEquals(record.ttl, rttl)
        self.assertTrue(record.HasField('rdata'))

    def checkProtobufPolicy(self, msg, policyType, reason):
        self.assertEquals(msg.type, dnsmessage_pb2.PBDNSMessage.DNSResponseType)
        self.assertTrue(msg.response.HasField('appliedPolicyType'))
        self.assertTrue(msg.response.HasField('appliedPolicy'))
        self.assertEquals(msg.response.appliedPolicy, reason)
        self.assertEquals(msg.response.appliedPolicyType, policyType)

    def checkProtobufTags(self, msg, tags):
        self.assertEquals(len(msg.response.tags), len(tags))
        for tag in msg.response.tags:
            self.assertTrue(tag in tags)

    def checkProtobufOutgoingQuery(self, msg, protocol, query, qclass, qtype, qname, initiator='127.0.0.1'):
        self.assertEquals(msg.type, dnsmessage_pb2.PBDNSMessage.DNSOutgoingQueryType)
        self.checkOutgoingProtobufBase(msg, protocol, query, initiator)
        self.assertTrue(msg.HasField('to'))
        self.assertTrue(msg.HasField('question'))
        self.assertTrue(msg.question.HasField('qClass'))
        self.assertEquals(msg.question.qClass, qclass)
        self.assertTrue(msg.question.HasField('qType'))
        self.assertEquals(msg.question.qClass, qtype)
        self.assertTrue(msg.question.HasField('qName'))
        self.assertEquals(msg.question.qName, qname)

    def checkProtobufIncomingResponse(self, msg, protocol, response, initiator='127.0.0.1'):
        self.assertEquals(msg.type, dnsmessage_pb2.PBDNSMessage.DNSIncomingResponseType)
        self.checkOutgoingProtobufBase(msg, protocol, response, initiator)
        self.assertTrue(msg.HasField('response'))
        self.assertTrue(msg.response.HasField('queryTimeSec'))

    @classmethod
    def setUpClass(cls):

        global protobufListener
        global protobufServerPort
        global ProtobufListener
        if protobufListener is None or not protobufListener.isAlive():
            protobufListener = threading.Thread(name='Protobuf Listener', target=ProtobufListener, args=[protobufServerPort])
            protobufListener.setDaemon(True)
            protobufListener.start()

        cls.setUpSockets()

        cls.startResponders()

        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)

        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

    def setUp(self):
      # Make sure the queue is empty, in case
      # a previous test failed
      global protobufQueue
      while not protobufQueue.empty():
        protobufQueue.get(False)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'example.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN example.
@ 3600 IN SOA {soa}
a 3600 IN A 192.0.2.42
tagged 3600 IN A 192.0.2.84
query-selected 3600 IN A 192.0.2.84
answer-selected 3600 IN A 192.0.2.84
""".format(soa=cls._SOA))
        super(TestRecursorProtobuf, cls).generateRecursorConfig(confdir)

    @classmethod
    def tearDownClass(cls):
        cls.tearDownRecursor()

class ProtobufDefaultTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export queries and response over protobuf.
    """

    _confdir = 'ProtobufDefault'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir

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
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res)
        self.assertEquals(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEquals(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.42')
        self.checkNoRemainingMessage()

class OutgoingProtobufDefaultTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export outgoing queries over protobuf.
    It must be improved and setup env so we can check for incoming responses, but makes sure for now
    that the recursor at least connects to the protobuf server.
    """

    _confdir = 'OutgoingProtobufDefault'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    _lua_config_file = """
    outgoingProtobufServer("127.0.0.1:%d")
    """ % (protobufServerPort)

    def testA(self):
        name = 'www.example.org.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.RD
        res = self.sendUDPQuery(query)

        # check the protobuf messages corresponding to the UDP query and answer
        msg = self.getFirstProtobufMessage()
        self.checkProtobufOutgoingQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
#        # then the response
#        msg = self.getFirstProtobufMessage()
#        self.checkProtobufIncomingResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res)
        self.checkNoRemainingMessage()

class ProtobufMasksTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export queries and response over protobuf, respecting the configured initiator masking.
    """

    _confdir = 'ProtobufMasks'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    global protobufServerPort
    _protobufMaskV4 = 4
    _protobufMaskV6 = 128
    _lua_config_file = """
    protobufServer("127.0.0.1:%d")
    setProtobufMasks(%d, %d)
    """ % (protobufServerPort, _protobufMaskV4, _protobufMaskV6)

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
        self.assertEquals(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEquals(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.42')
        self.checkNoRemainingMessage()

class ProtobufQueriesOnlyTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export queries but not responses over protobuf.
    """

    _confdir = 'ProtobufQueriesOnly'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    global protobufServerPort
    _lua_config_file = """
    protobufServer("127.0.0.1:%d", { logQueries=true, logResponses=false } )
    """ % (protobufServerPort)

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
    global protobufServerPort
    _lua_config_file = """
    protobufServer("127.0.0.1:%d", { logQueries=false, logResponses=true } )
    """ % (protobufServerPort)

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
        self.assertEquals(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEquals(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.42')
        # nothing else in the queue
        self.checkNoRemainingMessage()

class ProtobufTaggedOnlyTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export queries and responses but only if they have been tagged.
    """

    _confdir = 'ProtobufTaggedOnly'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    global protobufServerPort
    _lua_config_file = """
    protobufServer("127.0.0.1:%d", { logQueries=true, logResponses=true, taggedOnly=true } )
    """ % (protobufServerPort)
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
        res = self.sendUDPQuery(query)
        self.assertRRsetInAnswer(res, expected)

        # check the protobuf message corresponding to the UDP response
        # the first query and answer are not tagged, so there is nothing in the queue
        time.sleep(1)
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
        self.checkProtobufTags(msg, [self._tag_from_gettag])
        # then the response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, res)
        self.assertEquals(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEquals(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.84')
        tags = [self._tag_from_gettag] + self._tags
        self.checkProtobufTags(msg, tags)
        self.checkNoRemainingMessage()

class ProtobufSelectedFromLuaTest(TestRecursorProtobuf):
    """
    This test makes sure that we correctly export queries and responses but only if they have been selected from Lua.
    """

    _confdir = 'ProtobufSelectedFromLua'
    _config_template = """
auth-zones=example=configs/%s/example.zone""" % _confdir
    global protobufServerPort
    _lua_config_file = """
    protobufServer("127.0.0.1:%d", { logQueries=false, logResponses=false } )
    """ % (protobufServerPort)
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
        self.assertEquals(len(msg.response.rrs), 1)
        rr = msg.response.rrs[0]
        # we have max-cache-ttl set to 15
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 15)
        self.assertEquals(socket.inet_ntop(socket.AF_INET, rr.rdata), '192.0.2.84')
        self.checkNoRemainingMessage()
