#!/usr/bin/env python
import threading
import socket
import struct
import sys
import time
from dnsdisttests import DNSDistTest, Queue

import dns
import dnsmessage_pb2

class DNSDistProtobufTest(DNSDistTest):
    _protobufServerPort = 4242
    _protobufQueue = Queue()
    _protobufServerID = 'dnsdist-server-1'
    _protobufCounter = 0

    @classmethod
    def ProtobufListener(cls, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except socket.error as e:
            print("Error binding in the protbuf listener: %s" % str(e))
            sys.exit(1)

        sock.listen(100)
        while True:
            (conn, _) = sock.accept()
            data = None
            while True:
                data = conn.recv(2)
                if not data:
                    break
                (datalen,) = struct.unpack("!H", data)
                data = conn.recv(datalen)
                if not data:
                    break

                cls._protobufQueue.put(data, True, timeout=2.0)

            conn.close()
        sock.close()

    @classmethod
    def startResponders(cls):
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder.setDaemon(True)
        cls._UDPResponder.start()

        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._TCPResponder.setDaemon(True)
        cls._TCPResponder.start()

        cls._protobufListener = threading.Thread(name='Protobuf Listener', target=cls.ProtobufListener, args=[cls._protobufServerPort])
        cls._protobufListener.setDaemon(True)
        cls._protobufListener.start()

    def getFirstProtobufMessage(self):
        self.assertFalse(self._protobufQueue.empty())
        data = self._protobufQueue.get(False)
        self.assertTrue(data)
        msg = dnsmessage_pb2.PBDNSMessage()
        msg.ParseFromString(data)
        return msg

    def checkProtobufBase(self, msg, protocol, query, initiator, normalQueryResponse=True):
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
        self.assertTrue(msg.HasField('id'))
        self.assertEquals(msg.id, query.id)
        self.assertTrue(msg.HasField('inBytes'))
        self.assertTrue(msg.HasField('serverIdentity'))
        self.assertEquals(msg.serverIdentity, self._protobufServerID.encode('utf-8'))

        if normalQueryResponse:
          # compare inBytes with length of query/response
          self.assertEquals(msg.inBytes, len(query.to_wire()))
        # dnsdist doesn't set the existing EDNS Subnet for now,
        # although it might be set from Lua
        # self.assertTrue(msg.HasField('originalRequestorSubnet'))
        # self.assertEquals(len(msg.originalRequestorSubnet), 4)
        # self.assertEquals(socket.inet_ntop(socket.AF_INET, msg.originalRequestorSubnet), '127.0.0.1')

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

    def checkProtobufTags(self, tags, expectedTags):
        # only differences will be in new list
        listx = set(tags) ^ set(expectedTags)
        # exclusive or of lists should be empty
        self.assertEqual(len(listx), 0, "Protobuf tags don't match")

    def checkProtobufQueryConvertedToResponse(self, msg, protocol, response, initiator='127.0.0.0'):
        self.assertEquals(msg.type, dnsmessage_pb2.PBDNSMessage.DNSResponseType)
        # skip comparing inBytes (size of the query) with the length of the generated response
        self.checkProtobufBase(msg, protocol, response, initiator, False)
        self.assertTrue(msg.HasField('response'))
        self.assertTrue(msg.response.HasField('queryTimeSec'))

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

class TestProtobuf(DNSDistProtobufTest):
    _config_params = ['_testServerPort', '_protobufServerPort', '_protobufServerID', '_protobufServerID']
    _config_template = """
    luasmn = newSuffixMatchNode()
    luasmn:add(newDNSName('lua.protobuf.tests.powerdns.com.'))

    function alterProtobufResponse(dq, protobuf)
      if luasmn:check(dq.qname) then
        requestor = newCA(dq.remoteaddr:toString())		-- called by testLuaProtobuf()
        if requestor:isIPv4() then
          requestor:truncate(24)
        else
          requestor:truncate(56)
        end
        protobuf:setRequestor(requestor)

        local tableTags = {}
        table.insert(tableTags, "TestLabel1,TestData1")
        table.insert(tableTags, "TestLabel2,TestData2")

        protobuf:setTagArray(tableTags)

        protobuf:setTag('TestLabel3,TestData3')

        protobuf:setTag("Response,456")

      else

        local tableTags = {} 					-- called by testProtobuf()
        table.insert(tableTags, "TestLabel1,TestData1")
        table.insert(tableTags, "TestLabel2,TestData2")
        protobuf:setTagArray(tableTags)

        protobuf:setTag('TestLabel3,TestData3')

        protobuf:setTag("Response,456")

      end
    end

    function alterProtobufQuery(dq, protobuf)

      if luasmn:check(dq.qname) then
        requestor = newCA(dq.remoteaddr:toString())		-- called by testLuaProtobuf()
        if requestor:isIPv4() then
          requestor:truncate(24)
        else
          requestor:truncate(56)
        end
        protobuf:setRequestor(requestor)

        local tableTags = {}
        tableTags = dq:getTagArray()				-- get table from DNSQuery

        local tablePB = {}
          for k, v in pairs( tableTags) do
          table.insert(tablePB, k .. "," .. v)
        end

        protobuf:setTagArray(tablePB)				-- store table in protobuf
        protobuf:setTag("Query,123")				-- add another tag entry in protobuf

        protobuf:setResponseCode(DNSRCode.NXDOMAIN)        	-- set protobuf response code to be NXDOMAIN

        local strReqName = dq.qname:toString()		  	-- get request dns name

        protobuf:setProtobufResponseType()			-- set protobuf to look like a response and not a query, with 0 default time

        blobData = '\127' .. '\000' .. '\000' .. '\001'		-- 127.0.0.1, note: lua 5.1 can only embed decimal not hex

        protobuf:addResponseRR(strReqName, 1, 1, 123, blobData) -- add a RR to the protobuf

        protobuf:setBytes(65)					-- set the size of the query to confirm in checkProtobufBase

      else

        local tableTags = {}                                    -- called by testProtobuf()
        table.insert(tableTags, "TestLabel1,TestData1")
        table.insert(tableTags, "TestLabel2,TestData2")

        protobuf:setTagArray(tableTags)
        protobuf:setTag('TestLabel3,TestData3')
        protobuf:setTag("Query,123")

      end
    end

    function alterLuaFirst(dq)					-- called when dnsdist receives new request
      local tt = {}
      tt["TestLabel1"] = "TestData1"
      tt["TestLabel2"] = "TestData2"

      dq:setTagArray(tt)

      dq:setTag("TestLabel3","TestData3")
      return DNSAction.None, ""				-- continue to the next rule
    end

    newServer{address="127.0.0.1:%s", useClientSubnet=true}
    rl = newRemoteLogger('127.0.0.1:%s')

    addAction(AllRule(), LuaAction(alterLuaFirst))							-- Add tags to DNSQuery first

    addAction(AllRule(), RemoteLogAction(rl, alterProtobufQuery, {serverID='%s'}))				-- Send protobuf message before lookup

    addResponseAction(AllRule(), RemoteLogResponseAction(rl, alterProtobufResponse, true, {serverID='%s'}))	-- Send protobuf message after lookup

    """

    def testProtobuf(self):
        """
        Protobuf: Send data to a protobuf server
        """
        name = 'query.protobuf.tests.powerdns.com.'

        target = 'target.protobuf.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    target)
        response.answer.append(rrset)

        rrset = dns.rrset.from_text(target,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        # let the protobuf messages the time to get there
        time.sleep(1)

        # check the protobuf message corresponding to the UDP query
        msg = self.getFirstProtobufMessage()

        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        self.checkProtobufTags(msg.response.tags, [u"TestLabel1,TestData1", u"TestLabel2,TestData2", u"TestLabel3,TestData3", u"Query,123"])

        # check the protobuf message corresponding to the UDP response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, response)
        self.checkProtobufTags(msg.response.tags, [ u"TestLabel1,TestData1", u"TestLabel2,TestData2", u"TestLabel3,TestData3", u"Response,456"])
        self.assertEquals(len(msg.response.rrs), 2)
        rr = msg.response.rrs[0]
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.CNAME, name, 3600)
        self.assertEquals(rr.rdata.decode('utf-8'), target)
        rr = msg.response.rrs[1]
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, target, 3600)
        self.assertEquals(socket.inet_ntop(socket.AF_INET, rr.rdata), '127.0.0.1')

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        # let the protobuf messages the time to get there
        time.sleep(1)

        # check the protobuf message corresponding to the TCP query
        msg = self.getFirstProtobufMessage()

        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.TCP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        self.checkProtobufTags(msg.response.tags, [u"TestLabel1,TestData1", u"TestLabel2,TestData2", u"TestLabel3,TestData3", u"Query,123"])

        # check the protobuf message corresponding to the TCP response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.TCP, response)
        self.checkProtobufTags(msg.response.tags, [ u"TestLabel1,TestData1", u"TestLabel2,TestData2", u"TestLabel3,TestData3", u"Response,456"])
        self.assertEquals(len(msg.response.rrs), 2)
        rr = msg.response.rrs[0]
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.CNAME, name, 3600)
        self.assertEquals(rr.rdata.decode('utf-8'), target)
        rr = msg.response.rrs[1]
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, target, 3600)
        self.assertEquals(socket.inet_ntop(socket.AF_INET, rr.rdata), '127.0.0.1')

    def testLuaProtobuf(self):

        """
        Protobuf: Check that the Lua callback rewrote the initiator
        """
        name = 'lua.protobuf.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)


        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)

        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)


        # let the protobuf messages the time to get there
        time.sleep(1)

        # check the protobuf message corresponding to the UDP query
        msg = self.getFirstProtobufMessage()

        self.checkProtobufQueryConvertedToResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, response, '127.0.0.0')
        self.checkProtobufTags(msg.response.tags, [ u"TestLabel1,TestData1", u"TestLabel2,TestData2", u"TestLabel3,TestData3", u"Query,123"])

        # check the protobuf message corresponding to the UDP response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, response, '127.0.0.0')
        self.checkProtobufTags(msg.response.tags, [ u"TestLabel1,TestData1", u"TestLabel2,TestData2", u"TestLabel3,TestData3", u"Response,456"])
        self.assertEquals(len(msg.response.rrs), 1)
        for rr in msg.response.rrs:
            self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 3600)
            self.assertEquals(socket.inet_ntop(socket.AF_INET, rr.rdata), '127.0.0.1')

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        # let the protobuf messages the time to get there
        time.sleep(1)

        # check the protobuf message corresponding to the TCP query
        msg = self.getFirstProtobufMessage()
        self.checkProtobufQueryConvertedToResponse(msg, dnsmessage_pb2.PBDNSMessage.TCP, response, '127.0.0.0')
        self.checkProtobufTags(msg.response.tags, [ u"TestLabel1,TestData1", u"TestLabel2,TestData2", u"TestLabel3,TestData3", u"Query,123"])

        # check the protobuf message corresponding to the TCP response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.TCP, response, '127.0.0.0')
        self.checkProtobufTags(msg.response.tags, [ u"TestLabel1,TestData1", u"TestLabel2,TestData2", u"TestLabel3,TestData3", u"Response,456"])
        self.assertEquals(len(msg.response.rrs), 1)
        for rr in msg.response.rrs:
            self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 3600)
            self.assertEquals(socket.inet_ntop(socket.AF_INET, rr.rdata), '127.0.0.1')

class TestProtobufIPCipher(DNSDistProtobufTest):
    _config_params = ['_testServerPort', '_protobufServerPort', '_protobufServerID', '_protobufServerID']
    _config_template = """
    newServer{address="127.0.0.1:%s", useClientSubnet=true}
    key = makeIPCipherKey("some 16-byte key")
    rl = newRemoteLogger('127.0.0.1:%s')
    addAction(AllRule(), RemoteLogAction(rl, nil, {serverID='%s', ipEncryptKey=key})) -- Send protobuf message before lookup
    addResponseAction(AllRule(), RemoteLogResponseAction(rl, nil, true, {serverID='%s', ipEncryptKey=key})) -- Send protobuf message after lookup

    """

    def testProtobuf(self):
        """
        Protobuf: Send data to a protobuf server
        """
        name = 'query.protobuf-ipcipher.tests.powerdns.com.'

        target = 'target.protobuf-ipcipher.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    target)
        response.answer.append(rrset)

        rrset = dns.rrset.from_text(target,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        # let the protobuf messages the time to get there
        time.sleep(1)

        # check the protobuf message corresponding to the UDP query
        msg = self.getFirstProtobufMessage()

        # 108.41.239.98 is 127.0.0.1 pseudonymized with ipcipher and the current key
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name, '108.41.239.98')

        # check the protobuf message corresponding to the UDP response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, response, '108.41.239.98')

        self.assertEquals(len(msg.response.rrs), 2)
        rr = msg.response.rrs[0]
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.CNAME, name, 3600)
        self.assertEquals(rr.rdata.decode('ascii'), target)
        rr = msg.response.rrs[1]
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, target, 3600)
        self.assertEquals(socket.inet_ntop(socket.AF_INET, rr.rdata), '127.0.0.1')

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        # let the protobuf messages the time to get there
        time.sleep(1)

        # check the protobuf message corresponding to the TCP query
        msg = self.getFirstProtobufMessage()
        # 108.41.239.98 is 127.0.0.1 pseudonymized with ipcipher and the current key
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.TCP, query, dns.rdataclass.IN, dns.rdatatype.A, name, '108.41.239.98')

        # check the protobuf message corresponding to the TCP response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.TCP, response, '108.41.239.98')
        self.assertEquals(len(msg.response.rrs), 2)
        rr = msg.response.rrs[0]
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.CNAME, name, 3600)
        self.assertEquals(rr.rdata.decode('ascii'), target)
        rr = msg.response.rrs[1]
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, target, 3600)
        self.assertEquals(socket.inet_ntop(socket.AF_INET, rr.rdata), '127.0.0.1')
