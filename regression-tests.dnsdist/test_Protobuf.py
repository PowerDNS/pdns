#!/usr/bin/env python
import base64
import threading
import socket
import struct
import sys
import time
from dnsdisttests import DNSDistTest, pickAvailablePort, Queue
from proxyprotocol import ProxyProtocol

import dns
import dnsmessage_pb2

class DNSDistProtobufTest(DNSDistTest):
    _protobufServerPort = pickAvailablePort()
    _protobufQueue = Queue()
    _protobufServerID = 'dnsdist-server-1'
    _protobufCounter = 0

    @classmethod
    def ProtobufListener(cls, port):
        cls._backgroundThreads[threading.get_native_id()] = True
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except socket.error as e:
            print("Error binding in the protbuf listener: %s" % str(e))
            sys.exit(1)

        sock.listen(100)
        sock.settimeout(1.0)
        while True:
            try:
                (conn, _) = sock.accept()
            except socket.timeout:
                if cls._backgroundThreads.get(threading.get_native_id(), False) == False:
                    del cls._backgroundThreads[threading.get_native_id()]
                    break
                else:
                    continue

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
        cls._UDPResponder.daemon = True
        cls._UDPResponder.start()

        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._TCPResponder.daemon = True
        cls._TCPResponder.start()

        cls._protobufListener = threading.Thread(name='Protobuf Listener', target=cls.ProtobufListener, args=[cls._protobufServerPort])
        cls._protobufListener.daemon = True
        cls._protobufListener.start()

    def getFirstProtobufMessage(self):
        self.assertFalse(self._protobufQueue.empty())
        data = self._protobufQueue.get(False)
        self.assertTrue(data)
        msg = dnsmessage_pb2.PBDNSMessage()
        msg.ParseFromString(data)
        return msg

    def checkProtobufBase(self, msg, protocol, query, initiator, normalQueryResponse=True, v6=False):
        self.assertTrue(msg)
        self.assertTrue(msg.HasField('timeSec'))
        self.assertTrue(msg.HasField('socketFamily'))
        if v6:
            self.assertEqual(msg.socketFamily, dnsmessage_pb2.PBDNSMessage.INET6)
        else:
            self.assertEqual(msg.socketFamily, dnsmessage_pb2.PBDNSMessage.INET)
        self.assertTrue(msg.HasField('from'))
        fromvalue = getattr(msg, 'from')
        if v6:
            self.assertEqual(socket.inet_ntop(socket.AF_INET6, fromvalue), initiator)
        else:
            self.assertEqual(socket.inet_ntop(socket.AF_INET, fromvalue), initiator)
        self.assertTrue(msg.HasField('socketProtocol'))
        self.assertEqual(msg.socketProtocol, protocol)
        self.assertTrue(msg.HasField('messageId'))
        self.assertTrue(msg.HasField('id'))
        self.assertEqual(msg.id, query.id)
        self.assertTrue(msg.HasField('inBytes'))
        self.assertTrue(msg.HasField('serverIdentity'))
        self.assertEqual(msg.serverIdentity, self._protobufServerID.encode('utf-8'))

        if normalQueryResponse and (protocol == dnsmessage_pb2.PBDNSMessage.UDP or protocol == dnsmessage_pb2.PBDNSMessage.TCP):
          # compare inBytes with length of query/response
          self.assertEqual(msg.inBytes, len(query.to_wire()))
        # dnsdist doesn't set the existing EDNS Subnet for now,
        # although it might be set from Lua
        # self.assertTrue(msg.HasField('originalRequestorSubnet'))
        # self.assertEqual(len(msg.originalRequestorSubnet), 4)
        # self.assertEqual(socket.inet_ntop(socket.AF_INET, msg.originalRequestorSubnet), '127.0.0.1')

    def checkProtobufQuery(self, msg, protocol, query, qclass, qtype, qname, initiator='127.0.0.1', v6=False):
        self.assertEqual(msg.type, dnsmessage_pb2.PBDNSMessage.DNSQueryType)
        self.checkProtobufBase(msg, protocol, query, initiator, v6=v6)
        # dnsdist doesn't fill the responder field for responses
        # because it doesn't keep the information around.
        self.assertTrue(msg.HasField('to'))
        if not v6:
            self.assertEqual(socket.inet_ntop(socket.AF_INET, msg.to), '127.0.0.1')
        self.assertTrue(msg.HasField('question'))
        self.assertTrue(msg.question.HasField('qClass'))
        self.assertEqual(msg.question.qClass, qclass)
        self.assertTrue(msg.question.HasField('qType'))
        self.assertEqual(msg.question.qClass, qtype)
        self.assertTrue(msg.question.HasField('qName'))
        self.assertEqual(msg.question.qName, qname)

    def checkProtobufTags(self, tags, expectedTags):
        # only differences will be in new list
        listx = set(tags) ^ set(expectedTags)
        # exclusive or of lists should be empty
        self.assertEqual(len(listx), 0, "Protobuf tags don't match")

    def checkProtobufQueryConvertedToResponse(self, msg, protocol, response, initiator='127.0.0.0'):
        self.assertEqual(msg.type, dnsmessage_pb2.PBDNSMessage.DNSResponseType)
        # skip comparing inBytes (size of the query) with the length of the generated response
        self.checkProtobufBase(msg, protocol, response, initiator, False)
        self.assertTrue(msg.HasField('response'))
        self.assertTrue(msg.response.HasField('queryTimeSec'))

    def checkProtobufResponse(self, msg, protocol, response, initiator='127.0.0.1', v6=False):
        self.assertEqual(msg.type, dnsmessage_pb2.PBDNSMessage.DNSResponseType)
        self.checkProtobufBase(msg, protocol, response, initiator, v6=v6)
        self.assertTrue(msg.HasField('response'))
        self.assertTrue(msg.response.HasField('queryTimeSec'))

    def checkProtobufResponseRecord(self, record, rclass, rtype, rname, rttl):
        self.assertTrue(record.HasField('class'))
        self.assertEqual(getattr(record, 'class'), rclass)
        self.assertTrue(record.HasField('type'))
        self.assertEqual(record.type, rtype)
        self.assertTrue(record.HasField('name'))
        self.assertEqual(record.name, rname)
        self.assertTrue(record.HasField('ttl'))
        self.assertEqual(record.ttl, rttl)
        self.assertTrue(record.HasField('rdata'))

class TestProtobuf(DNSDistProtobufTest):
    _config_params = ['_testServerPort', '_protobufServerPort', '_protobufServerID', '_protobufServerID']
    _config_template = """
    luasmn = newSuffixMatchNode()
    luasmn:add(newDNSName('lua.protobuf.tests.powerdns.com.'))

    function alterProtobufResponse(dq, protobuf)
      if luasmn:check(dq.qname) then
        requestor = newCA(tostring(dq.remoteaddr))		-- called by testLuaProtobuf()
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
        requestor = newCA(tostring(dq.remoteaddr))		-- called by testLuaProtobuf()
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

        local strReqName = tostring(dq.qname)		  	-- get request dns name

        protobuf:setProtobufResponseType()			-- set protobuf to look like a response and not a query, with 0 default time

        blobData = '\127' .. '\000' .. '\000' .. '\002'		-- 127.0.0.2, note: lua 5.1 can only embed decimal not hex

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
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

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
        self.assertEqual(len(msg.response.rrs), 2)
        rr = msg.response.rrs[0]
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.CNAME, name, 3600)
        self.assertEqual(rr.rdata.decode('utf-8'), target)
        rr = msg.response.rrs[1]
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, target, 3600)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '127.0.0.1')

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

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
        self.assertEqual(len(msg.response.rrs), 2)
        rr = msg.response.rrs[0]
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.CNAME, name, 3600)
        self.assertEqual(rr.rdata.decode('utf-8'), target)
        rr = msg.response.rrs[1]
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, target, 3600)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '127.0.0.1')

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
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)


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
        self.assertEqual(len(msg.response.rrs), 1)
        for rr in msg.response.rrs:
            self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 3600)
            self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '127.0.0.1')

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

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
        self.assertEqual(len(msg.response.rrs), 1)
        for rr in msg.response.rrs:
            self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, name, 3600)
            self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '127.0.0.1')

class TestProtobufMetaTags(DNSDistProtobufTest):
    _config_params = ['_testServerPort', '_protobufServerPort']
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    rl = newRemoteLogger('127.0.0.1:%d')

    addAction(AllRule(), SetTagAction('my-tag-key', 'my-tag-value'))
    addAction(AllRule(), SetTagAction('my-empty-key', ''))
    addAction(AllRule(), RemoteLogAction(rl, nil, {serverID='dnsdist-server-1', exportTags='*'}, {b64='b64-content', ['my-tag-export-name']='tag:my-tag-key'}))
    addResponseAction(AllRule(), SetTagResponseAction('my-tag-key2', 'my-tag-value2'))
    addResponseAction(AllRule(), RemoteLogResponseAction(rl, nil, false, {serverID='dnsdist-server-1', exportTags='my-empty-key,my-tag-key2'}, {['my-tag-export-name']='tags'}))
    """

    def testProtobufMeta(self):
        """
        Protobuf: Meta values
        """
        name = 'meta.protobuf.tests.powerdns.com.'
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
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # let the protobuf messages the time to get there
        time.sleep(1)

        # check the protobuf message corresponding to the UDP query
        msg = self.getFirstProtobufMessage()

        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)
        # regular tags
        self.assertEqual(len(msg.response.tags), 2)
        self.assertIn('my-tag-key:my-tag-value', msg.response.tags)
        self.assertIn('my-empty-key', msg.response.tags)
        # meta tags
        self.assertEqual(len(msg.meta), 2)
        tags = {}
        for entry in msg.meta:
            tags[entry.key] = entry.value.stringVal

        self.assertIn('b64', tags)
        self.assertIn('my-tag-export-name', tags)

        b64EncodedQuery = base64.b64encode(query.to_wire()).decode('ascii')
        self.assertEqual(tags['b64'], [b64EncodedQuery])
        self.assertEqual(tags['my-tag-export-name'], ['my-tag-value'])

        # check the protobuf message corresponding to the UDP response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, response)
        # regular tags
        self.assertEqual(len(msg.response.tags), 2)
        self.assertIn('my-tag-key2:my-tag-value2', msg.response.tags)
        self.assertIn('my-empty-key', msg.response.tags)
        # meta tags
        self.assertEqual(len(msg.meta), 1)
        self.assertEqual(msg.meta[0].key, 'my-tag-export-name')
        self.assertEqual(len(msg.meta[0].value.stringVal), 3)
        self.assertIn('my-tag-key:my-tag-value', msg.meta[0].value.stringVal)
        self.assertIn('my-tag-key2:my-tag-value2', msg.meta[0].value.stringVal)
        # no ':' when the value is empty
        self.assertIn('my-empty-key', msg.meta[0].value.stringVal)

class TestProtobufMetaDOH(DNSDistProtobufTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _tlsServerPort = pickAvailablePort()
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/dns-query" % (_serverName, _dohServerPort))
    _config_params = ['_testServerPort', '_protobufServerPort', '_tlsServerPort', '_serverCert', '_serverKey', '_dohServerPort', '_serverCert', '_serverKey']
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    rl = newRemoteLogger('127.0.0.1:%d')

    addTLSLocal("127.0.0.1:%s", "%s", "%s", { provider="openssl" })
    addDOHLocal("127.0.0.1:%s", "%s", "%s", { '/dns-query' }, { keepIncomingHeaders=true })

    local mytags = {path='doh-path', host='doh-host', ['query-string']='doh-query-string', scheme='doh-scheme', agent='doh-header:user-agent'}
    addAction(AllRule(), RemoteLogAction(rl, nil, {serverID='dnsdist-server-1'}, mytags))
    addResponseAction(AllRule(), RemoteLogResponseAction(rl, nil, false, {serverID='dnsdist-server-1'}, mytags))
    """

    def testProtobufMetaDoH(self):
        """
        Protobuf: Meta values - DoH
        """
        name = 'meta-doh.protobuf.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery", "sendDOTQueryWrapper", "sendDOHQueryWrapper"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)

            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

            # let the protobuf messages the time to get there
            time.sleep(1)

            # check the protobuf message corresponding to the query
            msg = self.getFirstProtobufMessage()

            if method == "sendUDPQuery":
                pbMessageType = dnsmessage_pb2.PBDNSMessage.UDP
            elif method == "sendTCPQuery":
                pbMessageType = dnsmessage_pb2.PBDNSMessage.TCP
            elif method == "sendDOTQueryWrapper":
                pbMessageType = dnsmessage_pb2.PBDNSMessage.DOT
            elif method == "sendDOHQueryWrapper":
                pbMessageType = dnsmessage_pb2.PBDNSMessage.DOH

            print(method)
            self.checkProtobufQuery(msg, pbMessageType, query, dns.rdataclass.IN, dns.rdatatype.A, name)
            self.assertEqual(len(msg.meta), 5)
            tags = {}
            for entry in msg.meta:
                self.assertEqual(len(entry.value.stringVal), 1)
                tags[entry.key] = entry.value.stringVal[0]

            self.assertIn('agent', tags)
            if method == "sendDOHQueryWrapper":
                self.assertIn('PycURL', tags['agent'])
                self.assertIn('host', tags)
                self.assertEqual(tags['host'], self._serverName + ':' + str(self._dohServerPort))
                self.assertIn('path', tags)
                self.assertEqual(tags['path'], '/dns-query')
                self.assertIn('query-string', tags)
                self.assertIn('?dns=', tags['query-string'])
                self.assertIn('scheme', tags)
                self.assertEqual(tags['scheme'], 'https')

            # check the protobuf message corresponding to the response
            msg = self.getFirstProtobufMessage()
            self.checkProtobufResponse(msg, pbMessageType, response)
            self.assertEqual(len(msg.meta), 5)
            tags = {}
            for entry in msg.meta:
                self.assertEqual(len(entry.value.stringVal), 1)
                tags[entry.key] = entry.value.stringVal[0]

            self.assertIn('agent', tags)
            if method == "sendDOHQueryWrapper":
                self.assertIn('PycURL', tags['agent'])
                self.assertIn('host', tags)
                self.assertEqual(tags['host'], self._serverName + ':' + str(self._dohServerPort))
                self.assertIn('path', tags)
                self.assertEqual(tags['path'], '/dns-query')
                self.assertIn('query-string', tags)
                self.assertIn('?dns=', tags['query-string'])
                self.assertIn('scheme', tags)
                self.assertEqual(tags['scheme'], 'https')

class TestProtobufMetaProxy(DNSDistProtobufTest):

    _config_params = ['_testServerPort', '_protobufServerPort']
    _config_template = """
    setProxyProtocolACL( { "127.0.0.1/32" } )

    newServer{address="127.0.0.1:%d"}
    rl = newRemoteLogger('127.0.0.1:%d')

    local mytags = {pp='proxy-protocol-values', pp42='proxy-protocol-value:42'}
    addAction(AllRule(), RemoteLogAction(rl, nil, {serverID='dnsdist-server-1'}, mytags))

    -- proxy protocol values are NOT passed to the response
    """

    def testProtobufMetaProxy(self):
        """
        Protobuf: Meta values - Proxy
        """
        name = 'meta-proxy.protobuf.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        destAddr = "2001:db8::9"
        destPort = 9999
        srcAddr = "2001:db8::8"
        srcPort = 8888
        udpPayload = ProxyProtocol.getPayload(False, False, True, srcAddr, destAddr, srcPort, destPort, [ [ 2, b'foo'], [ 42, b'proxy'] ])
        (receivedQuery, receivedResponse) = self.sendUDPQuery(udpPayload + query.to_wire(), response, rawQuery=True)

        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # let the protobuf messages the time to get there
        time.sleep(1)

        # check the protobuf message corresponding to the UDP query
        msg = self.getFirstProtobufMessage()

        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name, initiator='2001:db8::8', v6=True)
        self.assertEqual(len(msg.meta), 2)
        tags = {}
        for entry in msg.meta:
            tags[entry.key] = entry.value.stringVal

        self.assertIn('pp42', tags)
        self.assertEqual(tags['pp42'], ['proxy'])
        self.assertIn('pp', tags)
        self.assertEqual(len(tags['pp']), 2)
        self.assertIn('2:foo', tags['pp'])
        self.assertIn('42:proxy', tags['pp'])

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
        Protobuf: Send data to a protobuf server, with pseudonymization
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
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # let the protobuf messages the time to get there
        time.sleep(1)

        # check the protobuf message corresponding to the UDP query
        msg = self.getFirstProtobufMessage()

        # 108.41.239.98 is 127.0.0.1 pseudonymized with ipcipher and the current key
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name, '108.41.239.98')

        # check the protobuf message corresponding to the UDP response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, response, '108.41.239.98')

        self.assertEqual(len(msg.response.rrs), 2)
        rr = msg.response.rrs[0]
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.CNAME, name, 3600)
        self.assertEqual(rr.rdata.decode('ascii'), target)
        rr = msg.response.rrs[1]
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, target, 3600)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '127.0.0.1')

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # let the protobuf messages the time to get there
        time.sleep(1)

        # check the protobuf message corresponding to the TCP query
        msg = self.getFirstProtobufMessage()
        # 108.41.239.98 is 127.0.0.1 pseudonymized with ipcipher and the current key
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.TCP, query, dns.rdataclass.IN, dns.rdatatype.A, name, '108.41.239.98')

        # check the protobuf message corresponding to the TCP response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.TCP, response, '108.41.239.98')
        self.assertEqual(len(msg.response.rrs), 2)
        rr = msg.response.rrs[0]
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.CNAME, name, 3600)
        self.assertEqual(rr.rdata.decode('ascii'), target)
        rr = msg.response.rrs[1]
        self.checkProtobufResponseRecord(rr, dns.rdataclass.IN, dns.rdatatype.A, target, 3600)
        self.assertEqual(socket.inet_ntop(socket.AF_INET, rr.rdata), '127.0.0.1')
