#!/usr/bin/env python
import Queue
import threading
import socket
import struct
import sys
import time
from dnsdisttests import DNSDistTest

import dns
import dnsmessage_pb2

class TestProtobuf(DNSDistTest):

    _protobufServerPort = 4242
    _protobufQueue = Queue.Queue()
    _protobufCounter = 0
    _config_params = ['_testServerPort', '_protobufServerPort']
    _config_template = """
    newServer{address="127.0.0.1:%s", useClientSubnet=true}
    rl = newRemoteLogger('127.0.0.1:%s')
    addAction(AllRule(), RemoteLogAction(rl))
    addResponseAction(AllRule(), RemoteLogResponseAction(rl))
    """

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
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort])
        cls._UDPResponder.setDaemon(True)
        cls._UDPResponder.start()
        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort])
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

    def checkProtobufBase(self, msg, protocol, query):
        self.assertTrue(msg)
        self.assertTrue(msg.HasField('timeSec'))
        self.assertTrue(msg.HasField('socketFamily'))
        self.assertEquals(msg.socketFamily, dnsmessage_pb2.PBDNSMessage.INET)
        self.assertTrue(msg.HasField('from'))
        fromvalue = getattr(msg, 'from')
        self.assertEquals(socket.inet_ntop(socket.AF_INET, fromvalue), '127.0.0.1')
        self.assertTrue(msg.HasField('socketProtocol'))
        self.assertEquals(msg.socketProtocol, protocol)
        self.assertTrue(msg.HasField('messageId'))
        self.assertTrue(msg.HasField('id'))
        self.assertEquals(msg.id, query.id)
        self.assertTrue(msg.HasField('inBytes'))
        self.assertEquals(msg.inBytes, len(query.to_wire()))
        # dnsdist doesn't set the existing EDNS Subnet for now,
        # although it might be set from Lua
        # self.assertTrue(msg.HasField('originalRequestorSubnet'))
        # self.assertEquals(len(msg.originalRequestorSubnet), 4)
        # self.assertEquals(socket.inet_ntop(socket.AF_INET, msg.originalRequestorSubnet), '127.0.0.1')

    def checkProtobufQuery(self, msg, protocol, query, qclass, qtype, qname):
        self.assertEquals(msg.type, dnsmessage_pb2.PBDNSMessage.DNSQueryType)
        self.checkProtobufBase(msg, protocol, query)
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

    def checkProtobufResponse(self, msg, protocol, response):
        self.assertEquals(msg.type, dnsmessage_pb2.PBDNSMessage.DNSResponseType)
        self.checkProtobufBase(msg, protocol, response)
        self.assertTrue(msg.HasField('response'))
        self.assertTrue(msg.response.HasField('queryTimeSec'))

    def testProtobuf(self):
        """
        Protobuf: Send data to a protobuf server
        """
        name = 'query.protobuf.tests.powerdns.com.'
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
        self.checkProtobufQuery(msg, dnsmessage_pb2.PBDNSMessage.UDP, query, dns.rdataclass.IN, dns.rdatatype.A, name)

        # check the protobuf message corresponding to the UDP response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.UDP, response)
        self.assertEquals(len(msg.response.rrs), 1)
        for rr in msg.response.rrs:
            self.assertTrue(rr.HasField('class'))
            self.assertEquals(getattr(rr, 'class'), dns.rdataclass.IN)
            self.assertTrue(rr.HasField('type'))
            self.assertEquals(rr.type, dns.rdatatype.A)
            self.assertTrue(rr.HasField('name'))
            self.assertEquals(rr.name, name)
            self.assertTrue(rr.HasField('ttl'))
            self.assertEquals(rr.ttl, 3600)
            self.assertTrue(rr.HasField('rdata'))
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

        # check the protobuf message corresponding to the TCP response
        msg = self.getFirstProtobufMessage()
        self.checkProtobufResponse(msg, dnsmessage_pb2.PBDNSMessage.TCP, response)
        self.assertEquals(len(msg.response.rrs), 1)
        for rr in msg.response.rrs:
            self.assertTrue(rr.HasField('class'))
            self.assertEquals(getattr(rr, 'class'), dns.rdataclass.IN)
            self.assertTrue(rr.HasField('type'))
            self.assertEquals(rr.type, dns.rdatatype.A)
            self.assertTrue(rr.HasField('name'))
            self.assertEquals(rr.name, name)
            self.assertTrue(rr.HasField('ttl'))
            self.assertEquals(rr.ttl, 3600)
            self.assertTrue(rr.HasField('rdata'))
            self.assertEquals(socket.inet_ntop(socket.AF_INET, rr.rdata), '127.0.0.1')
