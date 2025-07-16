#!/usr/bin/env python
import threading
import os
import socket
import struct
import sys
import time
from dnsdisttests import DNSDistTest, Queue, pickAvailablePort

import dns
import dnstap_pb2

FSTRM_CONTROL_ACCEPT = 0x01
FSTRM_CONTROL_START = 0x02
FSTRM_CONTROL_STOP = 0x03
FSTRM_CONTROL_READY = 0x04
FSTRM_CONTROL_FINISH = 0x05


def checkDnstapBase(testinstance, dnstap, protocol, initiator, response_port):
    testinstance.assertTrue(dnstap)
    testinstance.assertTrue(dnstap.HasField('identity'))
    testinstance.assertEqual(dnstap.identity, b'a.server')
    testinstance.assertTrue(dnstap.HasField('version'))
    testinstance.assertIn(b'dnsdist ', dnstap.version)
    testinstance.assertTrue(dnstap.HasField('type'))
    testinstance.assertEqual(dnstap.type, dnstap.MESSAGE)
    testinstance.assertTrue(dnstap.HasField('message'))
    testinstance.assertTrue(dnstap.message.HasField('socket_protocol'))
    testinstance.assertEqual(dnstap.message.socket_protocol, protocol)
    testinstance.assertTrue(dnstap.message.HasField('socket_family'))
    testinstance.assertEqual(dnstap.message.socket_family, dnstap_pb2.INET)
    testinstance.assertTrue(dnstap.message.HasField('query_address'))
    testinstance.assertEqual(socket.inet_ntop(socket.AF_INET, dnstap.message.query_address), initiator)
    testinstance.assertTrue(dnstap.message.HasField('response_address'))
    testinstance.assertEqual(socket.inet_ntop(socket.AF_INET, dnstap.message.response_address), initiator)
    testinstance.assertTrue(dnstap.message.HasField('response_port'))
    testinstance.assertEqual(dnstap.message.response_port, response_port)


def checkDnstapQuery(testinstance, dnstap, protocol, query, initiator='127.0.0.1', response_port=0, http_protocol=0):

    testinstance.assertEqual(dnstap.message.type, dnstap_pb2.Message.CLIENT_QUERY)
    if response_port == 0 :
        response_port = testinstance._dnsDistPort

    checkDnstapBase(testinstance, dnstap, protocol, initiator, response_port)

    testinstance.assertTrue(dnstap.message.HasField('query_time_sec'))
    testinstance.assertTrue(dnstap.message.HasField('query_time_nsec'))

    if http_protocol != 0 :
        testinstance.assertTrue(dnstap.message.HasField('http_protocol'))
        testinstance.assertEqual(dnstap.message.http_protocol, http_protocol)

    testinstance.assertTrue(dnstap.message.HasField('query_message'))
    wire_message = dns.message.from_wire(dnstap.message.query_message)
    testinstance.assertEqual(wire_message, query)


def checkDnstapExtra(testinstance, dnstap, expected):
    testinstance.assertTrue(dnstap.HasField('extra'))
    testinstance.assertEqual(dnstap.extra, expected)

def checkDnstapNoExtra(testinstance, dnstap):
    testinstance.assertFalse(dnstap.HasField('extra'))


def checkDnstapResponse(testinstance, dnstap, protocol, response, initiator='127.0.0.1', response_port=0):
    testinstance.assertEqual(dnstap.message.type, dnstap_pb2.Message.CLIENT_RESPONSE)
    if response_port == 0 :
        response_port = testinstance._dnsDistPort
    checkDnstapBase(testinstance, dnstap, protocol, initiator, response_port)

    testinstance.assertTrue(dnstap.message.HasField('query_time_sec'))
    testinstance.assertTrue(dnstap.message.HasField('query_time_nsec'))

    testinstance.assertTrue(dnstap.message.HasField('response_time_sec'))
    testinstance.assertTrue(dnstap.message.HasField('response_time_nsec'))

    testinstance.assertTrue(dnstap.message.response_time_sec > dnstap.message.query_time_sec or \
        dnstap.message.response_time_nsec > dnstap.message.query_time_nsec)

    testinstance.assertTrue(dnstap.message.HasField('response_message'))
    wire_message = dns.message.from_wire(dnstap.message.response_message)
    testinstance.assertEqual(wire_message, response)


def getFirstMatchingMessageFromQueue(queue, messageType=None):
    unused_messages = []
    selected = None
    while True:
        data = queue.get(True, timeout=2.0)
        if not data:
            break
        decoded_message = dnstap_pb2.Dnstap()
        decoded_message.ParseFromString(data)
        if not selected and (not messageType or decoded_message.message.type == messageType):
            selected = decoded_message
        else:
            unused_messages.append(data)

        if queue.empty():
            break

    # put back non-matching messages for later
    for msg in reversed(unused_messages):
        queue.put(msg)

    return selected

class TestDnstapOverRemoteLogger(DNSDistTest):
    _remoteLoggerServerPort = pickAvailablePort()
    _remoteLoggerQueue = Queue()
    _remoteLoggerCounter = 0
    _config_params = ['_testServerPort', '_remoteLoggerServerPort']
    _config_template = """
    extrasmn = newSuffixMatchNode()
    extrasmn:add(newDNSName('extra.dnstap.tests.powerdns.com.'))

    luatarget = 'lua.dnstap.tests.powerdns.com.'

    function alterDnstapQuery(dq, tap)
      if extrasmn:check(dq.qname) then
        tap:setExtra("Type,Query")
      end
    end

    function alterDnstapResponse(dq, tap)
      if extrasmn:check(dq.qname) then
        tap:setExtra("Type,Response")
      end
    end

    function luaFunc(dq)
      dq.dh:setQR(true)
      dq.dh:setRCode(DNSRCode.NXDOMAIN)
      return DNSAction.None, ""
    end

    newServer{address="127.0.0.1:%s", useClientSubnet=true}
    rl = newRemoteLogger('127.0.0.1:%s')

    addAction(AllRule(), DnstapLogAction("a.server", rl, alterDnstapQuery))				-- Send dnstap message before lookup

    addAction(luatarget, LuaAction(luaFunc))				-- Send dnstap message before lookup

    addResponseAction(AllRule(), DnstapLogResponseAction("a.server", rl, alterDnstapResponse))	-- Send dnstap message after lookup

    addAction('spoof.dnstap.tests.powerdns.com.', SpoofAction("192.0.2.1"))
    """

    @classmethod
    def RemoteLoggerListener(cls, port):
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

                cls._remoteLoggerQueue.put(data, True, timeout=2.0)

            conn.close()
        sock.close()

    @classmethod
    def startResponders(cls):
        DNSDistTest.startResponders()

        cls._remoteLoggerListener = threading.Thread(name='RemoteLogger Listener', target=cls.RemoteLoggerListener, args=[cls._remoteLoggerServerPort])
        cls._remoteLoggerListener.daemon = True
        cls._remoteLoggerListener.start()

    def getFirstDnstap(self):
        return getFirstMatchingMessageFromQueue(self._remoteLoggerQueue)

    def testDnstap(self):
        """
        Dnstap: Send query and responses packed in dnstap to a remotelogger server
        """
        name = 'query.dnstap.tests.powerdns.com.'

        target = 'target.dnstap.tests.powerdns.com.'
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

        # give the dnstap messages time to get here
        time.sleep(1)

        # check the dnstap message corresponding to the UDP query
        dnstap = self.getFirstDnstap()

        checkDnstapQuery(self, dnstap, dnstap_pb2.UDP, query)
        checkDnstapNoExtra(self, dnstap)

        # check the dnstap message corresponding to the UDP response
        dnstap = self.getFirstDnstap()
        checkDnstapResponse(self, dnstap, dnstap_pb2.UDP, response)
        checkDnstapNoExtra(self, dnstap)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # give the dnstap messages time to get here
        time.sleep(1)

        # check the dnstap message corresponding to the TCP query
        dnstap = self.getFirstDnstap()

        checkDnstapQuery(self, dnstap, dnstap_pb2.TCP, query)
        checkDnstapNoExtra(self, dnstap)

        # check the dnstap message corresponding to the TCP response
        dnstap = self.getFirstDnstap()
        checkDnstapResponse(self, dnstap, dnstap_pb2.TCP, response)
        checkDnstapNoExtra(self, dnstap)

    def testDnstapExtra(self):
        """
        DnstapExtra: Send query and responses packed in dnstap to a remotelogger server. Extra data is filled out.
        """
        name = 'extra.dnstap.tests.powerdns.com.'

        target = 'target.dnstap.tests.powerdns.com.'
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

        # give the dnstap messages time to get here
        time.sleep(1)

        # check the dnstap message corresponding to the UDP query
        dnstap = self.getFirstDnstap()
        checkDnstapQuery(self, dnstap, dnstap_pb2.UDP, query)
        checkDnstapExtra(self, dnstap, b"Type,Query")

        # check the dnstap message corresponding to the UDP response
        dnstap = self.getFirstDnstap()
        checkDnstapResponse(self, dnstap, dnstap_pb2.UDP, response)
        checkDnstapExtra(self, dnstap, b"Type,Response")

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # give the dnstap messages time to get here
        time.sleep(1)

        # check the dnstap message corresponding to the TCP query
        dnstap = self.getFirstDnstap()
        checkDnstapQuery(self, dnstap, dnstap_pb2.TCP, query)
        checkDnstapExtra(self, dnstap, b"Type,Query")

        # check the dnstap message corresponding to the TCP response
        dnstap = self.getFirstDnstap()
        checkDnstapResponse(self, dnstap, dnstap_pb2.TCP, response)
        checkDnstapExtra(self, dnstap, b"Type,Response")

class TestDnstapOverRemoteLoggerPool(DNSDistTest):
    _remoteLoggerServerPort = pickAvailablePort()
    _remoteLoggerQueue = Queue()
    _remoteLoggerCounter = 0
    _poolConnectionCount = 8
    _config_params = ['_testServerPort', '_remoteLoggerServerPort', '_poolConnectionCount']
    _config_template = """
    extrasmn = newSuffixMatchNode()
    extrasmn:add(newDNSName('extra.dnstap.tests.powerdns.com.'))

    luatarget = 'lua.dnstap.tests.powerdns.com.'

    function alterDnstapQuery(dq, tap)
      if extrasmn:check(dq.qname) then
        tap:setExtra("Type,Query")
      end
    end

    function alterDnstapResponse(dq, tap)
      if extrasmn:check(dq.qname) then
        tap:setExtra("Type,Response")
      end
    end

    function luaFunc(dq)
      dq.dh:setQR(true)
      dq.dh:setRCode(DNSRCode.NXDOMAIN)
      return DNSAction.None, ""
    end

    newServer{address="127.0.0.1:%d", useClientSubnet=true}
    rl = newRemoteLogger('127.0.0.1:%d', 2, 100, 1, %d)

    addAction(AllRule(), DnstapLogAction("a.server", rl, alterDnstapQuery))				-- Send dnstap message before lookup

    addAction(luatarget, LuaAction(luaFunc))				-- Send dnstap message before lookup

    addResponseAction(AllRule(), DnstapLogResponseAction("a.server", rl, alterDnstapResponse))	-- Send dnstap message after lookup

    addAction('spoof.dnstap.tests.powerdns.com.', SpoofAction("192.0.2.1"))
    """

    @classmethod
    def RemoteLoggerListener(cls, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except socket.error as e:
            print("Error binding in the protbuf listener: %s" % str(e))
            sys.exit(1)

        sock.listen(100)

        def handle_connection(conn):
            data = None
            while True:
                data = conn.recv(2)
                if not data:
                    break
                (datalen,) = struct.unpack("!H", data)
                data = conn.recv(datalen)
                if not data:
                    break

                cls._remoteLoggerQueue.put(data, True, timeout=2.0)

            conn.close()

        threads = []
        while True:
            (conn, _) = sock.accept()
            thread = threading.Thread(target=handle_connection, args=[conn])
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
        sock.close()

    @classmethod
    def startResponders(cls):
        DNSDistTest.startResponders()

        cls._remoteLoggerListener = threading.Thread(name='RemoteLogger Listener', target=cls.RemoteLoggerListener, args=[cls._remoteLoggerServerPort])
        cls._remoteLoggerListener.daemon = True
        cls._remoteLoggerListener.start()

    def getFirstDnstap(self, messageType=None):
        return getFirstMatchingMessageFromQueue(self._remoteLoggerQueue, messageType=messageType)

    def testDnstap(self):
        """
        Dnstap: Send query and responses packed in dnstap to a remotelogger server
        """
        name = 'query.dnstap.tests.powerdns.com.'

        target = 'target.dnstap.tests.powerdns.com.'
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

        # give the dnstap messages time to get here
        time.sleep(1)

        # check the dnstap message corresponding to the UDP query
        dnstap = self.getFirstDnstap(dnstap_pb2.Message.CLIENT_QUERY)

        checkDnstapQuery(self, dnstap, dnstap_pb2.UDP, query)
        checkDnstapNoExtra(self, dnstap)

        # check the dnstap message corresponding to the UDP response
        dnstap = self.getFirstDnstap(dnstap_pb2.Message.CLIENT_RESPONSE)
        checkDnstapResponse(self, dnstap, dnstap_pb2.UDP, response)
        checkDnstapNoExtra(self, dnstap)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # give the dnstap messages time to get here
        time.sleep(1)

        # check the dnstap message corresponding to the TCP query
        dnstap = self.getFirstDnstap(dnstap_pb2.Message.CLIENT_QUERY)

        checkDnstapQuery(self, dnstap, dnstap_pb2.TCP, query)
        checkDnstapNoExtra(self, dnstap)

        # check the dnstap message corresponding to the TCP response
        dnstap = self.getFirstDnstap(dnstap_pb2.Message.CLIENT_RESPONSE)
        checkDnstapResponse(self, dnstap, dnstap_pb2.TCP, response)
        checkDnstapNoExtra(self, dnstap)

    def testDnstapExtra(self):
        """
        DnstapExtra: Send query and responses packed in dnstap to a remotelogger server. Extra data is filled out.
        """
        name = 'extra.dnstap.tests.powerdns.com.'

        target = 'target.dnstap.tests.powerdns.com.'
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

        # give the dnstap messages time to get here
        time.sleep(1)

        # check the dnstap message corresponding to the UDP query
        dnstap = self.getFirstDnstap(dnstap_pb2.Message.CLIENT_QUERY)
        checkDnstapQuery(self, dnstap, dnstap_pb2.UDP, query)
        checkDnstapExtra(self, dnstap, b"Type,Query")

        # check the dnstap message corresponding to the UDP response
        dnstap = self.getFirstDnstap(dnstap_pb2.Message.CLIENT_RESPONSE)
        checkDnstapResponse(self, dnstap, dnstap_pb2.UDP, response)
        checkDnstapExtra(self, dnstap, b"Type,Response")

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # give the dnstap messages time to get here
        time.sleep(1)

        # check the dnstap message corresponding to the TCP query
        dnstap = self.getFirstDnstap(dnstap_pb2.Message.CLIENT_QUERY)
        checkDnstapQuery(self, dnstap, dnstap_pb2.TCP, query)
        checkDnstapExtra(self, dnstap, b"Type,Query")

        # check the dnstap message corresponding to the TCP response
        dnstap = self.getFirstDnstap(dnstap_pb2.Message.CLIENT_RESPONSE)
        checkDnstapResponse(self, dnstap, dnstap_pb2.TCP, response)
        checkDnstapExtra(self, dnstap, b"Type,Response")



def fstrm_get_control_frame_type(data):
    (t,) = struct.unpack("!L", data[0:4])
    return t


def fstrm_make_control_frame_reply(cft, data):
    if cft == FSTRM_CONTROL_READY:
        # Reply with ACCEPT frame and content-type
        contenttype = b'protobuf:dnstap.Dnstap'
        frame = struct.pack('!LLL', FSTRM_CONTROL_ACCEPT, 1,
                            len(contenttype)) + contenttype
        buf = struct.pack("!LL", 0, len(frame)) + frame
        return buf
    elif cft == FSTRM_CONTROL_START:
        return None
    else:
        raise Exception('unhandled control frame ' + cft)


def fstrm_read_and_dispatch_control_frame(conn):
    data = conn.recv(4)
    if not data:
        raise Exception('length of control frame payload could not be read')
    (datalen,) = struct.unpack("!L", data)
    data = conn.recv(datalen)
    cft = fstrm_get_control_frame_type(data)
    reply = fstrm_make_control_frame_reply(cft, data)
    if reply:
        conn.send(reply)
    return cft


def fstrm_handle_bidir_connection(conn, on_data, exit_early=False):
    data = None
    while True:
        data = conn.recv(4)
        if not data:
            break
        (datalen,) = struct.unpack("!L", data)
        if datalen == 0:
            # control frame length follows
            cft = fstrm_read_and_dispatch_control_frame(conn)
            if cft == FSTRM_CONTROL_STOP:
                break
        else:
            # data frame
            data = conn.recv(datalen)
            if not data:
                break

            on_data(data)
            if exit_early:
                break

class TestDnstapOverFrameStreamUnixLogger(DNSDistTest):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _doh3ServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))

    _fstrmLoggerAddress = '/tmp/fslutest.sock'
    _fstrmLoggerQueue = Queue()
    _fstrmLoggerCounter = 0
    _config_params = ['_testServerPort', '_fstrmLoggerAddress', '_dohServerPort', '_serverCert', '_serverKey', '_doh3ServerPort', '_serverCert', '_serverKey']
    _config_template = """
    newServer{address="127.0.0.1:%s", useClientSubnet=true}
    fslu = newFrameStreamUnixLogger('%s')

    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, {})
    addDOH3Local("127.0.0.1:%d", "%s", "%s")
    addAction(AllRule(), DnstapLogAction("a.server", fslu))
    """

    @classmethod
    def FrameStreamUnixListener(cls, path):
        try:
            os.unlink(path)
        except OSError:
            pass  # Assume file not found
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(path)
        except socket.error as e:
            print("Error binding in the framestream listener: %s" % str(e))
            sys.exit(1)

        sock.listen(100)
        while True:
            (conn, _) = sock.accept()
            fstrm_handle_bidir_connection(conn, lambda data: \
                cls._fstrmLoggerQueue.put(data, True, timeout=2.0))
            conn.close()
        sock.close()

    @classmethod
    def startResponders(cls):
        DNSDistTest.startResponders()

        cls._fstrmLoggerListener = threading.Thread(name='FrameStreamUnixListener', target=cls.FrameStreamUnixListener, args=[cls._fstrmLoggerAddress])
        cls._fstrmLoggerListener.daemon = True
        cls._fstrmLoggerListener.start()

    def getFirstDnstap(self):
        return getFirstMatchingMessageFromQueue(self._fstrmLoggerQueue)

    def testDnstapOverFrameStreamUnix(self):
        """
        Dnstap: Send query packed in dnstap to a unix socket fstrmlogger server
        """
        name = 'query.dnstap.tests.powerdns.com.'

        target = 'target.dnstap.tests.powerdns.com.'
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

        # check the dnstap message corresponding to the UDP query
        dnstap = self.getFirstDnstap()

        checkDnstapQuery(self, dnstap, dnstap_pb2.UDP, query)
        checkDnstapNoExtra(self, dnstap)

    def testDnstapHttpProtocol(self):
        """
        DOH and DOH3: Make sure http protocol field is correctly set
        """
        name = 'simple.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        protocols = [
            {"method": "sendDOH3QueryWrapper", "port": self._doh3ServerPort, "expected_protocol": dnstap_pb2.HttpProtocol.HTTP3},
            {"method": "sendDOHQueryWrapper",  "port": self._dohServerPort,  "expected_protocol": dnstap_pb2.HttpProtocol.HTTP2},
        ]
        for protocol in protocols :
            sender = getattr(self, protocol["method"])
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

            # check the dnstap message corresponding to the UDP query
            dnstap = self.getFirstDnstap()

            checkDnstapQuery(self, dnstap, dnstap_pb2.DOH, query, '127.0.0.1', protocol["port"], protocol["expected_protocol"])
            checkDnstapNoExtra(self, dnstap)

class TestDnstapOverRemotePoolUnixLogger(DNSDistTest):
    _fstrmLoggerAddress = '/tmp/fslutest.sock'
    _fstrmLoggerQueue = Queue()
    _fstrmLoggerCounter = 0
    _poolConnectionCount = 5
    _config_params = ['_testServerPort', '_fstrmLoggerAddress', '_poolConnectionCount']
    _config_template = """
    newServer{address="127.0.0.1:%d", useClientSubnet=true}
    fslu = newFrameStreamUnixLogger('%s', { connectionCount = %d })

    addAction(AllRule(), DnstapLogAction("a.server", fslu))
    """

    @classmethod
    def FrameStreamUnixListener(cls, path):
        try:
            os.unlink(path)
        except OSError:
            pass  # Assume file not found
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(path)
        except socket.error as e:
            print("Error binding in the framestream listener: %s" % str(e))
            sys.exit(1)

        sock.listen(100)

        def handle_connection(conn):
            fstrm_handle_bidir_connection(conn, lambda data: \
                cls._fstrmLoggerQueue.put(data, True, timeout=2.0), exit_early=True)
            conn.close()

        threads = []
        while True:
            (conn, _) = sock.accept()
            thread = threading.Thread(target=handle_connection, args=[conn])
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
        sock.close()

    @classmethod
    def startResponders(cls):
        DNSDistTest.startResponders()

        cls._fstrmLoggerListener = threading.Thread(name='FrameStreamUnixListener', target=cls.FrameStreamUnixListener, args=[cls._fstrmLoggerAddress])
        cls._fstrmLoggerListener.daemon = True
        cls._fstrmLoggerListener.start()

    def getFirstDnstap(self):
        return getFirstMatchingMessageFromQueue(self._fstrmLoggerQueue)

    def testDnstapOverFrameStreamUnix(self):
        """
        Dnstap: Send query packed in dnstap to a unix socket fstrmlogger server
        """
        for i in range(self._poolConnectionCount):
            name = 'query.dnstap.tests.powerdns.com.'

            target = 'target.dnstap.tests.powerdns.com.'
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

            # check the dnstap message corresponding to the UDP query
            dnstap = self.getFirstDnstap()

            checkDnstapQuery(self, dnstap, dnstap_pb2.UDP, query)
            checkDnstapNoExtra(self, dnstap)


class TestDnstapOverFrameStreamTcpLogger(DNSDistTest):
    _fstrmLoggerPort = pickAvailablePort()
    _fstrmLoggerQueue = Queue()
    _fstrmLoggerCounter = 0
    _config_params = ['_testServerPort', '_fstrmLoggerPort']
    _config_template = """
    newServer{address="127.0.0.1:%s", useClientSubnet=true}
    fslu = newFrameStreamTcpLogger('127.0.0.1:%s')

    addAction(AllRule(), DnstapLogAction("a.server", fslu))
    """

    @classmethod
    def FrameStreamTcpListener(cls, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", port))
        except socket.error as e:
            print("Error binding in the framestream listener: %s" % str(e))
            sys.exit(1)

        sock.listen(100)
        while True:
            (conn, _) = sock.accept()
            fstrm_handle_bidir_connection(conn, lambda data: \
                cls._fstrmLoggerQueue.put(data, True, timeout=2.0))
            conn.close()
        sock.close()

    @classmethod
    def startResponders(cls):
        DNSDistTest.startResponders()

        cls._fstrmLoggerListener = threading.Thread(name='FrameStreamTcpListener', target=cls.FrameStreamTcpListener, args=[cls._fstrmLoggerPort])
        cls._fstrmLoggerListener.daemon = True
        cls._fstrmLoggerListener.start()

    def getFirstDnstap(self):
        return getFirstMatchingMessageFromQueue(self._fstrmLoggerQueue)

    def testDnstapOverFrameStreamTcp(self):
        """
        Dnstap: Send query packed in dnstap to a tcp socket fstrmlogger server
        """
        name = 'query.dnstap.tests.powerdns.com.'

        target = 'target.dnstap.tests.powerdns.com.'
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

        # check the dnstap message corresponding to the UDP query
        dnstap = self.getFirstDnstap()

        checkDnstapQuery(self, dnstap, dnstap_pb2.UDP, query)
        checkDnstapNoExtra(self, dnstap)

class TestDnstapOverRemotePoolTcpLogger(DNSDistTest):
    _fstrmLoggerPort = pickAvailablePort()
    _fstrmLoggerQueue = Queue()
    _fstrmLoggerCounter = 0
    _poolConnectionCount = 5
    _config_params = ['_testServerPort', '_fstrmLoggerPort', '_poolConnectionCount']
    _config_template = """
    newServer{address="127.0.0.1:%d", useClientSubnet=true}
    fslu = newFrameStreamTcpLogger('127.0.0.1:%d', { connectionCount = %d })

    addAction(AllRule(), DnstapLogAction("a.server", fslu))
    """

    @classmethod
    def FrameStreamTcpListener(cls, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", port))
        except socket.error as e:
            print("Error binding in the framestream listener: %s" % str(e))
            sys.exit(1)

        sock.listen(100)

        def handle_connection(conn):
            fstrm_handle_bidir_connection(conn, lambda data: \
                cls._fstrmLoggerQueue.put(data, True, timeout=2.0), exit_early=True)
            conn.close()

        threads = []
        while True:
            (conn, _) = sock.accept()
            thread = threading.Thread(target=handle_connection, args=[conn])
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
        sock.close()

    @classmethod
    def startResponders(cls):
        DNSDistTest.startResponders()

        cls._fstrmLoggerListener = threading.Thread(name='FrameStreamTcpListener', target=cls.FrameStreamTcpListener, args=[cls._fstrmLoggerPort])
        cls._fstrmLoggerListener.daemon = True
        cls._fstrmLoggerListener.start()

    def getFirstDnstap(self):
        return getFirstMatchingMessageFromQueue(self._fstrmLoggerQueue)

    def testDnstapOverFrameStreamTcp(self):
        """
        Dnstap: Send query packed in dnstap to a tcp socket fstrmlogger server
        """
        for i in range(self._poolConnectionCount):
            name = 'query.dnstap.tests.powerdns.com.'

            target = 'target.dnstap.tests.powerdns.com.'
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

            # check the dnstap message corresponding to the UDP query
            dnstap = self.getFirstDnstap()

            checkDnstapQuery(self, dnstap, dnstap_pb2.UDP, query)
            checkDnstapNoExtra(self, dnstap)
