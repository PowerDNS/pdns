#!/usr/bin/env python
import socket
import struct
import threading
import time
import dns
from dnsdisttests import DNSDistTest

try:
  range = xrange
except NameError:
  pass

class TestTCPShort(DNSDistTest):
    # this test suite uses a different responder port
    # because, contrary to the other ones, its
    # responders allow trailing data and multiple responses,
    # and we don't want to mix things up.
    _testServerPort = 5361
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _tlsServerPort = 8453
    _tcpSendTimeout = 60
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    addTLSLocal("127.0.0.1:%s", "%s", "%s")
    setTCPSendTimeout(%d)
    """
    _config_params = ['_testServerPort', '_tlsServerPort', '_serverCert', '_serverKey', '_tcpSendTimeout']

    @classmethod
    def startResponders(cls):
        print("Launching responders..")

        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue, True])
        cls._UDPResponder.setDaemon(True)
        cls._UDPResponder.start()

        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue, True, True])
        cls._TCPResponder.setDaemon(True)
        cls._TCPResponder.start()

    def testTCPShortRead(self):
        """
        TCP: Short read from client
        """
        name = 'short-read.tcp-short.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        expectedResponse.answer.append(rrset)

        conn = self.openTCPConnection()
        wire = query.to_wire()
        # announce 7680 bytes (more than 4096, less than 8192 - the 512 bytes dnsdist is going to add)
        announcedSize = 7680
        paddingSize = announcedSize - len(wire)
        wire = wire + (b'A' * (paddingSize - 1))
        self._toResponderQueue.put(expectedResponse, True, 2.0)

        sizeBytes = struct.pack("!H", announcedSize)
        conn.send(sizeBytes[:1])
        time.sleep(1)
        conn.send(sizeBytes[1:])
        # send announcedSize bytes minus 1 so we get a second read
        conn.send(wire)
        time.sleep(1)
        # send 1024 bytes
        conn.send(b'A' * 1024)

        (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, True)
        conn.close()

        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, expectedResponse)

    def testTCPTLSShortRead(self):
        """
        TCP/TLS: Short read from client
        """
        name = 'short-read-tls.tcp-short.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        expectedResponse.answer.append(rrset)

        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)
        wire = query.to_wire()
        # announce 7680 bytes (more than 4096, less than 8192 - the 512 bytes dnsdist is going to add)
        announcedSize = 7680
        paddingSize = announcedSize - len(wire)
        wire = wire + (b'A' * (paddingSize - 1))
        self._toResponderQueue.put(expectedResponse, True, 2.0)

        sizeBytes = struct.pack("!H", announcedSize)
        conn.send(sizeBytes[:1])
        time.sleep(1)
        conn.send(sizeBytes[1:])
        # send announcedSize bytes minus 1 so we get a second read
        conn.send(wire)
        time.sleep(1)
        # send 1024 bytes
        conn.send(b'A' * 1024)

        (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, True)
        conn.close()

        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, expectedResponse)

    def testTCPShortWrite(self):
        """
        TCP: Short write to client
        """
        name = 'short-write.tcp-short.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AXFR', 'IN')

        # we prepare a large AXFR answer
        # SOA + 200 dns messages of one huge TXT RRset each + SOA
        responses = []
        soa = dns.rrset.from_text(name,
                                  60,
                                  dns.rdataclass.IN,
                                  dns.rdatatype.SOA,
                                  'ns.' + name + ' hostmaster.' + name + ' 1 3600 3600 3600 60')

        soaResponse = dns.message.make_response(query)
        soaResponse.use_edns(edns=False)
        soaResponse.answer.append(soa)
        responses.append(soaResponse)

        response = dns.message.make_response(query)
        response.use_edns(edns=False)
        content = ""
        for i in range(200):
            if len(content) > 0:
                content = content + ', '
            content = content + (str(i)*50)

        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    content)
        response.answer.append(rrset)

        for _ in range(200):
            responses.append(response)

        responses.append(soaResponse)

        conn = self.openTCPConnection()

        for response in responses:
            self._toResponderQueue.put(response, True, 2.0)

        self.sendTCPQueryOverConnection(conn, query)

        # we sleep for one second, making sure that dnsdist
        # will fill its TCP window and buffers, which will result
        # in some short writes
        time.sleep(1)

        # we then read the messages
        receivedResponses = []
        while True:
            datalen = conn.recv(2)
            if not datalen:
                break

            (datalen,) = struct.unpack("!H", datalen)
            data = b''
            remaining = datalen
            got = conn.recv(remaining)
            while got:
                data = data + got
                if len(data) == datalen:
                    break
                remaining = remaining - len(got)
                if remaining <= 0:
                    break
                got = conn.recv(remaining)

            if data and len(data) == datalen:
                receivedResponse = dns.message.from_wire(data)
                receivedResponses.append(receivedResponse)

        receivedQuery = None
        if not self._fromResponderQueue.empty():
            receivedQuery = self._fromResponderQueue.get(True, 2.0)

        conn.close()

        # and check that everything is good
        self.assertTrue(receivedQuery)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponses, responses)

    def testTCPTLSShortWrite(self):
        """
        TCP/TLS: Short write to client
        """
        # same as testTCPShortWrite but over TLS this time
        name = 'short-write-tls.tcp-short.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AXFR', 'IN')
        responses = []
        soa = dns.rrset.from_text(name,
                                  60,
                                  dns.rdataclass.IN,
                                  dns.rdatatype.SOA,
                                  'ns.' + name + ' hostmaster.' + name + ' 1 3600 3600 3600 60')

        soaResponse = dns.message.make_response(query)
        soaResponse.use_edns(edns=False)
        soaResponse.answer.append(soa)
        responses.append(soaResponse)

        response = dns.message.make_response(query)
        response.use_edns(edns=False)
        content = ""
        for i in range(200):
            if len(content) > 0:
                content = content + ', '
            content = content + (str(i)*50)

        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    content)
        response.answer.append(rrset)

        for _ in range(200):
            responses.append(response)

        responses.append(soaResponse)

        conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert)

        for response in responses:
            self._toResponderQueue.put(response, True, 2.0)

        self.sendTCPQueryOverConnection(conn, query)

        time.sleep(1)

        receivedResponses = []
        while True:
            datalen = conn.recv(2)
            if not datalen:
                break

            (datalen,) = struct.unpack("!H", datalen)
            data = b''
            remaining = datalen
            got = conn.recv(remaining)
            while got:
                data = data + got
                if len(data) == datalen:
                    break
                remaining = remaining - len(got)
                if remaining <= 0:
                    break
                got = conn.recv(remaining)

            if data and len(data) == datalen:
                receivedResponse = dns.message.from_wire(data)
                receivedResponses.append(receivedResponse)

        receivedQuery = None
        if not self._fromResponderQueue.empty():
            receivedQuery = self._fromResponderQueue.get(True, 2.0)

        conn.close()

        self.assertTrue(receivedQuery)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(len(receivedResponses), len(responses))
        self.assertEquals(receivedResponses, responses)
