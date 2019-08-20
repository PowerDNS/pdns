#!/usr/bin/env python
import threading
import clientsubnetoption
import dns
import requests
import socket
import struct
from dnsdisttests import DNSDistTest

class TestBrokenTCPFastOpen(DNSDistTest):

    # this test suite uses a different responder port
    # because, contrary to the other ones, its
    # TCP responder will accept a connection, read the
    # query then just close the connection right away
    _testServerPort = 5410
    _testServerRetries = 5
    _webTimeout = 2.0
    _webServerPort = 8083
    _webServerBasicAuthPassword = 'secret'
    _webServerAPIKey = 'apisecret'
    _config_params = ['_testServerPort', '_testServerRetries', '_webServerPort', '_webServerBasicAuthPassword', '_webServerAPIKey']
    _config_template = """
    newServer{address="127.0.0.1:%s", useClientSubnet=true, tcpFastOpen=true, retries=%d }
    webserver("127.0.0.1:%s", "%s", "%s")
    """

    @classmethod
    def BrokenTCPResponder(cls, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except socket.error as e:
            print("Error binding in the TCP responder: %s" % str(e))
            sys.exit(1)

        sock.listen(100)
        while True:
            (conn, _) = sock.accept()
            conn.settimeout(5.0)
            data = conn.recv(2)
            if not data:
                conn.close()
                continue

            (datalen,) = struct.unpack("!H", data)
            data = conn.recv(datalen)
            conn.close()
            continue

        sock.close()

    @classmethod
    def startResponders(cls):
        print("Launching responders..")

        # Normal responder
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder.setDaemon(True)
        cls._UDPResponder.start()

        # Close the connection right after reading the query
        cls._TCPResponder = threading.Thread(name='Broken TCP Responder', target=cls.BrokenTCPResponder, args=[cls._testServerPort])
        cls._TCPResponder.setDaemon(True)
        cls._TCPResponder.start()

    def testTCOFastOpenOnCloseAfterRead(self):
        """
        TCP Fast Open: Close after read
        """
        name = 'close-after-read.tfo.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertFalse(receivedQuery)
        self.assertFalse(receivedResponse)

        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/api/v1/servers/localhost'
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEquals(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        self.assertTrue(len(content['servers']), 1)
        server = content['servers'][0]
        self.assertIn('tcpDiedReadingResponse', server)
        self.assertEquals(server['tcpDiedReadingResponse'], self._testServerRetries)
