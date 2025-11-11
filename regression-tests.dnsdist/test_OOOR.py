#!/usr/bin/env python
import dns
import socket
import struct
import time
import threading
from dnsdisttests import DNSDistTest, pickAvailablePort

class OOORTCPResponder(object):

    def handleConnection(self, conn):
        try:

            while True:
                try:
                    data = conn.recv(2)
                except socket.timeout:
                    data = None

                if not data:
                    conn.close()
                    break

                (datalen,) = struct.unpack("!H", data)
                data = conn.recv(datalen)

                # computing the correct ID for the response
                request = dns.message.from_wire(data)
                #print("got a query for %s" % (request.question[0].name))
                if request.question[0].name == "0.simple.ooor.tests.powerdns.com":
                    time.sleep(1)

                response = dns.message.make_response(request)

                wire = response.to_wire()
                conn.send(struct.pack("!H", len(wire)))
                conn.send(wire)

        except ConnectionError as err:
            print("Error in the thread handling reverse OOOR connections: %s" % (err))
        finally:
            conn.close()

    def __init__(self, port):
        OOORTCPResponder.numberOfConnections = 0

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except socket.error as e:
            print("Error binding in the TCP responder: %s" % str(e))
            sys.exit(1)

        sock.listen(100)

        try:
            while True:
                (conn, _) = sock.accept()
                conn.settimeout(5.0)

                OOORTCPResponder.numberOfConnections = OOORTCPResponder.numberOfConnections + 1
                thread = threading.Thread(name='Connection Handler',
                                        target=self.handleConnection,
                                        args=[conn])
                thread.daemon = True
                thread.start()

        finally:
            sock.close()

class ReverseOOORTCPResponder(OOORTCPResponder):

    def handleConnection(self, conn):
        try:
            # short timeout since we want to answer only after receiving 5 requests
            # or a timeout
            conn.settimeout(0.2)

            queuedResponses = []
            while True:
                timedout = False
                try:
                    data = conn.recv(2)
                except socket.timeout:
                    data = None
                    timedout = True

                if timedout or len(queuedResponses) >= 5:
                    queuedResponses.reverse()
                    for response in queuedResponses:
                        wire = response.to_wire()
                        conn.send(struct.pack("!H", len(wire)))
                        conn.send(wire)
                    queuedResponses = []
                    if timedout:
                        continue
                elif not data:
                    conn.close()
                    break

                (datalen,) = struct.unpack("!H", data)
                data = conn.recv(datalen)

                # computing the correct ID for the response
                request = dns.message.from_wire(data)
                #print("got a query for %s" % (request.question[0].name))

                response = dns.message.make_response(request)
                queuedResponses.append(response)

        except ConnectionError as err:
            print("Error in the thread handling reverse OOOR connections: %s" % (err))
        finally:
            conn.close()

    def __init__(self, port):
        ReverseOOORTCPResponder.numberOfConnections = 0

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except socket.error as e:
            print("Error binding in the TCP responder: %s" % str(e))
            sys.exit(1)

        sock.listen(100)

        try:
            while True:
                (conn, _) = sock.accept()

                ReverseOOORTCPResponder.numberOfConnections = ReverseOOORTCPResponder.numberOfConnections + 1
                thread = threading.Thread(name='Connection Handler',
                                        target=self.handleConnection,
                                        args=[conn])
                thread.daemon = True
                thread.start()

        finally:
            sock.close()


OOORResponderPort = pickAvailablePort()
ooorTCPResponder = threading.Thread(name='TCP Responder', target=OOORTCPResponder, args=[OOORResponderPort])
ooorTCPResponder.daemon = True
ooorTCPResponder.start()

ReverseOOORResponderPort = pickAvailablePort()
ReverseOoorTCPResponder = threading.Thread(name='TCP Responder', target=ReverseOOORTCPResponder, args=[ReverseOOORResponderPort])
ReverseOoorTCPResponder.daemon = True
ReverseOoorTCPResponder.start()

class TestOOORWithClientNotBackend(DNSDistTest):
    # this test suite uses a different responder port
    _testServerPort = OOORResponderPort

    _concurrentQueriesFromClient = 10
    _config_template = """
    newServer{address="127.0.0.1:%d", maxInFlight=0, pool={""}}:setUp()
    newServer{address="127.0.0.1:%d", maxInFlight=0, pool={"more-queries"}}:setUp()
    -- route these queries to a different backend so we don't reuse the connection from a previous test
    addAction("more-queries.ooor.tests.powerdns.com.", PoolAction("more-queries"))
    setLocal("%s:%d", {maxInFlight=%d})
    """
    _config_params = ['_testServerPort', '_testServerPort', '_dnsDistListeningAddr', '_dnsDistPort', '_concurrentQueriesFromClient']
    _verboseMode = True
    _skipListeningOnCL = True

    @classmethod
    def startResponders(cls):
        return

    def testSimple(self):
        """
        OOOR: 5 queries
        """
        names = []
        OOORTCPResponder.numberOfConnections = 0

        for idx in range(5):
            names.append('%d.simple.ooor.tests.powerdns.com.' % (idx))

        conn = self.openTCPConnection()

        counter = 0
        for name in names:
            query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
            query.id = counter
            counter = counter + 1

            self.sendTCPQueryOverConnection(conn, query)

        receivedResponses = {}

        for name in names:
            receivedResponse = self.recvTCPResponseOverConnection(conn)
            self.assertTrue(receivedResponse)
            receivedResponses[str(receivedResponse.question[0].name)] = (receivedResponse)

        self.assertEqual(len(receivedResponses), 5)
        for idx in range(5):
            self.assertIn('%d.simple.ooor.tests.powerdns.com.' % (idx), receivedResponses)

        # we can get a response to one of the first query before they all have
        # been read, reusing a backend connection
        self.assertLessEqual(OOORTCPResponder.numberOfConnections, 5)

    def testMoreQueriesThanAllowedInFlight(self):
        """
        OOOR: 100 queries, 10 in flight
        """
        names = []
        OOORTCPResponder.numberOfConnections = 0

        for idx in range(100):
            names.append('%d.more-queries.ooor.tests.powerdns.com.' % (idx))

        conn = self.openTCPConnection()

        counter = 0
        for name in names:
            query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
            query.id = counter
            counter = counter + 1

            self.sendTCPQueryOverConnection(conn, query)

        receivedResponses = {}

        for name in names:
            receivedResponse = self.recvTCPResponseOverConnection(conn)
            self.assertTrue(receivedResponse)
            receivedResponses[str(receivedResponse.question[0].name)] = (receivedResponse)

        self.assertEqual(len(receivedResponses), 100)
        for idx in range(5):
            self.assertIn('%d.more-queries.ooor.tests.powerdns.com.' % (idx), receivedResponses)

        self.assertLessEqual(OOORTCPResponder.numberOfConnections, self._concurrentQueriesFromClient)

class TestOOORWithClientAndBackend(DNSDistTest):
    # this test suite uses a different responder port
    _testServerPort = ReverseOOORResponderPort

    _concurrentQueriesFromClient = 10
    _concurrentQueriesToServer = 5
    _config_template = """
    newServer{address="127.0.0.1:%d", maxInFlight=%d, pool={""}}:setUp()
    newServer{address="127.0.0.1:%d", maxInFlight=%d, pool={"more-queries"}}:setUp()
    -- route these queries to a different backend so we don't reuse the connection from a previous test
    addAction("more-queries.reverse-ooor.tests.powerdns.com.", PoolAction("more-queries"))
    setLocal("%s:%d", {maxInFlight=%d})
    """
    _config_params = ['_testServerPort', '_concurrentQueriesToServer', '_testServerPort', '_concurrentQueriesToServer', '_dnsDistListeningAddr', '_dnsDistPort', '_concurrentQueriesFromClient']
    _verboseMode = True
    _skipListeningOnCL = True

    @classmethod
    def startResponders(cls):
        return

    def testSimple(self):
        """
        OOOR Reverse: 5 queries
        """
        names = []
        ReverseOOORTCPResponder.numberOfConnections = 0

        for idx in range(5):
            names.append('%d.simple.reverse-ooor.tests.powerdns.com.' % (idx))

        conn = self.openTCPConnection()

        counter = 0
        for name in names:
            query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
            query.id = counter
            counter = counter + 1

            self.sendTCPQueryOverConnection(conn, query)

        receivedResponses = {}

        for name in names:
            receivedResponse = self.recvTCPResponseOverConnection(conn)
            self.assertTrue(receivedResponse)
            receivedResponses[str(receivedResponse.question[0].name)] = (receivedResponse)

        self.assertEqual(len(receivedResponses), 5)
        for idx in range(5):
            self.assertIn('%d.simple.reverse-ooor.tests.powerdns.com.' % (idx), receivedResponses)

        self.assertEqual(ReverseOOORTCPResponder.numberOfConnections, 1)

    def testMoreQueriesThanAllowedInFlight(self):
        """
        OOOR Reverse: 100 queries, 10 in flight, 5 per backend
        """
        names = []
        ReverseOOORTCPResponder.numberOfConnections = 0

        for idx in range(100):
            names.append('%d.more-queries.reverse-ooor.tests.powerdns.com.' % (idx))

        conn = self.openTCPConnection()

        counter = 0
        for name in names:
            query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
            query.id = counter
            counter = counter + 1

            self.sendTCPQueryOverConnection(conn, query)

        receivedResponses = {}

        for name in names:
            receivedResponse = self.recvTCPResponseOverConnection(conn)
            self.assertTrue(receivedResponse)
            receivedResponses[str(receivedResponse.question[0].name)] = (receivedResponse)
            #print("Received a response for %s" % (receivedResponse.question[0].name))

        self.assertEqual(len(receivedResponses), 100)
        for idx in range(5):
            self.assertIn('%d.more-queries.reverse-ooor.tests.powerdns.com.' % (idx), receivedResponses)

        # in theory they could all be handled by the same backend if we get the responses
        # fast enough, but over 100 queries that's very, very unlikely
        self.assertEqual(ReverseOOORTCPResponder.numberOfConnections, 2)
