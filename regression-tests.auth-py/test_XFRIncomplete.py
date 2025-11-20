import dns
import os
import socket
import struct
import sys
import threading
import time

from authtests import AuthTest

class BadXFRServer(object):

    def __init__(self, port):
        self._currentSerial = 0
        self._targetSerial = 1
        self._serverPort = port
        listener = threading.Thread(name='XFR Listener', target=self._listener, args=[])
        listener.setDaemon(True)
        listener.start()

    def getCurrentSerial(self):
        return self._currentSerial

    def moveToSerial(self, newSerial):
        if newSerial == self._currentSerial or newSerial == self._targetSerial:
            return False

        #if newSerial != self._currentSerial + 1:
        #    raise AssertionError("Asking the XFR server to serve serial %d, already serving %d" % (newSerial, self._currentSerial))
        self._targetSerial = newSerial
        print("moveToSerial %d" % newSerial, file=sys.stderr)
        return True

    def _getAnswer(self, message):

        response = dns.message.make_response(message)
        records = []

        if message.question[0].rdtype == dns.rdatatype.AXFR:
            if self._currentSerial != 0:
                print('Received an AXFR query but IXFR expected because the current serial is %d' % (self._currentSerial))
                return (None, self._currentSerial)

            newSerial = self._targetSerial
            records = [
                dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                dns.rrset.from_text('a.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'),
                dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial)
                ]

        elif message.question[0].rdtype == dns.rdatatype.IXFR:
            oldSerial = message.authority[0][0].serial

            newSerial = self._targetSerial
            if newSerial == 2:
                records = [
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % oldSerial),
                    # no deletion
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('b.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'),
                    ]
            elif newSerial == 3:
                records = [
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('a.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'),
                    ]

        response.answer = records
        return (newSerial, response)

    def _connectionHandler(self, conn):
        data = None
        while True:
            print("Reading from connection...", file=sys.stderr)
            data = conn.recv(2)
            if not data:
                break
            (datalen,) = struct.unpack("!H", data)
            data = conn.recv(datalen)
            print("Received request with len %d" % datalen, file=sys.stderr)
            if not data:
                break

            message = dns.message.from_wire(data)
            if len(message.question) != 1:
                print('Invalid query, qdcount is %d' % (len(message.question)), file=sys.stderr)
                break
            if not message.question[0].rdtype in [dns.rdatatype.AXFR, dns.rdatatype.IXFR]:
                print('Invalid query, qtype is %d' % (message.question.rdtype), file=sys.stderr)
                break
            print(message, file=sys.stderr)
            (serial, answer) = self._getAnswer(message)
            if not answer:
                print('Unable to get a response for %s %d' % (message.question[0].name, message.question[0].rdtype), file=sys.stderr)
                break

            wire = answer.to_wire()
            conn.send(struct.pack("!H", len(wire)))
            conn.send(wire)
            print("_currentSerial to %d" % serial, file=sys.stderr)
            self._currentSerial = serial
            break

        print("_connectionHandler: stop", file=sys.stderr)
        conn.close()

    def _listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            sock.bind(("127.0.0.1", self._serverPort))
        except socket.error as e:
            print("Error binding in the IXFR listener: %s" % str(e))
            sys.exit(1)

        sock.listen(100)
        while True:
            try:
                (conn, _) = sock.accept()
                print("New connection", file=sys.stderr)
                thread = threading.Thread(name='IXFR Connection Handler',
                                      target=self._connectionHandler,
                                      args=[conn])
                thread.setDaemon(True)
                thread.start()

            except socket.error as e:
                print('Error in IXFR socket: %s' % str(e))
                sock.close()

badxfrServerPort = 4251
badxfrServer = BadXFRServer(badxfrServerPort)

class XFRIncompleteAuthTest(AuthTest):
    """
    This test makes sure that we correctly detect incomplete RPZ zones via AXFR then IXFR
    """

    global badxfrServerPort

    _backend = 'gsqlite3'

    _config_template = """
launch=gsqlite3
gsqlite3-database=configs/auth/powerdns.sqlite
gsqlite3-dnssec
secondary
cache-ttl=0
query-cache-ttl=0
domain-metadata-cache-ttl=0
negquery-cache-ttl=0
xfr-cycle-interval=1
#loglevel=9
#axfr-fetch-timeout=20
"""

    @classmethod
    def setUpClass(cls):
        super(XFRIncompleteAuthTest, cls).setUpClass()
        os.system("$PDNSUTIL --config-dir=configs/auth create-secondary-zone zone.rpz. 127.0.0.1:%s" % (badxfrServerPort,))
        os.system("$PDNSUTIL --config-dir=configs/auth set-meta zone.rpz. IXFR 1")
    
    def waitUntilCorrectSerialIsLoaded(self, serial, timeout=20):
        global badxfrServer

        badxfrServer.moveToSerial(serial)

        attempts = 0
        while attempts < timeout:
            currentSerial = badxfrServer.getCurrentSerial()
            if currentSerial > serial:
                raise AssertionError("Expected serial %d, got %d" % (serial, currentSerial))
            if currentSerial == serial:
                badxfrServer.moveToSerial(serial+1)
                return

            attempts = attempts + 1
            time.sleep(1)

        raise AssertionError("Waited %d seconds for the serial to be updated to %d but the serial is still %d" % (timeout, serial, currentSerial))

    def checkZone(self):
        query = dns.message.make_query('zone.rpz.', 'SOA')
        res = self.sendUDPQuery(query) # , count=len(expected))

        expected = [dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. 1 3600 3600 3600 1')]
        self.assertEqual(res.answer, expected)

    def doRetrieve(self):
        os.system("$PDNSCONTROL --socket-dir=configs/auth retrieve zone.rpz.")

    def testXFR(self):
        # self.waitForTCPSocket("127.0.0.1", self._wsPort)
        # First zone
        self.doRetrieve()
        self.waitUntilCorrectSerialIsLoaded(1)
        self.checkZone()

        # second zone, should fail, incomplete IXFR
        self.doRetrieve()
        self.waitUntilCorrectSerialIsLoaded(2)
        self.checkZone()

        # third zone, should fail, incomplete AXFR
        self.doRetrieve()
        self.waitUntilCorrectSerialIsLoaded(3)
        self.checkZone()
