import dns
import json
import os
import requests
import socket
import struct
import sys
import threading
import time

from recursortests import RecursorTest

class BadRPZServer(object):

    def __init__(self, port):
        self._currentSerial = 0
        self._targetSerial = 1
        self._serverPort = port
        listener = threading.Thread(name='RPZ Listener', target=self._listener, args=[])
        listener.daemon = True
        listener.start()

    def getCurrentSerial(self):
        return self._currentSerial

    def moveToSerial(self, newSerial):
        if newSerial == self._currentSerial:
            return False

        #if newSerial != self._currentSerial + 1:
        #    raise AssertionError("Asking the RPZ server to serve serial %d, already serving %d" % (newSerial, self._currentSerial))
        self._targetSerial = newSerial
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
            data = conn.recv(2)
            if not data:
                break
            (datalen,) = struct.unpack("!H", data)
            data = conn.recv(datalen)
            if not data:
                break

            message = dns.message.from_wire(data)
            if len(message.question) != 1:
                print('Invalid RPZ query, qdcount is %d' % (len(message.question)), file=sys.stderr)
                break
            if not message.question[0].rdtype in [dns.rdatatype.AXFR, dns.rdatatype.IXFR]:
                print('Invalid RPZ query, qtype is %d' % (message.question.rdtype), file=sys.stderr)
                break
            (serial, answer) = self._getAnswer(message)
            if not answer:
                print('Unable to get a response for %s %d' % (message.question[0].name, message.question[0].rdtype), file=sys.stderr)
                break

            wire = answer.to_wire()
            conn.send(struct.pack("!H", len(wire)))
            conn.send(wire)
            self._currentSerial = serial
            break

        conn.close()

    def _listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            sock.bind(("127.0.0.1", self._serverPort))
        except socket.error as e:
            print("Error binding in the RPZ listener: %s" % str(e))
            sys.exit(1)

        sock.listen(100)
        while True:
            try:
                (conn, _) = sock.accept()
                thread = threading.Thread(name='RPZ Connection Handler',
                                      target=self._connectionHandler,
                                      args=[conn])
                thread.daemon = True
                thread.start()

            except socket.error as e:
                print('Error in RPZ socket: %s' % str(e))
                sock.close()

class RPZIncompleteRecursorTest(RecursorTest):
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _confdir = 'RPZIncompleteRecursor'
    _auth_zones = {
        '8': {'threads': 1,
              'zones': ['ROOT']},
        '10': {'threads': 1,
               'zones': ['example']},
    }

    _config_template = """
auth-zones=example=configs/%s/example.zone
webserver=yes
webserver-port=%d
webserver-address=127.0.0.1
webserver-password=%s
api-key=%s
log-rpz-changes=yes
""" % (_confdir, _wsPort, _wsPassword, _apiKey)

    def checkRPZStats(self, serial, recordsCount, fullXFRCount, totalXFRCount, failedXFRCount):
        headers = {'x-api-key': self._apiKey}
        url = 'http://127.0.0.1:' + str(self._wsPort) + '/api/v1/servers/localhost/rpzstatistics'
        r = requests.get(url, headers=headers, timeout=self._wsTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        self.assertIn('zone.rpz.', content)
        zone = content['zone.rpz.']
        for key in ['last_update', 'records', 'serial', 'transfers_failed', 'transfers_full', 'transfers_success']:
            self.assertIn(key, zone)

        self.assertEqual(zone['serial'], serial)
        self.assertEqual(zone['records'], recordsCount)
        self.assertEqual(zone['transfers_full'], fullXFRCount)
        self.assertEqual(zone['transfers_success'], totalXFRCount)
        self.assertEqual(zone['transfers_failed'], failedXFRCount)

badrpzServerPort = 4251
badrpzServer = BadRPZServer(badrpzServerPort)

class RPZXFRIncompleteRecursorTest(RPZIncompleteRecursorTest):
    """
    This test makes sure that we correctly detect incomplete RPZ zones via AXFR then IXFR
    """

    global badrpzServerPort
    _lua_config_file = """
    -- The first server is a bogus one, to test that we correctly fail over to the second one
    rpzPrimary({'127.0.0.1:9999', '127.0.0.1:%d'}, 'zone.rpz.', { refresh=1 })
    """ % (badrpzServerPort)
    _confdir = 'RPZXFRIncompleteRecursor'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _config_template = """
auth-zones=example=configs/%s/example.zone
webserver=yes
webserver-port=%d
webserver-address=127.0.0.1
webserver-password=%s
api-key=%s
""" % (_confdir, _wsPort, _wsPassword, _apiKey)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'example.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN example.
@ 3600 IN SOA {soa}
a 3600 IN A 192.0.2.42
b 3600 IN A 192.0.2.42
c 3600 IN A 192.0.2.42
d 3600 IN A 192.0.2.42
e 3600 IN A 192.0.2.42
""".format(soa=cls._SOA))
        super(RPZXFRIncompleteRecursorTest, cls).generateRecursorConfig(confdir)

    def waitUntilCorrectSerialIsLoaded(self, serial, timeout=5):
        global badrpzServer

        badrpzServer.moveToSerial(serial)

        attempts = 0
        while attempts < timeout:
            currentSerial = badrpzServer.getCurrentSerial()
            if currentSerial > serial:
                raise AssertionError("Expected serial %d, got %d" % (serial, currentSerial))
            if currentSerial == serial:
                return

            attempts = attempts + 1
            time.sleep(1)

        raise AssertionError("Waited %d seconds for the serial to be updated to %d but the serial is still %d" % (timeout, serial, currentSerial))

    def testRPZ(self):
        self.waitForTCPSocket("127.0.0.1", self._wsPort)
        # First zone
        self.waitUntilCorrectSerialIsLoaded(1)
        self.checkRPZStats(1, 1, 1, 1, 1) # failure count includes a port 9999 attempt

        # second zone, should fail, incomplete IXFR
        self.waitUntilCorrectSerialIsLoaded(2)
        self.checkRPZStats(1, 1, 1, 1, 3)

        # third zone, should fail, incomplete AXFR
        self.waitUntilCorrectSerialIsLoaded(3)
        self.checkRPZStats(1, 1, 1, 1, 5)

