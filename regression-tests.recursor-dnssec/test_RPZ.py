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

class RPZServer(object):

    def __init__(self, port):
        self._currentSerial = 0
        self._targetSerial = 1
        self._serverPort = port
        listener = threading.Thread(name='RPZ Listener', target=self._listener, args=[])
        listener.setDaemon(True)
        listener.start()

    def getCurrentSerial(self):
        return self._currentSerial

    def moveToSerial(self, newSerial):
        if newSerial == self._currentSerial:
            return False

        if newSerial != self._currentSerial + 1:
            raise AssertionError("Asking the RPZ server to server serial %d, already serving %d" % (newSerial, self._currentSerial))
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

            if oldSerial != self._currentSerial:
                print('Received an IXFR query with an unexpected serial %d, expected %d' % (oldSerial, self._currentSerial))
                return (None, self._currentSerial)

            newSerial = self._targetSerial
            if newSerial == 2:
                records = [
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % oldSerial),
                    # no deletion
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('b.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 3:
                records = [
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % oldSerial),
                    dns.rrset.from_text('a.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    # no addition
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 4:
                records = [
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % oldSerial),
                    dns.rrset.from_text('b.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('c.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 5:
                # this one is a bit special, we are answering with a full AXFR
                records = [
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('d.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'),
                    dns.rrset.from_text('tc.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.CNAME, 'rpz-tcp-only.'),
                    dns.rrset.from_text('drop.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.CNAME, 'rpz-drop.'),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 6:
                # back to IXFR
                records = [
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % oldSerial),
                    dns.rrset.from_text('d.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'),
                    dns.rrset.from_text('tc.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.CNAME, 'rpz-tcp-only.'),
                    dns.rrset.from_text('drop.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.CNAME, 'rpz-drop.'),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('e.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1', '192.0.2.2'),
                    dns.rrset.from_text('e.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.MX, '10 mx.example.'),
                    dns.rrset.from_text('f.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.CNAME, 'e.example.'),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 7:
                records = [
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % oldSerial),
                    dns.rrset.from_text('e.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1', '192.0.2.2'),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('e.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.2'),
                    dns.rrset.from_text('tc.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.CNAME, 'rpz-tcp-only.'),
                    dns.rrset.from_text('drop.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.CNAME, 'rpz-drop.'),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 8:
                # this one is a bit special too, we are answering with a full AXFR and the new zone is empty
                records = [
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial)
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
                print('Invalid RPZ query, qdcount is %d' % (len(message.question)))
                break
            if not message.question[0].rdtype in [dns.rdatatype.AXFR, dns.rdatatype.IXFR]:
                print('Invalid RPZ query, qtype is %d' % (message.question.rdtype))
                break
            (serial, answer) = self._getAnswer(message)
            if not answer:
                print('Unable to get a response for %s %d' % (message.question[0].name, message.question[0].rdtype))
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
                thread.setDaemon(True)
                thread.start()

            except socket.error as e:
                print('Error in RPZ socket: %s' % str(e))
                sock.close()

class RPZRecursorTest(RecursorTest):
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _confdir = 'RPZ'
    _lua_dns_script_file = """

    function prerpz(dq)
      -- disable the RPZ policy named 'zone.rpz' for AD=1 queries
      if dq:getDH():getAD() then
        dq:discardPolicy('zone.rpz.')
      end
      return false
    end
    """

    _config_template = """
auth-zones=example=configs/%s/example.zone
webserver=yes
webserver-port=%d
webserver-address=127.0.0.1
webserver-password=%s
api-key=%s
log-rpz-changes=yes
""" % (_confdir, _wsPort, _wsPassword, _apiKey)

    @classmethod
    def setUpClass(cls):

        cls.setUpSockets()
        cls.startResponders()

        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)

        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

    @classmethod
    def tearDownClass(cls):
        cls.tearDownRecursor()

    def checkBlocked(self, name, shouldBeBlocked=True, adQuery=False):
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        if adQuery:
            query.flags |= dns.flags.AD

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            if shouldBeBlocked:
                expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.1')
            else:
                expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.42')

            self.assertRRsetInAnswer(res, expected)

    def checkNotBlocked(self, name, adQuery=False):
        self.checkBlocked(name, False, adQuery)

    def checkCustom(self, qname, qtype, expected):
        query = dns.message.make_query(qname, qtype, want_dnssec=True)
        query.flags |= dns.flags.CD
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def checkNoData(self, qname, qtype):
        query = dns.message.make_query(qname, qtype, want_dnssec=True)
        query.flags |= dns.flags.CD
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(len(res.answer), 0)

    def checkNXD(self, qname, qtype='A'):
        query = dns.message.make_query(qname, qtype, want_dnssec=True)
        query.flags |= dns.flags.CD
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
            self.assertEqual(len(res.answer), 0)
            self.assertEqual(len(res.authority), 1)

    def checkTruncated(self, qname, qtype='A'):
        query = dns.message.make_query(qname, qtype, want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD', 'TC'])
        self.assertEqual(len(res.answer), 0)
        self.assertEqual(len(res.authority), 0)
        self.assertEqual(len(res.additional), 0)

        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'])
        self.assertEqual(len(res.answer), 0)
        self.assertEqual(len(res.authority), 1)
        self.assertEqual(len(res.additional), 0)

    def checkDropped(self, qname, qtype='A'):
        query = dns.message.make_query(qname, qtype, want_dnssec=True)
        query.flags |= dns.flags.CD
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertEqual(res, None)

    def checkRPZStats(self, serial, recordsCount, fullXFRCount, totalXFRCount):
        headers = {'x-api-key': self._apiKey}
        url = 'http://127.0.0.1:' + str(self._wsPort) + '/api/v1/servers/localhost/rpzstatistics'
        r = requests.get(url, headers=headers, timeout=self._wsTimeout)
        self.assertTrue(r)
        self.assertEquals(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        self.assertIn('zone.rpz.', content)
        zone = content['zone.rpz.']
        for key in ['last_update', 'records', 'serial', 'transfers_failed', 'transfers_full', 'transfers_success']:
            self.assertIn(key, zone)

        self.assertEquals(zone['serial'], serial)
        self.assertEquals(zone['records'], recordsCount)
        self.assertEquals(zone['transfers_full'], fullXFRCount)
        self.assertEquals(zone['transfers_success'], totalXFRCount)

rpzServerPort = 4250
rpzServer = RPZServer(rpzServerPort)

class RPZXFRRecursorTest(RPZRecursorTest):
    """
    This test makes sure that we correctly update RPZ zones via AXFR then IXFR
    """

    global rpzServerPort
    _lua_config_file = """
    -- The first server is a bogus one, to test that we correctly fail over to the second one
    rpzMaster({'127.0.0.1:9999', '127.0.0.1:%d'}, 'zone.rpz.', { refresh=1 })
    """ % (rpzServerPort)
    _confdir = 'RPZXFR'
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
    _xfrDone = 0

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
        super(RPZRecursorTest, cls).generateRecursorConfig(confdir)

    def waitUntilCorrectSerialIsLoaded(self, serial, timeout=5):
        global rpzServer

        rpzServer.moveToSerial(serial)

        attempts = 0
        while attempts < timeout:
            currentSerial = rpzServer.getCurrentSerial()
            if currentSerial > serial:
                raise AssertionError("Expected serial %d, got %d" % (serial, currentSerial))
            if currentSerial == serial:
                self._xfrDone = self._xfrDone + 1
                return

            attempts = attempts + 1
            time.sleep(1)

        raise AssertionError("Waited %d seconds for the serial to be updated to %d but the serial is still %d" % (timeout, serial, currentSerial))

    def testRPZ(self):
        # first zone, only a should be blocked
        self.waitUntilCorrectSerialIsLoaded(1)
        self.checkRPZStats(1, 1, 1, self._xfrDone)
        self.checkBlocked('a.example.')
        self.checkNotBlocked('b.example.')
        self.checkNotBlocked('c.example.')

        # second zone, a and b should be blocked
        self.waitUntilCorrectSerialIsLoaded(2)
        self.checkRPZStats(2, 2, 1, self._xfrDone)
        self.checkBlocked('a.example.')
        self.checkBlocked('b.example.')
        self.checkNotBlocked('c.example.')

        # third zone, only b should be blocked
        self.waitUntilCorrectSerialIsLoaded(3)
        self.checkRPZStats(3, 1, 1, self._xfrDone)
        self.checkNotBlocked('a.example.')
        self.checkBlocked('b.example.')
        self.checkNotBlocked('c.example.')

        # fourth zone, only c should be blocked
        self.waitUntilCorrectSerialIsLoaded(4)
        self.checkRPZStats(4, 1, 1, self._xfrDone)
        self.checkNotBlocked('a.example.')
        self.checkNotBlocked('b.example.')
        self.checkBlocked('c.example.')

        # fifth zone, we should get a full AXFR this time, and only d should be blocked
        self.waitUntilCorrectSerialIsLoaded(5)
        self.checkRPZStats(5, 3, 2, self._xfrDone)
        self.checkNotBlocked('a.example.')
        self.checkNotBlocked('b.example.')
        self.checkNotBlocked('c.example.')
        self.checkBlocked('d.example.')

        # sixth zone, only e should be blocked, f is a local data record
        self.waitUntilCorrectSerialIsLoaded(6)
        self.checkRPZStats(6, 2, 2, self._xfrDone)
        self.checkNotBlocked('a.example.')
        self.checkNotBlocked('b.example.')
        self.checkNotBlocked('c.example.')
        self.checkNotBlocked('d.example.')
        self.checkCustom('e.example.', 'A', dns.rrset.from_text('e.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.1', '192.0.2.2'))
        self.checkCustom('e.example.', 'MX', dns.rrset.from_text('e.example.', 0, dns.rdataclass.IN, 'MX', '10 mx.example.'))
        self.checkNoData('e.example.', 'AAAA')
        self.checkCustom('f.example.', 'A', dns.rrset.from_text('f.example.', 0, dns.rdataclass.IN, 'CNAME', 'e.example.'))

        # seventh zone, e should only have one A
        self.waitUntilCorrectSerialIsLoaded(7)
        self.checkRPZStats(7, 4, 2, self._xfrDone)
        self.checkNotBlocked('a.example.')
        self.checkNotBlocked('b.example.')
        self.checkNotBlocked('c.example.')
        self.checkNotBlocked('d.example.')
        self.checkCustom('e.example.', 'A', dns.rrset.from_text('e.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.2'))
        self.checkCustom('e.example.', 'MX', dns.rrset.from_text('e.example.', 0, dns.rdataclass.IN, 'MX', '10 mx.example.'))
        self.checkNoData('e.example.', 'AAAA')
        self.checkCustom('f.example.', 'A', dns.rrset.from_text('f.example.', 0, dns.rdataclass.IN, 'CNAME', 'e.example.'))
        # check that the policy is disabled for AD=1 queries
        self.checkNotBlocked('e.example.', True)
        # check non-custom policies
        self.checkTruncated('tc.example.')
        self.checkDropped('drop.example.')

        # eighth zone, all entries should be gone
        self.waitUntilCorrectSerialIsLoaded(8)
        self.checkRPZStats(8, 0, 3, self._xfrDone)
        self.checkNotBlocked('a.example.')
        self.checkNotBlocked('b.example.')
        self.checkNotBlocked('c.example.')
        self.checkNotBlocked('d.example.')
        self.checkNotBlocked('e.example.')
        self.checkNXD('f.example.')
        self.checkNXD('tc.example.')
        self.checkNXD('drop.example.')

class RPZFileRecursorTest(RPZRecursorTest):
    """
    This test makes sure that we correctly load RPZ zones from a file
    """

    _confdir = 'RPZFile'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _lua_config_file = """
    rpzFile('configs/%s/zone.rpz', { policyName="zone.rpz." })
    """ % (_confdir)
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
z 3600 IN A 192.0.2.42
""".format(soa=cls._SOA))

        rpzFilePath = os.path.join(confdir, 'zone.rpz')
        with open(rpzFilePath, 'w') as rpzZone:
            rpzZone.write("""$ORIGIN zone.rpz.
@ 3600 IN SOA {soa}
a.example.zone.rpz. 60 IN A 192.0.2.42
a.example.zone.rpz. 60 IN A 192.0.2.43
a.example.zone.rpz. 60 IN TXT "some text"
drop.example.zone.rpz. 60 IN CNAME rpz-drop.
z.example.zone.rpz. 60 IN A 192.0.2.1
tc.example.zone.rpz. 60 IN CNAME rpz-tcp-only.
""".format(soa=cls._SOA))
        super(RPZFileRecursorTest, cls).generateRecursorConfig(confdir)

    def testRPZ(self):
        self.checkCustom('a.example.', 'A', dns.rrset.from_text('a.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.42', '192.0.2.43'))
        self.checkCustom('a.example.', 'TXT', dns.rrset.from_text('a.example.', 0, dns.rdataclass.IN, 'TXT', '"some text"'))
        self.checkBlocked('z.example.')
        self.checkNotBlocked('b.example.')
        self.checkNotBlocked('c.example.')
        self.checkNotBlocked('d.example.')
        self.checkNotBlocked('e.example.')
        # check that the policy is disabled for AD=1 queries
        self.checkNotBlocked('z.example.', True)
        # check non-custom policies
        self.checkTruncated('tc.example.')
        self.checkDropped('drop.example.')

class RPZFileDefaultPolRecursorTest(RPZRecursorTest):
    """
    This test makes sure that we correctly load RPZ zones from a file with a default policy
    """

    _confdir = 'RPZFileDefaultPolicy'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _lua_config_file = """
    rpzFile('configs/%s/zone.rpz', { policyName="zone.rpz.", defpol=Policy.NoAction })
    """ % (_confdir)
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
drop 3600 IN A 192.0.2.42
e 3600 IN A 192.0.2.42
z 3600 IN A 192.0.2.42
""".format(soa=cls._SOA))

        rpzFilePath = os.path.join(confdir, 'zone.rpz')
        with open(rpzFilePath, 'w') as rpzZone:
            rpzZone.write("""$ORIGIN zone.rpz.
@ 3600 IN SOA {soa}
a.example.zone.rpz. 60 IN A 192.0.2.42
drop.example.zone.rpz. 60 IN CNAME rpz-drop.
z.example.zone.rpz. 60 IN A 192.0.2.1
tc.example.zone.rpz. 60 IN CNAME rpz-tcp-only.
""".format(soa=cls._SOA))
        super(RPZFileDefaultPolRecursorTest, cls).generateRecursorConfig(confdir)

    def testRPZ(self):
        # local data entries are overridden by default
        self.checkCustom('a.example.', 'A', dns.rrset.from_text('a.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.42'))
        self.checkNoData('a.example.', 'TXT')
        # will not be blocked because the default policy overrides local data entries by default
        self.checkNotBlocked('z.example.')
        self.checkNotBlocked('b.example.')
        self.checkNotBlocked('c.example.')
        self.checkNotBlocked('d.example.')
        self.checkNotBlocked('e.example.')
        # check non-local policies, they should be overridden by the default policy
        self.checkNXD('tc.example.', 'A')
        self.checkNotBlocked('drop.example.')

class RPZFileDefaultPolNotOverrideLocalRecursorTest(RPZRecursorTest):
    """
    This test makes sure that we correctly load RPZ zones from a file with a default policy, not overriding local data entries
    """

    _confdir = 'RPZFileDefaultPolicyNotOverrideLocal'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _lua_config_file = """
    rpzFile('configs/%s/zone.rpz', { policyName="zone.rpz.", defpol=Policy.NoAction, defpolOverrideLocalData=false })
    """ % (_confdir)
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
drop 3600 IN A 192.0.2.42
e 3600 IN A 192.0.2.42
z 3600 IN A 192.0.2.42
""".format(soa=cls._SOA))

        rpzFilePath = os.path.join(confdir, 'zone.rpz')
        with open(rpzFilePath, 'w') as rpzZone:
            rpzZone.write("""$ORIGIN zone.rpz.
@ 3600 IN SOA {soa}
a.example.zone.rpz. 60 IN A 192.0.2.42
a.example.zone.rpz. 60 IN A 192.0.2.43
a.example.zone.rpz. 60 IN TXT "some text"
drop.example.zone.rpz. 60 IN CNAME rpz-drop.
z.example.zone.rpz. 60 IN A 192.0.2.1
tc.example.zone.rpz. 60 IN CNAME rpz-tcp-only.
""".format(soa=cls._SOA))
        super(RPZFileDefaultPolNotOverrideLocalRecursorTest, cls).generateRecursorConfig(confdir)

    def testRPZ(self):
        # local data entries will not be overridden by the default polic
        self.checkCustom('a.example.', 'A', dns.rrset.from_text('a.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.42', '192.0.2.43'))
        self.checkCustom('a.example.', 'TXT', dns.rrset.from_text('a.example.', 0, dns.rdataclass.IN, 'TXT', '"some text"'))
        # will be blocked because the default policy does not override local data entries
        self.checkBlocked('z.example.')
        self.checkNotBlocked('b.example.')
        self.checkNotBlocked('c.example.')
        self.checkNotBlocked('d.example.')
        self.checkNotBlocked('e.example.')
        # check non-local policies, they should be overridden by the default policy
        self.checkNXD('tc.example.', 'A')
        self.checkNotBlocked('drop.example.')
