import dns
import dns.zone
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
        listener.daemon = True
        listener.start()

    def getCurrentSerial(self):
        return self._currentSerial

    def moveToSerial(self, newSerial):
        if newSerial == self._currentSerial:
            return False

        if newSerial != self._currentSerial + 1:
            raise AssertionError("Asking the RPZ server to serve serial %d, already serving %d" % (newSerial, self._currentSerial))
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

            # special case for the 9th update, which might get skipped
            if oldSerial != self._currentSerial and self._currentSerial != 9:
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
            elif newSerial == 9:
                # IXFR inserting a duplicate, we should not crash and skip it
                records = [
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % oldSerial),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('dup.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.CNAME, 'rpz-passthru.'),
                    dns.rrset.from_text('dup.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.CNAME, 'rpz-passthru.'),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 10:
                # full AXFR to make sure we are removing the duplicate, adding a record, to check that the update was correctly applied
                records = [
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('f.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 11:
                # IXFR with two deltas, the first one adding a 'g' and the second one removing 'f'
                records = [
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % (newSerial + 1)),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % oldSerial),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('g.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('f.example.zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % (newSerial + 1)),
                    dns.rrset.from_text('zone.rpz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.zone.rpz. hostmaster.zone.rpz. %d 3600 3600 3600 1' % (newSerial + 1))
                    ]
                # this one has two updates in one
                newSerial = newSerial + 1
                self._targetSerial = self._targetSerial + 1

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
            lenprefix = struct.pack("!H", len(wire))

            for b in lenprefix:
                conn.send(bytes([b]))
                time.sleep(0.1)

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

class RPZRecursorTest(RecursorTest):
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _confdir = 'RPZ'
    _auth_zones = {
        '8': {'threads': 1,
              'zones': ['ROOT']},
        '10': {'threads': 1,
               'zones': ['example']},
    }
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

    def sendNotify(self):
        notify = dns.message.make_query('zone.rpz', 'SOA', want_dnssec=False)
        notify.set_opcode(4) # notify
        res = self.sendUDPQuery(notify)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(res.opcode(), 4)
        self.assertEqual(res.question[0].to_text(), 'zone.rpz. IN SOA')

    def assertAdditionalHasSOA(self, msg, name):
        if not isinstance(msg, dns.message.Message):
            raise TypeError("msg is not a dns.message.Message but a %s" % type(msg))

        found = False
        for rrset in msg.additional:
            if rrset.rdtype == dns.rdatatype.SOA and str(rrset.name) == name:
                found = True
                break

        if not found:
            raise AssertionError("No %s SOA record found in the additional section:\n%s" % (name, msg.to_text()))

    def checkBlocked(self, name, shouldBeBlocked=True, adQuery=False, singleCheck=False, soa=None):
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
            if soa:
                self.assertAdditionalHasSOA(res, soa)
            if singleCheck:
                break

    def checkNotBlocked(self, name, adQuery=False, singleCheck=False):
        self.checkBlocked(name, False, adQuery, singleCheck)

    def checkCustom(self, qname, qtype, expected, soa=None):
        query = dns.message.make_query(qname, qtype, want_dnssec=True)
        query.flags |= dns.flags.CD
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)
            if soa:
                self.assertAdditionalHasSOA(res, soa)

    def checkNoData(self, qname, qtype, soa=None):
        query = dns.message.make_query(qname, qtype, want_dnssec=True)
        query.flags |= dns.flags.CD
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(len(res.answer), 0)
            if soa:
                self.assertAdditionalHasSOA(res, soa)

    def checkNXD(self, qname, qtype='A'):
        query = dns.message.make_query(qname, qtype, want_dnssec=True)
        query.flags |= dns.flags.CD
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
            self.assertEqual(len(res.answer), 0)
            self.assertEqual(len(res.authority), 1)

    def checkTruncated(self, qname, qtype='A', soa=None):
        query = dns.message.make_query(qname, qtype, want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD', 'TC'])
        self.assertEqual(len(res.answer), 0)
        self.assertEqual(len(res.authority), 0)
        if soa:
            self.assertAdditionalHasSOA(res, soa)

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

rpzServerPort = 4250
rpzServer = RPZServer(rpzServerPort)

class RPZXFRRecursorTest(RPZRecursorTest):
    """
    This test makes sure that we correctly update RPZ zones via AXFR then IXFR
    """

    global rpzServerPort
    _confdir = 'RPZXFRRecursor'
    _lua_config_file = """
    -- The first server is a bogus one, to test that we correctly fail over to the second one
    rpzPrimary({'127.0.0.1:9999', '127.0.0.1:%d'}, 'zone.rpz.', { refresh=1, includeSOA=true, dumpFile="configs/%s/rpz.zone.dump"})
    """ % (rpzServerPort, _confdir)
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
disable-packetcache
allow-notify-from=127.0.0.0/8
allow-notify-for=zone.rpz
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
        super(RPZXFRRecursorTest, cls).generateRecursorConfig(confdir)

    def checkDump(self, serial, timeout=2):
        file = 'configs/%s/rpz.zone.dump' % self._confdir
        attempts = 0
        incr = .1
        # There's a file base race here, so do a few attempts
        while attempts < timeout:
            try:
                zone = dns.zone.from_file(file, 'zone.rpz', relativize=False, check_origin=False, allow_include=False)
                soa = zone['']
                soa.find_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
                # if the above call did not throw an exception, the SOA has the right owner, continue
                soa = zone.get_soa()
                if soa.serial == serial and soa.mname == dns.name.from_text('ns.zone.rpz.'):
                    return # we found what we expected
            except FileNotFoundError as e:
                pass
            attempts = attempts + incr
            time.sleep(incr)
        raise AssertionError("Waited %d seconds for the dumpfile to be updated to %d but the serial is still %d" % (timeout, serial, soa.serial))

    def waitUntilCorrectSerialIsLoaded(self, serial, timeout=5):
        global rpzServer

        rpzServer.moveToSerial(serial)

        attempts = 0
        incr = .1
        while attempts < timeout:
            currentSerial = rpzServer.getCurrentSerial()
            if currentSerial > serial:
                raise AssertionError("Expected serial %d, got %d" % (serial, currentSerial))
            if currentSerial == serial:
                self._xfrDone = self._xfrDone + 1
                self.checkDump(serial)
                return

            attempts = attempts + incr
            time.sleep(incr)

        raise AssertionError("Waited %d seconds for the serial to be updated to %d but the serial is still %d" % (timeout, serial, currentSerial))

    def testRPZ(self):
        # Fresh RPZ does not need a notify
        self.waitForTCPSocket("127.0.0.1", self._wsPort)
        # first zone, only a should be blocked
        self.waitUntilCorrectSerialIsLoaded(1)
        self.checkRPZStats(1, 1, 1, self._xfrDone)
        self.checkBlocked('a.example.', soa='zone.rpz.')
        self.checkNotBlocked('b.example.')
        self.checkNotBlocked('c.example.')

        # second zone, a and b should be blocked
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(2)
        self.checkRPZStats(2, 2, 1, self._xfrDone)
        self.checkBlocked('a.example.', soa='zone.rpz.')
        self.checkBlocked('b.example.', soa='zone.rpz.')
        self.checkNotBlocked('c.example.')

        # third zone, only b should be blocked
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(3)
        self.checkRPZStats(3, 1, 1, self._xfrDone)
        self.checkNotBlocked('a.example.')
        self.checkBlocked('b.example.', soa='zone.rpz.')
        self.checkNotBlocked('c.example.')

        # fourth zone, only c should be blocked
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(4)
        self.checkRPZStats(4, 1, 1, self._xfrDone)
        self.checkNotBlocked('a.example.')
        self.checkNotBlocked('b.example.')
        self.checkBlocked('c.example.', soa='zone.rpz.')

        # fifth zone, we should get a full AXFR this time, and only d should be blocked
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(5)
        self.checkRPZStats(5, 3, 2, self._xfrDone)
        self.checkNotBlocked('a.example.')
        self.checkNotBlocked('b.example.')
        self.checkNotBlocked('c.example.')
        self.checkBlocked('d.example.', soa='zone.rpz.')

        # sixth zone, only e should be blocked, f is a local data record
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(6)
        self.checkRPZStats(6, 2, 2, self._xfrDone)
        self.checkNotBlocked('a.example.')
        self.checkNotBlocked('b.example.')
        self.checkNotBlocked('c.example.')
        self.checkNotBlocked('d.example.')
        self.checkCustom('e.example.', 'A', dns.rrset.from_text('e.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.1', '192.0.2.2'), soa='zone.rpz.')
        self.checkCustom('e.example.', 'MX', dns.rrset.from_text('e.example.', 0, dns.rdataclass.IN, 'MX', '10 mx.example.'))
        self.checkNoData('e.example.', 'AAAA', soa='zone.rpz.')
        self.checkCustom('f.example.', 'A', dns.rrset.from_text('f.example.', 0, dns.rdataclass.IN, 'CNAME', 'e.example.'), soa='zone.rpz.')

        # seventh zone, e should only have one A
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(7)
        self.checkRPZStats(7, 4, 2, self._xfrDone)
        self.checkNotBlocked('a.example.')
        self.checkNotBlocked('b.example.')
        self.checkNotBlocked('c.example.')
        self.checkNotBlocked('d.example.')
        self.checkCustom('e.example.', 'A', dns.rrset.from_text('e.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.2'), soa='zone.rpz.')
        self.checkCustom('e.example.', 'MX', dns.rrset.from_text('e.example.', 0, dns.rdataclass.IN, 'MX', '10 mx.example.'), soa='zone.rpz.')
        self.checkNoData('e.example.', 'AAAA', soa='zone.rpz.')
        self.checkCustom('f.example.', 'A', dns.rrset.from_text('f.example.', 0, dns.rdataclass.IN, 'CNAME', 'e.example.'), soa='zone.rpz.')
        # check that the policy is disabled for AD=1 queries
        self.checkNotBlocked('e.example.', True)
        # check non-custom policies
        self.checkTruncated('tc.example.', soa='zone.rpz.')
        self.checkDropped('drop.example.')

        # eighth zone, all entries should be gone
        self.sendNotify()
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

        # 9th zone is a duplicate, it might get skipped
        global rpzServer
        rpzServer.moveToSerial(9)
        self.sendNotify()
        time.sleep(3)
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(10)
        self.checkRPZStats(10, 1, 4, self._xfrDone)
        self.checkNotBlocked('a.example.')
        self.checkNotBlocked('b.example.')
        self.checkNotBlocked('c.example.')
        self.checkNotBlocked('d.example.')
        self.checkNotBlocked('e.example.')
        self.checkBlocked('f.example.', soa='zone.rpz.')
        self.checkNXD('tc.example.')
        self.checkNXD('drop.example.')

        # the next update will update the zone twice
        rpzServer.moveToSerial(11)
        self.sendNotify()
        time.sleep(3)
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(12)
        self.checkRPZStats(12, 1, 4, self._xfrDone)
        self.checkNotBlocked('a.example.')
        self.checkNotBlocked('b.example.')
        self.checkNotBlocked('c.example.')
        self.checkNotBlocked('d.example.')
        self.checkNotBlocked('e.example.')
        self.checkNXD('f.example.')
        self.checkBlocked('g.example.', soa='zone.rpz.')
        self.checkNXD('tc.example.')
        self.checkNXD('drop.example.')

class RPZFileRecursorTest(RPZRecursorTest):
    """
    This test makes sure that we correctly load RPZ zones from a file
    """

    _confdir = 'RPZFileRecursor'
    _lua_config_file = """
    rpzFile('configs/%s/zone.rpz', { policyName="zone.rpz.", includeSOA=true })
    """ % (_confdir)
    _config_template = """
auth-zones=example=configs/%s/example.zone
""" % (_confdir)

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
        self.checkBlocked('z.example.', soa='zone.rpz.')
        self.checkNotBlocked('b.example.')
        self.checkNotBlocked('c.example.')
        self.checkNotBlocked('d.example.')
        self.checkNotBlocked('e.example.')
        # check that the policy is disabled for AD=1 queries
        self.checkNotBlocked('z.example.', True)
        # check non-custom policies
        self.checkTruncated('tc.example.', soa='zone.rpz.')
        self.checkDropped('drop.example.')

class RPZFileDefaultPolRecursorTest(RPZRecursorTest):
    """
    This test makes sure that we correctly load RPZ zones from a file with a default policy
    """

    _confdir = 'RPZFileDefaultPolRecursor'
    _lua_config_file = """
    rpzFile('configs/%s/zone.rpz', { policyName="zone.rpz.", defpol=Policy.NoAction })
    """ % (_confdir)
    _config_template = """
auth-zones=example=configs/%s/example.zone
""" % (_confdir)

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

    _confdir = 'RPZFileDefaultPolNotOverrideLocalRecursor'
    _lua_config_file = """
    rpzFile('configs/%s/zone.rpz', { policyName="zone.rpz.", defpol=Policy.NoAction, defpolOverrideLocalData=false })
    """ % (_confdir)
    _config_template = """
auth-zones=example=configs/%s/example.zone
""" % (_confdir)

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
        # local data entries will not be overridden by the default policy
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

class RPZSimpleAuthServer(object):

    def __init__(self, port):
        self._serverPort = port
        listener = threading.Thread(name='RPZ Simple Auth Listener', target=self._listener, args=[])
        listener.daemon = True
        listener.start()

    def _getAnswer(self, message):

        response = dns.message.make_response(message)
        response.flags |= dns.flags.AA
        records = [
            dns.rrset.from_text('nsip.delegated.example.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.42')
        ]

        response.answer = records
        return response

    def _listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("127.0.0.1", self._serverPort))
        except socket.error as e:
            print("Error binding in the RPZ simple auth listener: %s" % str(e))
            sys.exit(1)

        while True:
            try:
                data, addr = sock.recvfrom(4096)
                message = dns.message.from_wire(data)
                if len(message.question) != 1:
                    print('Invalid query, qdcount is %d' % (len(message.question)))
                    break

                answer = self._getAnswer(message)
                if not answer:
                    print('Unable to get a response for %s %d' % (message.question[0].name, message.question[0].rdtype))
                    break

                wire = answer.to_wire()
                sock.sendto(wire, addr)

            except socket.error as e:
                print('Error in RPZ simple auth socket: %s' % str(e))

rpzAuthServerPort = 4260
rpzAuthServer = RPZSimpleAuthServer(rpzAuthServerPort)

class RPZOrderingPrecedenceRecursorTest(RPZRecursorTest):
    """
    This test makes sure that the recursor respects the RPZ ordering precedence rules
    """

    _confdir = 'RPZOrderingPrecedenceRecursor'
    _lua_config_file = """
    rpzFile('configs/%s/zone.rpz', { policyName="zone.rpz."})
    rpzFile('configs/%s/zone2.rpz', { policyName="zone2.rpz."})
    """ % (_confdir, _confdir)
    _config_template = """
auth-zones=example=configs/%s/example.zone
forward-zones=delegated.example=127.0.0.1:%d
""" % (_confdir, rpzAuthServerPort)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'example.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN example.
@ 3600 IN SOA {soa}
sub.test 3600 IN A 192.0.2.42
passthru-then-blocked-by-higher 3600 IN A 192.0.2.66
passthru-then-blocked-by-same 3600 IN A 192.0.2.66
blocked-then-passhtru-by-higher 3600 IN A 192.0.2.100
""".format(soa=cls._SOA))

        rpzFilePath = os.path.join(confdir, 'zone.rpz')
        with open(rpzFilePath, 'w') as rpzZone:
            rpzZone.write("""$ORIGIN zone.rpz.
@ 3600 IN SOA {soa}
*.test.example.zone.rpz. 60 IN CNAME rpz-passthru.
32.66.2.0.192.rpz-ip.zone.rpz. 60 IN A 192.0.2.1
32.100.2.0.192.rpz-ip.zone.rpz. 60 IN CNAME rpz-passthru.
passthru-then-blocked-by-same.example.zone.rpz. 60 IN CNAME rpz-passthru.
32.1.0.0.127.rpz-nsip.zone.rpz. 60 IN CNAME rpz-passthru.
""".format(soa=cls._SOA))

        rpzFilePath = os.path.join(confdir, 'zone2.rpz')
        with open(rpzFilePath, 'w') as rpzZone:
            rpzZone.write("""$ORIGIN zone2.rpz.
@ 3600 IN SOA {soa}
sub.test.example.com.zone2.rpz. 60 IN CNAME .
passthru-then-blocked-by-higher.example.zone2.rpz. 60 IN CNAME rpz-passthru.
blocked-then-passhtru-by-higher.example.zone2.rpz. 60 IN A 192.0.2.1
32.42.2.0.192.rpz-ip 60 IN CNAME .
""".format(soa=cls._SOA))

        super(RPZOrderingPrecedenceRecursorTest, cls).generateRecursorConfig(confdir)

    def testRPZOrderingForQNameAndWhitelisting(self):
        # we should first match on the qname (the wildcard, not on the exact name since
        # we respect the order of the RPZ zones), see the pass-thru rule
        # and only process RPZ rules of higher precedence.
        # The subsequent rule on the content of the A should therefore not trigger a NXDOMAIN.
        self.checkNotBlocked('sub.test.example.')

    def testRPZOrderingWhitelistedThenBlockedByHigher(self):
        # we should first match on the qname from the second RPZ zone,
        # continue the resolution process, and get blocked by the content of the A record
        # based on the first RPZ zone, whose priority is higher than the second one.
        self.checkBlocked('passthru-then-blocked-by-higher.example.')

    def testRPZOrderingWhitelistedThenBlockedBySame(self):
        # we should first match on the qname from the first RPZ zone,
        # continue the resolution process, and NOT get blocked by the content of the A record
        # based on the same RPZ zone, since it's not higher.
        self.checkCustom('passthru-then-blocked-by-same.example.', 'A', dns.rrset.from_text('passthru-then-blocked-by-same.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.66'))

    def testRPZOrderBlockedThenWhitelisted(self):
        # The qname is first blocked by the second RPZ zone
        # Then, should the resolution process go on, the A record would be whitelisted
        # by the first zone.
        # This is what the RPZ specification requires, but we currently decided that we
        # don't want to leak queries to malicious DNS servers and waste time if the qname is blacklisted.
        # We might change our opinion at some point, though.
        self.checkBlocked('blocked-then-passhtru-by-higher.example.')

    def testRPZOrderDelegate(self):
        # The IP of the NS we are going to contact is whitelisted (passthru) in zone 1,
        # so even though the record (192.0.2.42) returned by the server is blacklisted
        # by zone 2, it should not be blocked.
        # We only test once because after that the answer is cached, so the NS is not contacted
        # and the whitelist is not applied (yes, NSIP and NSDNAME are brittle).
        self.checkNotBlocked('nsip.delegated.example.', singleCheck=True)

class RPZNSIPCustomTest(RPZRecursorTest):
    """
    This test makes sure that the recursor handles custom RPZ rules in a NSIP
    """

    _confdir = 'RPZNSIPCustom'
    _lua_config_file = """
    rpzFile('configs/%s/zone.rpz', { policyName="zone.rpz."})
    rpzFile('configs/%s/zone2.rpz', { policyName="zone2.rpz."})
    """ % (_confdir, _confdir)
    _config_template = """
auth-zones=example=configs/%s/example.zone
forward-zones=delegated.example=127.0.0.1:%d
""" % (_confdir, rpzAuthServerPort)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'example.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN example.
@ 3600 IN SOA {soa}
""".format(soa=cls._SOA))

        rpzFilePath = os.path.join(confdir, 'zone.rpz')
        with open(rpzFilePath, 'w') as rpzZone:
            rpzZone.write("""$ORIGIN zone.rpz.
@ 3600 IN SOA {soa}
32.1.0.0.127.rpz-nsip.zone.rpz. 60 IN A 192.0.2.1
""".format(soa=cls._SOA))

        rpzFilePath = os.path.join(confdir, 'zone2.rpz')
        with open(rpzFilePath, 'w') as rpzZone:
            rpzZone.write("""$ORIGIN zone2.rpz.
@ 3600 IN SOA {soa}
32.1.2.0.192.rpz-ip 60 IN CNAME .
""".format(soa=cls._SOA))

        super(RPZNSIPCustomTest, cls).generateRecursorConfig(confdir)

    def testRPZDelegate(self):
        # The IP of the NS we are going to contact should result in a custom record (192.0.2.1) from zone 1,
        # so even though the record (192.0.2.1) returned by the server is blacklisted
        # by zone 2, it should not be blocked.
        # We only test once because after that the answer is cached, so the NS is not contacted
        # and the whitelist is not applied (yes, NSIP and NSDNAME are brittle).
        self.checkCustom('nsip.delegated.example.', 'A', dns.rrset.from_text('nsip.delegated.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.1'))


class RPZResponseIPCNameChainCustomTest(RPZRecursorTest):
    """
    This test makes sure that the recursor applies response IP rules to records in a CNAME chain,
    and resolves the target of a custom CNAME.
    """

    _confdir = 'RPZResponseIPCNameChainCustom'
    _lua_config_file = """
    rpzFile('configs/%s/zone.rpz', { policyName="zone.rpz."})
    """ % (_confdir)
    _config_template = """
auth-zones=example=configs/%s/example.zone
forward-zones=delegated.example=127.0.0.1:%d
""" % (_confdir, rpzAuthServerPort)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'example.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN example.
@ 3600 IN SOA {soa}
name IN CNAME cname
cname IN A 192.0.2.255
custom-target IN A 192.0.2.254
""".format(soa=cls._SOA))

        rpzFilePath = os.path.join(confdir, 'zone.rpz')
        with open(rpzFilePath, 'w') as rpzZone:
            rpzZone.write("""$ORIGIN zone.rpz.
@ 3600 IN SOA {soa}
cname.example IN CNAME custom-target.example.
custom-target.example IN A 192.0.2.253
""".format(soa=cls._SOA))

        super(RPZResponseIPCNameChainCustomTest, cls).generateRecursorConfig(confdir)

    def testRPZChain(self):
        # we request the A record for 'name.example.', which is a CNAME to 'cname.example'
        # this one does exist but we have a RPZ rule that should be triggered,
        # replacing the 'real' CNAME by a CNAME to 'custom-target.example.'
        # There is a RPZ rule for that name but it should not be triggered, since
        # the RPZ specs state "Recall that only one policy rule, from among all those matched at all
        # stages of resolving a CNAME or DNAME chain, can affect the final
        # response; this is true even if the selected rule has a PASSTHRU
        # action" in 5.1 "CNAME or DNAME Chain Position" Precedence Rule

        # two times to check the cache
        for _ in range(2):
            query = dns.message.make_query('name.example.', 'A', want_dnssec=True)
            query.flags |= dns.flags.CD
            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                res = sender(query)
                self.assertRcodeEqual(res, dns.rcode.NOERROR)
                self.assertRRsetInAnswer(res, dns.rrset.from_text('name.example.', 0, dns.rdataclass.IN, 'CNAME', 'cname.example.'))
                self.assertRRsetInAnswer(res, dns.rrset.from_text('cname.example.', 0, dns.rdataclass.IN, 'CNAME', 'custom-target.example.'))
                self.assertRRsetInAnswer(res, dns.rrset.from_text('custom-target.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.254'))


class RPZCNameChainCustomTest(RPZRecursorTest):
    """
    This test makes sure that the recursor applies QName rules to names in a CNAME chain.
    No forward or internal auth zones here, as we want to test the real resolution
    (with QName Minimization).
    """

    _PREFIX = os.environ['PREFIX']
    _confdir = 'RPZCNameChainCustom'
    _lua_config_file = """
    rpzFile('configs/%s/zone.rpz', { policyName="zone.rpz."})
    """ % (_confdir)
    _config_template = ""

    @classmethod
    def generateRecursorConfig(cls, confdir):
        rpzFilePath = os.path.join(confdir, 'zone.rpz')
        with open(rpzFilePath, 'w') as rpzZone:
            rpzZone.write("""$ORIGIN zone.rpz.
@ 3600 IN SOA {soa}
32.100.2.0.192.rpz-ip IN CNAME .
32.101.2.0.192.rpz-ip IN CNAME *.
32.102.2.0.192.rpz-ip IN A 192.0.2.103
""".format(soa=cls._SOA))

        super(RPZCNameChainCustomTest, cls).generateRecursorConfig(confdir)

    def testRPZChainNXD(self):
        # we should match the A at the end of the CNAME chain and
        # trigger a NXD

        # two times to check the cache
        for _ in range(2):
            query = dns.message.make_query('cname-nxd.example.', 'A', want_dnssec=True)
            query.flags |= dns.flags.CD
            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                res = sender(query)
                self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
                self.assertEqual(len(res.answer), 0)

    def testRPZChainNODATA(self):
        # we should match the A at the end of the CNAME chain and
        # trigger a NODATA

        # two times to check the cache
        for _ in range(2):
            query = dns.message.make_query('cname-nodata.example.', 'A', want_dnssec=True)
            query.flags |= dns.flags.CD
            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                res = sender(query)
                self.assertRcodeEqual(res, dns.rcode.NOERROR)
                self.assertEqual(len(res.answer), 0)

    def testRPZChainCustom(self):
        # we should match the A at the end of the CNAME chain and
        # get a custom A, replacing the existing one

        # two times to check the cache
        for _ in range(2):
            query = dns.message.make_query('cname-custom-a.example.', 'A', want_dnssec=True)
            query.flags |= dns.flags.CD
            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                res = sender(query)
                self.assertRcodeEqual(res, dns.rcode.NOERROR)
                # the original CNAME record is signed
                self.assertEqual(len(res.answer), 3)
                self.assertRRsetInAnswer(res, dns.rrset.from_text('cname-custom-a.example.', 0, dns.rdataclass.IN, 'CNAME', 'cname-custom-a-target.example.'))
                self.assertRRsetInAnswer(res, dns.rrset.from_text('cname-custom-a-target.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.103'))

class RPZFileModByLuaRecursorTest(RPZRecursorTest):
    """
    This test makes sure that we correctly load RPZ zones from a file while being modified by Lua callbacks
    """

    _confdir = 'RPZFileModByLuaRecursor'
    _lua_dns_script_file = """
    function preresolve(dq)
      if dq.qname:equal('zmod.example.') then
        dq.appliedPolicy.policyKind = pdns.policykinds.Drop
        return true
      end
      return false
    end
    function nxdomain(dq)
      if dq.qname:equal('nxmod.example.') then
        dq.appliedPolicy.policyKind = pdns.policykinds.Drop
        return true
      end
      return false
    end
    function nodata(dq)
      print("NODATA")
      if dq.qname:equal('nodatamod.example.') then
        dq.appliedPolicy.policyKind = pdns.policykinds.Drop
        return true
      end
      return false
    end
    """
    _lua_config_file = """
    rpzFile('configs/%s/zone.rpz', { policyName="zone.rpz." })
    """ % (_confdir)
    _config_template = """
auth-zones=example=configs/%s/example.zone
""" % (_confdir)

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
zmod.example.zone.rpz. 60 IN A 192.0.2.1
tc.example.zone.rpz. 60 IN CNAME rpz-tcp-only.
nxmod.example.zone.rpz. 60 in CNAME .
nodatamod.example.zone.rpz. 60 in CNAME *.
""".format(soa=cls._SOA))
        super(RPZFileModByLuaRecursorTest, cls).generateRecursorConfig(confdir)

    def testRPZ(self):
        self.checkCustom('a.example.', 'A', dns.rrset.from_text('a.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.42', '192.0.2.43'))
        self.checkCustom('a.example.', 'TXT', dns.rrset.from_text('a.example.', 0, dns.rdataclass.IN, 'TXT', '"some text"'))
        self.checkDropped('zmod.example.')
        self.checkDropped('nxmod.example.')
        self.checkDropped('nodatamod.example.')
        self.checkNotBlocked('b.example.')
        self.checkNotBlocked('c.example.')
        self.checkNotBlocked('d.example.')
        self.checkNotBlocked('e.example.')
        # check non-custom policies
        self.checkTruncated('tc.example.')
        self.checkDropped('drop.example.')
