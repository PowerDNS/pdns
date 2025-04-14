import dns
import json
import os
import requests
import socket
import struct
import sys
import threading
import time
import yaml

from recursortests import RecursorTest

class FWCatzServer(object):

    def __init__(self, port):
        self._currentSerial = 0
        self._targetSerial = 1
        self._serverPort = port
        listener = threading.Thread(name='FWCatz Listener', target=self._listener, args=[])
        listener.daemon = True
        listener.start()

    def getCurrentSerial(self):
        return self._currentSerial

    def moveToSerial(self, newSerial):
        if newSerial == self._currentSerial:
            return False

        if newSerial != self._currentSerial + 1:
            raise AssertionError("Asking the FWCatz server to serve serial %d, already serving %d" % (newSerial, self._currentSerial))
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
                dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                dns.rrset.from_text('version.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.TXT, '2'),
                dns.rrset.from_text('a.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'a.'),
                dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial)
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
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % oldSerial),
                    # no deletion
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('b.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'b.'),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 3:
                records = [
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % oldSerial),
                    dns.rrset.from_text('a.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'a.'),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    # no addition
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 4:
                records = [
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % oldSerial),
                    dns.rrset.from_text('b.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'b.'),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('c.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'c.'),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 5:
                # this one is a bit special, we are answering with a full AXFR
                records = [
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('version.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.TXT, '2'),
                    dns.rrset.from_text('d.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'd.'),
                    dns.rrset.from_text('e.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'e.'),
                    dns.rrset.from_text('f.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'f.'),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 6:
                # back to IXFR
                records = [
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % oldSerial),
                    dns.rrset.from_text('d.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'd.'),
                    dns.rrset.from_text('e.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'e.'),
                    dns.rrset.from_text('f.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'f.'),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('e.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'ee.'),
                    dns.rrset.from_text('group.e.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.TXT, 'GROUP'),
                    dns.rrset.from_text('f.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'ff.'),
                    dns.rrset.from_text('g.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'gg.'),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 7:
                records = [
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % oldSerial),
                    dns.rrset.from_text('e.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'ee.'),
                    dns.rrset.from_text('group.e.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.TXT, 'GROUP'),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('e.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'e.'),
                    dns.rrset.from_text('f.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'f.'),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 8:
                # this one is a bit special too, we are answering with a full AXFR and the new zone is empty
                records = [
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('version.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.TXT, '2'),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 9:
                # IXFR inserting a duplicate, we should not crash and skip it
                records = [
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % oldSerial),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('version.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.TXT, '2'),
                    dns.rrset.from_text('dup1.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'dup.'),
                    dns.rrset.from_text('dup2.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'dup.'),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 10:
                # full AXFR to make sure we are removing the duplicate, adding a record, to check that the update was correctly applied
                records = [
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('version.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.TXT, '2'),
                    dns.rrset.from_text('f.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'f.'),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial)
                    ]
            elif newSerial == 11:
                # IXFR with two deltas, the first one adding a 'g' and the second one removing 'f'
                records = [
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % (newSerial + 1)),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % oldSerial),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('g.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'g.'),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % newSerial),
                    dns.rrset.from_text('f.zones.forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.PTR, 'f.'),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % (newSerial + 1)),
                    dns.rrset.from_text('forward.catz.', 60, dns.rdataclass.IN, dns.rdatatype.SOA, 'ns.forward.catz. hostmaster.forward.catz. %d 3600 3600 3600 1' % (newSerial + 1)),
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
                print('Invalid FWCatz query, qdcount is %d' % (len(message.question)))
                break
            if not message.question[0].rdtype in [dns.rdatatype.AXFR, dns.rdatatype.IXFR]:
                print('Invalid FWCatz query, qtype is %d' % (message.question.rdtype))
                break
            (serial, answer) = self._getAnswer(message)
            if not answer:
                print('Unable to get a response for %s %d' % (message.question[0].name, message.question[0].rdtype))
                break

            wire = answer.to_wire()
            lenprefix = struct.pack("!H", len(wire))

            for b in lenprefix:
                conn.send(bytes([b]))
                time.sleep(0.5)

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
            print("Error binding in the FWCatz listener: %s" % str(e))
            sys.exit(1)

        sock.listen(100)
        while True:
            try:
                (conn, _) = sock.accept()
                thread = threading.Thread(name='FWCatz Connection Handler',
                                      target=self._connectionHandler,
                                      args=[conn])
                thread.daemon = True
                thread.start()

            except socket.error as e:
                print('Error in FWCatz socket: %s' % str(e))
                sock.close()

fwCatzServerPort = 4252
fwCatzServer = FWCatzServer(fwCatzServerPort)

class FWCatzXFRRecursorTest(RecursorTest):
    """
    This test makes sure that we correctly update FW cat zones via AXFR then IXFR
    """

    global fwCatzServerPort
    _confdir = 'FWCatzXFRRecursor'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _config_template = """
logging:
  loglevel: 7
webservice:
  webserver: true
  port: %d
  address: 127.0.0.1
  password: %s
  api_key: %s
  api_dir: configs/%s
packetcache:
  disable: true
incoming:
  allow_notify_from: [127.0.0.0/8]
recursor:
  system_resolver_ttl: 30
  forwarding_catalog_zones:
  - zone: forward.catz
    xfr:
      # The first server is a bogus one, to test that we correctly fail over to the second one
      addresses: [127.0.0.1:9999, localhost:%d]
      refresh: 1
    notify_allowed: true
    groups:
    -  forwarders: [1.2.3.4] # Default
    -  name: 'GROUP'
       forwarders: [4.5.6.7]
       notify_allowed: true
       recurse: true
""" % (_wsPort, _wsPassword, _apiKey, _confdir, fwCatzServerPort)

    _xfrDone = 0

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(FWCatzXFRRecursorTest, cls).generateRecursorYamlConfig(confdir, False)

    def sendNotify(self):
        notify = dns.message.make_query('forward.catz', 'SOA', want_dnssec=False)
        notify.set_opcode(4) # notify
        res = self.sendUDPQuery(notify)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(res.opcode(), 4)
        self.assertEqual(res.question[0].to_text(), 'forward.catz. IN SOA')

    def checkForwards(self, expected):
        attempts = 0
        tries = 10
        ex = None
        while attempts < tries:
            try:
                with open('configs/' + self._confdir + '/catzone.forward.catz.') as file:
                    reality = yaml.safe_load(file);
                    if expected == reality:
                        return
            except Exception as e:
                ex = e
            attempts = attempts + 1
            time.sleep(0.1)
        if ex is not None:
            raise ex
        raise AssertionError('expected content not found')

    def waitUntilCorrectSerialIsLoaded(self, serial, timeout=5):
        global fwCatzServer

        fwCatzServer.moveToSerial(serial)

        attempts = 0
        while attempts < timeout:
            currentSerial = fwCatzServer.getCurrentSerial()
            if currentSerial > serial:
                raise AssertionError("Expected serial %d, got %d" % (serial, currentSerial))
            if currentSerial == serial:
                self._xfrDone = self._xfrDone + 1
                return

            attempts = attempts + 1
            time.sleep(1)

        raise AssertionError("Waited %d seconds for the serial to be updated to %d but the serial is still %d" % (timeout, serial, currentSerial))

    def testFWCatz(self):
        # Fresh catz does not need a notify
        self.waitForTCPSocket("127.0.0.1", self._wsPort)
        # first zone
        self.waitUntilCorrectSerialIsLoaded(1)
        self.checkForwards({'forward_zones': [
            {'zone': 'a.', 'forwarders': ['1.2.3.4']}
        ]})

        # second zone
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(2)
        self.checkForwards({'forward_zones': [
            {'zone': 'a.', 'forwarders': ['1.2.3.4']},
            {'zone': 'b.', 'forwarders': ['1.2.3.4']}
        ]})

        # third zone
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(3)
        self.checkForwards({'forward_zones': [
            {'zone': 'b.', 'forwarders': ['1.2.3.4']}
        ]})

        # fourth zone
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(4)
        self.checkForwards({'forward_zones': [
            {'zone': 'c.', 'forwarders': ['1.2.3.4']}
        ]})

        # fifth zone, we should get a full AXFR this time
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(5)
        self.checkForwards({'forward_zones': [
            {'zone': 'd.', 'forwarders': ['1.2.3.4']},
            {'zone': 'e.', 'forwarders': ['1.2.3.4']},
            {'zone': 'f.', 'forwarders': ['1.2.3.4']}
        ]})

        # sixth zone
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(6)
        self.checkForwards({'forward_zones': [
            {'zone': 'ee.', 'forwarders': ['4.5.6.7'], 'notify_allowed': True, 'recurse': True},
            {'zone': 'ff.', 'forwarders': ['1.2.3.4']},
            {'zone': 'gg.', 'forwarders': ['1.2.3.4']}
        ]})

        # seventh zone
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(7)
        self.checkForwards({'forward_zones': [
            {'zone': 'e.', 'forwarders': ['1.2.3.4']},
            {'zone': 'ff.', 'forwarders': ['1.2.3.4']},
            {'zone': 'f.', 'forwarders': ['1.2.3.4']},
            {'zone': 'gg.', 'forwarders': ['1.2.3.4']}
        ]})

        # eighth zone, all entries should be gone
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(8)
        self.checkForwards({})

        # 9th zone has a duplicate, it gets skipped
        global fwCatzServer
        fwCatzServer.moveToSerial(9)
        self.sendNotify()
        time.sleep(3)
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(10)

        # the next update will update the zone twice
        fwCatzServer.moveToSerial(11)
        self.sendNotify()
        time.sleep(3)
        self.sendNotify()
        self.waitUntilCorrectSerialIsLoaded(12)
        self.checkForwards({'forward_zones': [
            {'zone': 'g.', 'forwarders': ['1.2.3.4']}
        ]})


