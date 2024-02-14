import dns
import dns.serial
import time
import itertools
import socket

from ixfrdisttests import IXFRDistTest
from xfrserver.xfrserver import AXFRServer

zones = {
    1: """
$ORIGIN example.
@        86400   SOA    foo bar 1 2 3 4 5
@        4242    NS     ns1.example.
@        4242    NS     ns2.example.
ns1.example.    4242    A       192.0.2.1
ns2.example.    4242    A       192.0.2.2
""",
    2: """
$ORIGIN example.
@        86400   SOA    foo bar 2 2 3 4 5
@        4242    NS     ns1.example.
@        4242    NS     ns2.example.
ns1.example.    4242    A       192.0.2.1
ns2.example.    4242    A       192.0.2.2
newrecord.example.        8484    A       192.0.2.42
""",
    3: """
$ORIGIN example.
@        86400   SOA    foo bar 3 1500 3 4 5
@        4242    NS     ns1.example.
@        4242    NS     ns2.example.
ns1.example.    4242    A       192.0.2.1
ns2.example.    4242    A       192.0.2.2
newrecord2.example.        8484    A       192.0.2.42
""",
    4: """
$ORIGIN example.
@        86400   SOA    foo bar 4 2 3 4 5
@        4242    NS     ns1.example.
@        4242    NS     ns2.example.
ns1.example.    4242    A       192.0.2.1
ns2.example.    4242    A       192.0.2.2
newrecord2.example.        8484    A       192.0.2.42
other.example.  1234    TXT     "foo"
"""
}


xfrServerPort = 4244
xfrServer = AXFRServer(xfrServerPort, zones)

class IXFRDistBasicTest(IXFRDistTest):
    """
    This test makes sure that we correctly fetch a zone via AXFR, and provide the full AXFR and IXFR
    """

    global xfrServerPort
    _xfrDone = 0
    _config_domains = [
        # zone for actual XFR testing
        {"domain" : "example", "master" : "127.0.0.1:" + str(xfrServerPort), 'notify' : "127.0.0.1:" + str(xfrServerPort + 1)},
        # bogus port is intentional - zone is intentionally unloadable
        {"domain" : "example2", "master" : "127.0.0.1:1"},
        # for testing how ixfrdist deals with getting the wrong zone on XFR
        {"domain" : "example4", "master" : '127.0.0.1:' + str(xfrServerPort)},

    ]
    _loaded_serials = []

    @classmethod
    def setUpClass(cls):

        cls.startIXFRDist()
        cls.setUpSockets()

    @classmethod
    def tearDownClass(cls):
        cls.tearDownIXFRDist()

    def waitUntilCorrectSerialIsLoaded(self, serial, timeout=10, notify=False):
        global xfrServer

        xfrServer.moveToSerial(serial)

        if notify:
            notif = dns.message.make_query('example.', 'SOA')
            notif.set_opcode(dns.opcode.NOTIFY)
            notify_response = self.sendUDPQuery(notif)
            assert notify_response.rcode() == dns.rcode.NOERROR

        def get_current_serial():
            query = dns.message.make_query('example.', 'SOA')
            response_message = self.sendUDPQuery(query)

            if response_message.rcode() == dns.rcode.REFUSED:
                return 0

            soa_rrset = response_message.find_rrset(dns.message.ANSWER, dns.name.from_text("example."), dns.rdataclass.IN, dns.rdatatype.SOA)
            return soa_rrset[0].serial

        attempts = 0
        while attempts < timeout:
            print('attempts=%s timeout=%s' % (attempts, timeout))
            servedSerial = get_current_serial()
            print('servedSerial=%s' % servedSerial)
            if servedSerial > serial:
                raise AssertionError("Expected serial %d, got %d" % (serial, servedSerial))
            if servedSerial == serial:
                self._xfrDone = self._xfrDone + 1
                self._loaded_serials.append(serial)
                return

            attempts = attempts + 1
            time.sleep(1)

        raise AssertionError("Waited %d seconds for the serial to be updated to %d but the last served serial is still %d" % (timeout, serial, servedSerial))

    def checkFullZone(self, serial):
        global zones

        # FIXME: 90% duplication from _getRecordsForSerial
        zone = []
        for i in dns.zone.from_text(zones[serial], relativize=False).iterate_rdatasets():
            n, rds = i
            rrs=dns.rrset.RRset(n, rds.rdclass, rds.rdtype)
            rrs.update(rds)
            zone.append(rrs)

        expected =[[zone[0]], sorted(zone[1:], key=lambda rrset: (rrset.name, rrset.rdtype)), [zone[0]]] # AXFRs are SOA-wrapped

        query = dns.message.make_query('example.', 'AXFR')
        res = self.sendTCPQueryMultiResponse(query, count=len(expected)+1) # +1 for trailing data check
        answers = [r.answer for r in res]
        answers[1].sort(key=lambda rrset: (rrset.name, rrset.rdtype))
        self.assertEqual(answers, expected)

    def checkIXFR(self, fromserial, toserial):
        global zones, xfrServer

        soa_requested = xfrServer._getSOAForSerial(fromserial)
        soa_latest = xfrServer._getSOAForSerial(self._loaded_serials[-1])

        self.assertEqual(soa_latest[0].serial, toserial)

        query = dns.message.make_query('example.', 'IXFR')
        query.authority = [soa_requested]

        expected = []
        expected.append([soa_latest]) #latest SOA

        def pairwise(iterable): # itertools.pairwise exists in 3.10, but until then...
            # pairwise('ABCDEFG') --> AB BC CD DE EF FG
            a, b = itertools.tee(iterable)
            next(b, None)
            return zip(a, b)

        found_starting_version = False
        for serial_pair in pairwise(self._loaded_serials):
            if dns.serial.Serial(serial_pair[0]) < dns.serial.Serial(fromserial):
                continue

            if serial_pair[0] == fromserial:
                found_starting_version = True

            old_records = [r for r in xfrServer._getRecordsForSerial(serial_pair[0]) if r.rdtype != dns.rdatatype.SOA]
            new_records = [r for r in xfrServer._getRecordsForSerial(serial_pair[1]) if r.rdtype != dns.rdatatype.SOA]
            added = [r for r in new_records if r not in old_records]
            removed = [r for r in old_records if r not in new_records]

            expected.append([xfrServer._getSOAForSerial(serial_pair[0])]) # old SOA
            if removed: expected.append(removed) # removed records from old SOA (sendTCPQueryMultiResponse skips if empty)
            expected.append([xfrServer._getSOAForSerial(serial_pair[1])]) # new SOA
            if added: expected.append(added) # added records in new SOA (sendTCPQueryMultiResponse skips if empty)

        expected.append([soa_latest]) # latest SOA

        if not found_starting_version:
            raise AssertionError("Did not find zone version with requested serial {fromserial}, impossible to IXFR scenario?")

        res = self.sendTCPQueryMultiResponse(query, count=len(expected)+1) # +1 for trailing data check
        answers = [r.answer for r in res]

        # answers[1].sort(key=lambda rrset: (rrset.name, rrset.rdtype))
        self.assertEqual(answers, expected)
        # check the TTLs
        answerPos = 0
        for expectedAnswer in expected:
            pos = 0
            for rec in expectedAnswer:
                self.assertEqual(rec.ttl, answers[answerPos][pos].ttl)
                pos = pos + 1
            answerPos = answerPos + 1


    def test_a_XFR(self):
        self.waitUntilCorrectSerialIsLoaded(1)
        self.checkFullZone(1)

        self.waitUntilCorrectSerialIsLoaded(2)
        self.checkFullZone(2)

        self.checkIXFR(1,2)

    # _b_ because we expect post-XFR testing state
    def test_b_UDP_SOA_existing(self):
        query = dns.message.make_query('example.', 'SOA')
        expected = dns.message.make_response(query)
        expected.flags |= dns.flags.AA
        expected.answer.append(xfrServer._getSOAForSerial(2))

        response = self.sendUDPQuery(query)
        self.assertEqual(expected, response)
        # check the TTLs
        pos = 0
        for rec in expected.answer:
            self.assertEqual(rec.ttl, response.answer[pos].ttl)
            pos = pos + 1

    def test_b_UDP_SOA_not_loaded(self):
        query = dns.message.make_query('example2.', 'SOA')
        expected = dns.message.make_response(query)
        expected.set_rcode(dns.rcode.REFUSED)

        response = self.sendUDPQuery(query)
        self.assertEqual(expected, response)

    def test_b_UDP_SOA_not_configured(self):
        query = dns.message.make_query('example3.', 'SOA')
        expected = dns.message.make_response(query)
        expected.set_rcode(dns.rcode.REFUSED)

        response = self.sendUDPQuery(query)
        self.assertEqual(expected, response)

    def test_c_IXFR_multi(self):
        self.waitUntilCorrectSerialIsLoaded(3)
        self.checkFullZone(3)
        self.checkIXFR(2,3)
        self.checkIXFR(1,3)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", xfrServerPort + 1))
        sock.settimeout(2)

        self.waitUntilCorrectSerialIsLoaded(serial=4, timeout=10, notify=True)

        # recv the forwarded NOTIFY
        data, addr = sock.recvfrom(4096)
        received = dns.message.from_wire(data)
        sock.close()

        notif = dns.message.make_query('example.', 'SOA')
        notif.set_opcode(dns.opcode.NOTIFY)
        notif.flags |= dns.flags.AA
        notif.flags &= ~dns.flags.RD
        notif.id = received.id

        self.assertEqual(received, notif)

        self.checkFullZone(4)
        self.checkIXFR(3,4)
        self.checkIXFR(2,4)
        self.checkIXFR(1,4)
