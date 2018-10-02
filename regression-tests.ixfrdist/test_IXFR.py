import dns
import time

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
    _config_domains = { 'example': '127.0.0.1:' + str(xfrServerPort),
                        'example2': '127.0.0.1:1',       # bogus port is intentional
                        'example4': '127.0.0.1:' + str(xfrServerPort) }

    @classmethod
    def setUpClass(cls):

        cls.startIXFRDist()
        cls.setUpSockets()

    @classmethod
    def tearDownClass(cls):
        cls.tearDownIXFRDist()

    def waitUntilCorrectSerialIsLoaded(self, serial, timeout=10):
        global xfrServer

        xfrServer.moveToSerial(serial)

        attempts = 0
        while attempts < timeout:
            print('attempts=%s timeout=%s' % (attempts, timeout))
            servedSerial = xfrServer.getServedSerial()
            print('servedSerial=%s' % servedSerial)
            if servedSerial > serial:
                raise AssertionError("Expected serial %d, got %d" % (serial, servedSerial))
            if servedSerial == serial:
                self._xfrDone = self._xfrDone + 1
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

        ixfr = []
        soa1 = xfrServer._getSOAForSerial(fromserial)
        soa2 = xfrServer._getSOAForSerial(toserial)
        newrecord = [r for r in xfrServer._getRecordsForSerial(toserial) if r.name==dns.name.from_text('newrecord.example.')]
        query = dns.message.make_query('example.', 'IXFR')
        query.authority = [soa1]

        expected = [[soa2], [soa1], [soa2], newrecord, [soa2]]
        res = self.sendTCPQueryMultiResponse(query, count=len(expected)+1) # +1 for trailing data check
        answers = [r.answer for r in res]

        # answers[1].sort(key=lambda rrset: (rrset.name, rrset.rdtype))
        self.assertEqual(answers, expected)

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
        expected.answer.append(xfrServer._getSOAForSerial(2))

        response = self.sendUDPQuery(query)
        self.assertEquals(expected, response)

    def test_b_UDP_SOA_not_loaded(self):
        query = dns.message.make_query('example2.', 'SOA')
        expected = dns.message.make_response(query)
        expected.set_rcode(dns.rcode.REFUSED)

        response = self.sendUDPQuery(query)
        self.assertEquals(expected, response)

    def test_b_UDP_SOA_not_configured(self):
        query = dns.message.make_query('example3.', 'SOA')
        expected = dns.message.make_response(query)
        expected.set_rcode(dns.rcode.REFUSED)

        response = self.sendUDPQuery(query)
        self.assertEquals(expected, response)
