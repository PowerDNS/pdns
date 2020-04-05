import dns
import os
import subprocess
import time

from authtests import AuthTest
from xfrserver.xfrserver import AXFRServer

zones = {
    1: ["""
$ORIGIN example.""","""
@        86400   SOA    foo bar 1 2 3 4 5
@        4242    NS     ns1.example.
@        4242    NS     ns2.example.
ns1.example.    4242    A       192.0.2.1
ns2.example.    4242    A       192.0.2.2
"""],
    2: ["""
$ORIGIN example.""","""
@        86400   SOA    foo bar 2 2 3 4 5
@        4242    NS     ns1.example.
@        4242    NS     ns2.example.
ns1.example.    4242    A       192.0.2.1
ns2.example.    4242    A       192.0.2.2
newrecord.example.        8484    A       192.0.2.42
"""],
    3: ["""
$ORIGIN example.""","""
@        86400   SOA    foo bar 3 2 3 4 5""","""
@        86400   SOA    foo bar 2 2 3 4 5""","""
@        86400   SOA    foo bar 3 2 3 4 5""","""
@        4242    NS     ns3.example.
"""],
    5: ["""
$ORIGIN example.""","""
@        86400   SOA    foo bar 5 2 3 4 5""","""
@        86400   SOA    foo bar 3 2 3 4 5""","""
@        86400   SOA    foo bar 4 2 3 4 5""","""
@        86400   SOA    foo bar 4 2 3 4 5""","""
@        86400   SOA    foo bar 5 2 3 4 5""","""
@        4242    NS     ns5.example.
"""],
    8: ["""
$ORIGIN example.""","""
@        86400   SOA    foo bar 8 2 3 4 5""","""
@        86400   SOA    foo bar 5 2 3 4 5""","""
@        86400   SOA    foo bar 6 2 3 4 5""","""
@        86400   SOA    foo bar 6 2 3 4 5""","""
@        86400   SOA    foo bar 7 2 3 4 5""","""
@        86400   SOA    foo bar 7 2 3 4 5""","""
@        86400   SOA    foo bar 8 2 3 4 5""","""
"""]


}


xfrServerPort = 4244
xfrServer = AXFRServer(xfrServerPort, zones)

class TestIXFR(AuthTest):
    _config_template = """
launch=gsqlite3 bind
gsqlite3-database=configs/auth/powerdns.sqlite
gsqlite3-dnssec
slave
slave-cycle-interval=1
query-cache-ttl=20
negquery-cache-ttl=60
"""

    _zones = {}
    global xfrServerPort
    _xfrDone = 0

    @classmethod
    def setUpClass(cls):
        super(TestIXFR, cls).setUpClass()
        os.system("$PDNSUTIL --config-dir=configs/auth create-slave-zone example. 127.0.0.1:%s" % (xfrServerPort,))
        os.system("$PDNSUTIL --config-dir=configs/auth set-meta example. IXFR 1")

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
                time.sleep(1)
                return

            attempts = attempts + 1
            time.sleep(1)

        raise AssertionError("Waited %d seconds for the serial to be updated to %d but the last served serial is still %d" % (timeout, serial, servedSerial))

    def checkFullZone(self, serial, data=None):
        global zones

        # FIXME: 90% duplication from _getRecordsForSerial
        zone = []
        if not data:
            data = zones[serial]
        for i in dns.zone.from_text('\n'.join(data), relativize=False).iterate_rdatasets():
            n, rds = i
            rrs=dns.rrset.RRset(n, rds.rdclass, rds.rdtype)
            rrs.update(rds)
            zone.append(rrs)

        expected =[[zone[0]], sorted(zone[1:], key=lambda rrset: (rrset.name, rrset.rdtype)), [zone[0]]] # AXFRs are SOA-wrapped

        query = dns.message.make_query('example.', 'AXFR')
        res = self.sendTCPQueryMultiResponse(query, count=len(expected))
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
        res = self.sendTCPQueryMultiResponse(query, count=len(expected))
        answers = [r.answer for r in res]

        # answers[1].sort(key=lambda rrset: (rrset.name, rrset.rdtype))
        self.assertEqual(answers, expected)
        # check the TTLs
        answerPos = 0
        for expectedAnswer in expected:
            pos = 0
            for rec in expectedAnswer:
                self.assertEquals(rec.ttl, answers[answerPos][pos].ttl)
                pos = pos + 1
            answerPos = answerPos + 1

    def test_a_XFR(self):
        print("x1")
        self.waitUntilCorrectSerialIsLoaded(1)
        print("x2")
        self.checkFullZone(1)
        print("x3")

        self.waitUntilCorrectSerialIsLoaded(2)
        print("x4")
        self.checkFullZone(2)
        print("x5")

        self.waitUntilCorrectSerialIsLoaded(3)
        print("x7")
        self.checkFullZone(3, data=["""
$ORIGIN example.""","""
@        86400   SOA    foo bar 3 2 3 4 5
@        4242    NS     ns1.example.
@        4242    NS     ns2.example.
@        4242    NS     ns3.example.
ns1.example.    4242    A       192.0.2.1
ns2.example.    4242    A       192.0.2.2
newrecord.example.        8484    A       192.0.2.42
"""])
        print("x8")

        self.waitUntilCorrectSerialIsLoaded(5)
        print("x7")
        self.checkFullZone(5, data=["""
$ORIGIN example.""","""
@        86400   SOA    foo bar 5 2 3 4 5
@        4242    NS     ns1.example.
@        4242    NS     ns2.example.
@        4242    NS     ns3.example.
@        4242    NS     ns5.example.
ns1.example.    4242    A       192.0.2.1
ns2.example.    4242    A       192.0.2.2
newrecord.example.        8484    A       192.0.2.42
"""])
        print("x8")


    # _b_ because we expect post-XFR testing state
    def test_b_UDP_SOA_existing(self):
        query = dns.message.make_query('example.', 'SOA')
        expected = dns.message.make_response(query)
        expected.answer.append(xfrServer._getSOAForSerial(5))
        expected.flags |= dns.flags.AA

        response = self.sendUDPQuery(query)

        self.assertEquals(expected, response)
        # check the TTLs
        pos = 0
        for rec in expected.answer:
            self.assertEquals(rec.ttl, response.answer[pos].ttl)
            pos = pos + 1

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

    def test_d_XFR(self):
        self.waitUntilCorrectSerialIsLoaded(8)
        print("x7")
        self.checkFullZone(7, data=["""
$ORIGIN example.""","""
@        86400   SOA    foo bar 8 2 3 4 5
@        4242    NS     ns1.example.
@        4242    NS     ns2.example.
@        4242    NS     ns3.example.
@        4242    NS     ns5.example.
ns1.example.    4242    A       192.0.2.1
ns2.example.    4242    A       192.0.2.2
newrecord.example.        8484    A       192.0.2.42
"""])
        print("x8")
        ret = subprocess.check_output([os.environ['PDNSUTIL'],
                           '--config-dir=configs/auth',
                           'list-zone', 'example'], stderr=subprocess.STDOUT)
        rets = ret.split('\n')

        self.assertEqual(1, sum('SOA' in l for l in ret.split('\n')))