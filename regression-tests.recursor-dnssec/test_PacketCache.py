import clientsubnetoption
import cookiesoption
import dns
import os
import requests
import subprocess

from recursortests import RecursorTest

class PacketCacheTest(RecursorTest):

    _auth_zones = {
        '8': {'threads': 1,
              'zones': ['ROOT']}
    }

    _confdir = 'PacketCache'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _config_template = """
    packetcache-ttl=10
    packetcache-negative-ttl=8
    packetcache-servfail-ttl=5
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
f 3600 IN CNAME f            ; CNAME loop: dirty trick to get a ServFail in an authzone
""".format(soa=cls._SOA))
        super(PacketCacheTest, cls).generateRecursorConfig(confdir)

    def checkPacketCacheMetrics(self, expectedHits, expectedMisses):
        self.waitForTCPSocket("127.0.0.1", self._wsPort)
        headers = {'x-api-key': self._apiKey}
        url = 'http://127.0.0.1:' + str(self._wsPort) + '/api/v1/servers/localhost/statistics'
        r = requests.get(url, headers=headers, timeout=self._wsTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        foundHits = False
        foundMisses = True
        for entry in content:
            if entry['name'] == 'packetcache-hits':
                foundHits = True
                self.assertEqual(int(entry['value']), expectedHits)
            elif entry['name'] == 'packetcache-misses':
                foundMisses = True
                self.assertEqual(int(entry['value']), expectedMisses)

        self.assertTrue(foundHits)
        self.assertTrue(foundMisses)

    def testPacketCache(self):
        self.waitForTCPSocket("127.0.0.1", self._wsPort)
        # first query, no cookie
        qname = 'a.example.'
        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.42')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

        self.checkPacketCacheMetrics(0, 2)

        # we should get a hit over UDP this time
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkPacketCacheMetrics(1, 2)

        # we should get a hit over TCP this time
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkPacketCacheMetrics(2, 2)

        eco1 = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        eco2 = cookiesoption.CookiesOption(b'deadc0de', b'deadc0de')
        ecso1 = clientsubnetoption.ClientSubnetOption('192.0.2.1', 32)
        ecso2 = clientsubnetoption.ClientSubnetOption('192.0.2.2', 32)

        # we add a cookie, should not match anymore
        query = dns.message.make_query(qname, 'A', want_dnssec=True, options=[eco1])
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkPacketCacheMetrics(2, 3)

        # same cookie, should match
        query = dns.message.make_query(qname, 'A', want_dnssec=True, options=[eco1])
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkPacketCacheMetrics(3, 3)

        # different cookie, should still match
        query = dns.message.make_query(qname, 'A', want_dnssec=True, options=[eco2])
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkPacketCacheMetrics(4, 3)

        # first cookie but with an ECS option, should not match
        query = dns.message.make_query(qname, 'A', want_dnssec=True, options=[eco1, ecso1])
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkPacketCacheMetrics(4, 4)

        # different cookie but same ECS option, should match
        query = dns.message.make_query(qname, 'A', want_dnssec=True, options=[eco2, ecso1])
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkPacketCacheMetrics(5, 4)

        # first cookie but different ECS option, should still match (we ignore EDNS Client Subnet
        # in the recursor's packet cache, but ECS-specific responses are not cached
        query = dns.message.make_query(qname, 'A', want_dnssec=True, options=[eco1, ecso2])
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkPacketCacheMetrics(6, 4)

        # NXDomain should get negative packetcache TTL (8)
        query = dns.message.make_query('nxdomain.example.', 'A', want_dnssec=True)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.checkPacketCacheMetrics(6, 5)

        # NoData should get negative packetcache TTL (8)
        query = dns.message.make_query('a.example.', 'AAAA', want_dnssec=True)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.checkPacketCacheMetrics(6, 6)

        # ServFail should get ServFail TTL (5)
        query = dns.message.make_query('f.example.', 'A', want_dnssec=True)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.checkPacketCacheMetrics(6, 7)

        # We peek into the cache to check TTLs and allow TTLs to be one lower than inserted since the clock might have ticked
        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % 'configs/' + self._confdir,
                          'dump-cache', '-']
        try:
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
            self.assertTrue((b"a.example. 10 A  ; tag 0 udp\n" in ret) or (b"a.example. 9 A  ; tag 0 udp\n" in ret))
            self.assertTrue((b"nxdomain.example. 8 A  ; tag 0 udp\n" in ret) or (b"nxdomain.example. 7 A  ; tag 0 udp\n" in ret))
            self.assertTrue((b"a.example. 8 AAAA  ; tag 0 udp\n" in ret) or (b"a.example. 7 AAAA  ; tag 0 udp\n" in ret))
            self.assertTrue((b"f.example. 5 A  ; tag 0 udp\n" in ret) or (b"f.example. 4 A  ; tag 0 udp\n" in ret))

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

