import dns
import os
from recursortests import RecursorTest

class testSimpleTCP(RecursorTest):
    _confdir = 'SimpleTCP'

    _config_template = """dnssec=validate
auth-zones=authzone.example=configs/%s/authzone.zone""" % _confdir

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'authzone.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN authzone.example.
@ 3600 IN SOA {soa}
@ 3600 IN A 192.0.2.88
""".format(soa=cls._SOA))
        super(testSimpleTCP, cls).generateRecursorConfig(confdir)

    def testSOAs(self):
        for zone in ['.', 'example.', 'secure.example.']:
            expected = dns.rrset.from_text(zone, 0, dns.rdataclass.IN, 'SOA', self._SOA)
            query = dns.message.make_query(zone, 'SOA', want_dnssec=True)
            query.flags |= dns.flags.AD

            res = self.sendTCPQuery(query)

            self.assertMessageIsAuthenticated(res)
            self.assertRRsetInAnswer(res, expected)
            self.assertMatchingRRSIGInAnswer(res, expected)

    def testA(self):
        expected = dns.rrset.from_text('ns.secure.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.9'.format(prefix=self._PREFIX))
        query = dns.message.make_query('ns.secure.example', 'A', want_dnssec=True)
        query.flags |= dns.flags.AD

        res = self.sendTCPQuery(query)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testDelegation(self):
        query = dns.message.make_query('example', 'NS', want_dnssec=True)
        query.flags |= dns.flags.AD

        expectedNS = dns.rrset.from_text('example.', 0, 'IN', 'NS', 'ns1.example.', 'ns2.example.')

        res = self.sendTCPQuery(query)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expectedNS)

    def testBogus(self):
        query = dns.message.make_query('ted.bogus.example', 'A', want_dnssec=True)

        res = self.sendTCPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

    def testAuthZone(self):
        query = dns.message.make_query('authzone.example', 'A', want_dnssec=True)

        expectedA = dns.rrset.from_text('authzone.example.', 0, 'IN', 'A', '192.0.2.88')

        res = self.sendTCPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expectedA)

    def testLocalhost(self):
        queryA = dns.message.make_query('localhost', 'A', want_dnssec=True)
        expectedA = dns.rrset.from_text('localhost.', 0, 'IN', 'A', '127.0.0.1')

        queryPTR = dns.message.make_query('1.0.0.127.in-addr.arpa', 'PTR', want_dnssec=True)
        expectedPTR = dns.rrset.from_text('1.0.0.127.in-addr.arpa.', 0, 'IN', 'PTR', 'localhost.')

        resA = self.sendTCPQuery(queryA)
        resPTR = self.sendTCPQuery(queryPTR)

        self.assertRcodeEqual(resA, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(resA, expectedA)

        self.assertRcodeEqual(resPTR, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(resPTR, expectedPTR)

    def testIslandOfSecurity(self):
        query = dns.message.make_query('cname-to-islandofsecurity.secure.example.', 'A', want_dnssec=True)

        expectedCNAME = dns.rrset.from_text('cname-to-islandofsecurity.secure.example.', 0, 'IN', 'CNAME', 'node1.islandofsecurity.example.')
        expectedA = dns.rrset.from_text('node1.islandofsecurity.example.', 0, 'IN', 'A', '192.0.2.20')

        res = self.sendTCPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expectedA)


    def testVeryBasicPipeline(self):
        # This test does not enforce order, it will accept replies in any order. So
        # it does not actually test OOO behaviour.
        expected = {}
        queries = []
        for zone in ['.', 'example.', 'secure.example.']:
            expected[zone] = dns.rrset.from_text(zone, 0, dns.rdataclass.IN, 'SOA', self._SOA)
            query = dns.message.make_query(zone, 'SOA', want_dnssec=True)
            query.flags |= dns.flags.AD
            queries.append(query)

        expected['ns.secure.example.'] = dns.rrset.from_text('ns.secure.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.9'.format(prefix=self._PREFIX))
        query = dns.message.make_query('ns.secure.example', 'A', want_dnssec=True)
        query.flags |= dns.flags.AD
        queries.append(query)

        ress = self.sendTCPQueries(queries)

        self.assertEqual(len(ress), len(expected))

        for res in ress:
            exp = expected[res.question[0].name.to_text()]
            self.assertMessageIsAuthenticated(res)
            self.assertRRsetInAnswer(res, exp)
            self.assertMatchingRRSIGInAnswer(res, exp)

