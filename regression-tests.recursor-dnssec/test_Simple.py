import dns
from recursortests import RecursorTest

class testSimple(RecursorTest):
    _confdir = 'Simple'

    _config_template = """dnssec=validate"""

    def testSOAs(self):
        for zone in ['.', 'example.', 'secure.example.']:
            expected = dns.rrset.from_text(zone, 0, dns.rdataclass.IN, 'SOA', self._SOA)
            query = dns.message.make_query(zone, 'SOA', want_dnssec=True)

            res = self.sendUDPQuery(query)

            self.assertMessageIsAuthenticated(res)
            self.assertRRsetInAnswer(res, expected)
            self.assertMatchingRRSIGInAnswer(res, expected)

    def testA(self):
        expected = dns.rrset.from_text('ns.secure.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.9'.format(prefix=self._PREFIX))
        query = dns.message.make_query('ns.secure.example', 'A', want_dnssec=True)

        res = self.sendUDPQuery(query)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testDelegation(self):
        query = dns.message.make_query('example', 'NS', want_dnssec=True)

        expectedNS = dns.rrset.from_text('example.', 0, 'IN', 'NS', 'ns1.example.', 'ns2.example.')

        res = self.sendUDPQuery(query)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expectedNS)

    def testBogus(self):
        query = dns.message.make_query('ted.bogus.example', 'A', want_dnssec=True)

        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
