from recursortests import RecursorTest
import dns

class testSimple(RecursorTest):
    _confdir = 'Simple'

    _config_template = """dnssec=validate"""

    def testSOAs(self):
        for zone in ['.', 'example.net.']:
            expected = dns.rrset.from_text(zone, 0, dns.rdataclass.IN, 'SOA', self._SOA)
            query = dns.message.make_query(zone, 'SOA', want_dnssec = True)

            res = self.sendUDPQuery(query)

            self.assertMessageIsAuthenticated(res)
            self.assertRRsetInAnswer(res, expected)

    def testA(self):
        expected = dns.rrset.from_text('ns1.example.net.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        query = dns.message.make_query('ns1.example.net', 'A', want_dnssec = True)

        res = self.sendUDPQuery(query)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)

    def testDelegation(self):
        query = dns.message.make_query('example.net', 'NS', want_dnssec=True)

        expectedNS = dns.rrset.from_text('example.net.', 0, 'IN', 'NS', 'ns1.example.net.', 'ns2.example.net.')

        res = self.sendUDPQuery(query)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expectedNS)
