from recursortests import RecursorTest
import dns

class testSimple(RecursorTest):
    _confdir = 'Simple'

    _config_template = """dnssec=validate"""

    def testSOAs(self):
        for zone in ['.', 'example.net']:
            expected = dns.rrset.from_text(zone, 0, dns.rdataclass.IN, 'SOA', self._SOA)
            query = dns.message.make_query(zone, 'SOA', want_dnssec = True)

            res = self.sendUDPQuery(query)
            resFlags = dns.flags.to_text(res.flags)

            self.assertTrue('AD' in resFlags)
            self.assertEqual(len(res.answer), 2) # SOA + RRSIG
            self.assertEqual(res.answer[0], expected)

    def testA(self):
        expected = dns.rrset.from_text('ns.example.net', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        query = dns.message.make_query('ns.example.net', 'A', want_dnssec = True)

        res = self.sendUDPQuery(query)
        resFlags = dns.flags.to_text(res.flags)

        self.assertTrue('AD' in resFlags)
        self.assertEqual(len(res.answer), 2) # A + RRSIG
        self.assertEqual(res.answer[0], expected)
