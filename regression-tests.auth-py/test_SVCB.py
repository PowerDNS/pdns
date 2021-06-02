from authtests import AuthTest
import dns


class TestSVCBRecords(AuthTest):
    _config_template = """
launch=bind
svc-autohints
"""

    _zones = {
        'example.org': """
example.org.                 3600 IN SOA  {soa}
example.org.                 3600 IN NS   ns1.example.org.
example.org.                 3600 IN NS   ns2.example.org.

example.org.                 3600 IN HTTPS 0 www.example.org.
www.example.org.             3600 IN HTTPS 1 . ipv4hint=auto ipv6hint=auto
www.example.org.             3600 IN A     192.0.2.80
www.example.org.             3600 IN AAAA  2001:db8::80

no-a.example.org.            3600 IN HTTPS 1 . ipv4hint=auto ipv6hint=auto
no-a.example.org.            3600 IN AAAA  2001:db8::81

no-aaaa.example.org.         3600 IN HTTPS 1 . ipv4hint=auto ipv6hint=auto
no-aaaa.example.org.         3600 IN A     192.0.2.81
        """,
    }

    def testWithoutAlias(self):
        query = dns.message.make_query('www.example.org', 'HTTPS')
        res = self.sendUDPQuery(query)
        expected_ans = dns.rrset.from_text(
            'www.example.org.', 3600, dns.rdataclass.IN, 'HTTPS',
            '1 . ipv4hint="192.0.2.80" ipv6hint="2001:db8::80"'
        )
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected_ans)
        self.assertEqual(len(res.additional), 2)

    def testWithAlias(self):
        """
        Ensure additional processing happens for HTTPS AliasMode
        """
        query = dns.message.make_query('example.org', 'HTTPS')
        res = self.sendUDPQuery(query)
        expected_addl = dns.rrset.from_text(
            'www.example.org.', 3600, dns.rdataclass.IN, 'HTTPS',
            '1 . ipv4hint="192.0.2.80" ipv6hint="2001:db8::80"'
        )
        expected_ans = dns.rrset.from_text(
            'example.org.', 3600, dns.rdataclass.IN, 'HTTPS',
            '0 www.example.org'
        )
        print(res.answer)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected_ans)
        self.assertRRsetInAdditional(res, expected_addl)
        self.assertEqual(len(res.additional), 3)

    def testWithMissingA(self):
        """
        Ensure PowerDNS removes the ipv4hint if there's no A record
        """
        query = dns.message.make_query('no-a.example.org', 'HTTPS')
        res = self.sendUDPQuery(query)
        expected_ans = dns.rrset.from_text(
            'no-a.example.org.', 3600, dns.rdataclass.IN, 'HTTPS',
            '1 . ipv6hint="2001:db8::81"'
        )
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected_ans)
        self.assertEqual(len(res.additional), 1)

    def testWithMissingAAAA(self):
        """
        Ensure PowerDNS removes the ipv6hint if there's no AAAA record
        """
        query = dns.message.make_query('no-aaaa.example.org', 'HTTPS')
        res = self.sendUDPQuery(query)
        expected_ans = dns.rrset.from_text(
            'no-aaaa.example.org.', 3600, dns.rdataclass.IN, 'HTTPS',
            '1 . ipv4hint="192.0.2.81"'
        )
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected_ans)
        self.assertEqual(len(res.additional), 1)
