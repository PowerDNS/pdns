from authtests import AuthTest
import dns
import os
import subprocess

class SVCBRecordsBase(AuthTest):
    _config_template = """
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

auto-a.example.org.          3600 IN HTTPS 1 . ipv4hint=auto ipv6hint=2001:db8::81
auto-a.example.org.          3600 IN A 192.0.2.80
auto-a.example.org.          3600 IN AAAA 2001:db8::80

no-auto.example.org.         3600 IN HTTPS 1 . ipv4hint=192.0.2.81 ipv6hint=2001:db8::81
no-auto.example.org.         3600 IN A 192.0.2.80
no-auto.example.org.         3600 IN AAAA 2001:db8::80

auto-aaaa.example.org.       3600 IN HTTPS 1 . ipv4hint=192.0.2.81 ipv6hint=auto
auto-aaaa.example.org.       3600 IN A 192.0.2.80
auto-aaaa.example.org.       3600 IN AAAA 2001:db8::80
        """,
    }

    def impl_testWithoutAlias(self):
        query = dns.message.make_query('www.example.org', 'HTTPS')
        res = self.sendUDPQuery(query)
        expected_ans = dns.rrset.from_text(
            'www.example.org.', 3600, dns.rdataclass.IN, 'HTTPS',
            '1 . ipv4hint="192.0.2.80" ipv6hint="2001:db8::80"'
        )
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected_ans)
        self.assertEqual(len(res.additional), 2)

    def impl_testWithAlias(self):
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
            '0 www.example.org.'
        )
        print(res.answer)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected_ans)
        self.assertRRsetInAdditional(res, expected_addl)
        self.assertEqual(len(res.additional), 3)

    def impl_testWithMissingA(self):
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

    def impl_testWithMissingAAAA(self):
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

    def impl_testNoAuto(self):
        """
        Ensure we send the actual hints, not generated ones
        """
        query = dns.message.make_query('no-auto.example.org', 'HTTPS')
        res = self.sendUDPQuery(query)
        expected_ans = dns.rrset.from_text(
            'no-auto.example.org.', 3600, dns.rdataclass.IN, 'HTTPS',
            '1 . ipv4hint="192.0.2.81" ipv6hint="2001:db8::81"'
        )
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        print(res)
        self.assertRRsetInAnswer(res, expected_ans)
        self.assertEqual(len(res.additional), 2)

    def impl_testAutoA(self):
        """
        Ensure we send a generated A hint, but keep the existing AAAA hint
        """
        query = dns.message.make_query('auto-a.example.org', 'HTTPS')
        res = self.sendUDPQuery(query)
        expected_ans = dns.rrset.from_text(
            'auto-a.example.org.', 3600, dns.rdataclass.IN, 'HTTPS',
            '1 . ipv4hint="192.0.2.80" ipv6hint="2001:db8::81"'
        )
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        print(res)
        self.assertRRsetInAnswer(res, expected_ans)
        self.assertEqual(len(res.additional), 2)

    def impl_testAutoAAAA(self):
        """
        Ensure we send a generated AAAA hint, but keep the existing A hint
        """
        query = dns.message.make_query('auto-aaaa.example.org', 'HTTPS')
        res = self.sendUDPQuery(query)
        expected_ans = dns.rrset.from_text(
            'auto-aaaa.example.org.', 3600, dns.rdataclass.IN, 'HTTPS',
            '1 . ipv4hint="192.0.2.81" ipv6hint="2001:db8::80"'
        )
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        print(res)
        self.assertRRsetInAnswer(res, expected_ans)
        self.assertEqual(len(res.additional), 2)

class TestSVCBRecordsBind(SVCBRecordsBase):
    _backend = "bind"

    _config_template_default = (
        SVCBRecordsBase._config_template_default
        + """
bind-config={confdir}/named.conf
bind-dnssec-db={bind_dnssec_db}
"""
    )

    _config_template = (
        SVCBRecordsBase._config_template
        + """
launch={backend}
"""
    )

    def testWithoutAlias(self):
        self.impl_testWithoutAlias()

    def testWithAlias(self):
        """
        Ensure additional processing happens for HTTPS AliasMode
        """
        self.impl_testWithAlias()

    def testWithMissingA(self):
        """
        Ensure PowerDNS removes the ipv4hint if there's no A record
        """
        self.impl_testWithMissingA()

    def testWithMissingAAAA(self):
        """
        Ensure PowerDNS removes the ipv6hint if there's no AAAA record
        """
        self.impl_testWithMissingAAAA()

    def testNoAuto(self):
        """
        Ensure we send the actual hints, not generated ones
        """
        self.impl_testNoAuto()

    def testAutoA(self):
        """
        Ensure we send a generated A hint, but keep the existing AAAA hint
        """
        self.impl_testAutoA()

    def testAutoAAAA(self):
        """
        Ensure we send a generated AAAA hint, but keep the existing A hint
        """
        self.impl_testAutoAAAA()

class TestSVCBRecordsLMDB(SVCBRecordsBase):
    _backend='lmdb'

    _config_template = (
        SVCBRecordsBase._config_template
        + """
launch=lmdb
"""
    )

    @classmethod
    def generateAllAuthConfig(cls, confdir):
        # This is very similar to AuthTest.generateAllAuthConfig,
        # but for lmdb backend, we ignore auth keys but need to load-zone
        # into lmdb storage.
        cls.generateAuthConfig(confdir)

        for zonename, zonecontent in cls._zones.items():
            cls.generateAuthZone(confdir,
                                 zonename,
                                 zonecontent)
            pdnsutilCmd = [os.environ['PDNSUTIL'],
                           '--config-dir=%s' % confdir,
                           'load-zone',
                           zonename,
                           os.path.join(confdir, '%s.zone' % zonename)]

            print(' '.join(pdnsutilCmd))
            try:
                subprocess.check_output(pdnsutilCmd, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                raise AssertionError('%s failed (%d): %s' % (pdnsutilCmd, e.returncode, e.output))

    def testWithoutAlias(self):
        self.impl_testWithoutAlias()

    def testWithAlias(self):
        """
        Ensure additional processing happens for HTTPS AliasMode
        """
        self.impl_testWithAlias()

    def testWithMissingA(self):
        """
        Ensure PowerDNS removes the ipv4hint if there's no A record
        """
        self.impl_testWithMissingA()

    def testWithMissingAAAA(self):
        """
        Ensure PowerDNS removes the ipv6hint if there's no AAAA record
        """
        self.impl_testWithMissingAAAA()

    def testNoAuto(self):
        """
        Ensure we send the actual hints, not generated ones
        """
        self.impl_testNoAuto()

    def testAutoA(self):
        """
        Ensure we send a generated A hint, but keep the existing AAAA hint
        """
        self.impl_testAutoA()

    def testAutoAAAA(self):
        """
        Ensure we send a generated AAAA hint, but keep the existing A hint
        """
        self.impl_testAutoAAAA()
