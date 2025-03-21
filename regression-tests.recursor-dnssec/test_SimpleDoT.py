import pytest
import dns
import os
import subprocess
from recursortests import RecursorTest

class SimpleDoTTest(RecursorTest):
    """
    This tests DoT to auth server in a very basic way and is dependent on powerdns.com nameservers having DoT enabled.
    """

    _confdir = 'SimpleDoT'
    _config_template = """
dnssec=validate
dot-to-auth-names=powerdns.com
devonly-regression-test-mode
    """

    _roothints = None

    @pytest.mark.external
    def testTXT(self):
        expected = dns.rrset.from_text('dot-test-target.powerdns.org.', 0, dns.rdataclass.IN, 'TXT', 'https://github.com/PowerDNS/pdns/pull/12825')
        query = dns.message.make_query('dot-test-target.powerdns.org', 'TXT', want_dnssec=True)
        query.flags |= dns.flags.AD

        # As this test uses external servers, be a more generous wrt timeouts than the default 2.0s
        res = self.sendUDPQuery(query, timeout=5.0)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)

        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % 'configs/' + self._confdir,
                          'get dot-outqueries']
        try:
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
            self.assertNotEqual(ret, b'UNKNOWN\n')
            self.assertNotEqual(ret, b'0\n')

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % 'configs/' + self._confdir,
                          'get tcp-outqueries']
        try:
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
            self.assertEqual(ret, b'0\n')

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

