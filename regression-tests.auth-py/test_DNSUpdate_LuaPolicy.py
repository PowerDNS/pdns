#!/usr/bin/env python
import unittest
import requests
import threading
import dns
import time
import clientsubnetoption

from authtests import AuthTest

class TestDNSUpdatePolicyScript(AuthTest):
    _config_template = """
dnsupdate=yes
lua-dns-policy-script=dnsupdate_policies/accept-any-signed.lua

"""

    _tsig_test_key: "wQheCVjrrMc0DpIUixfegXXesCmiCgIAPsHw+P+QDOo="

    @classmethod
    def setUpClass(cls):

        super(TestDNSUpdatePolicyScript, cls).setUpClass()
        os.system(f"$PDNSUTIL --config-dir=configs/auth import-tsig-key test hmac-md5 {self._tsig_test_key}")
        os.system("$PDNSUTIL --config-dir=configs/auth activate-tsig-key example.org test primary")

    def testAuthenticatedDnsUpdate(self):
        """
        Test if an authenticated DNSUPDATE gets through
        """
        expected = [dns.rrset.from_text('updatetest.example.org', 0, dns.rdataclass.IN, 'A',
                                        '10.42.1.1')]
        update = dns.update.UpdateMessage('example.org', keyring=dns.tsigkeyring.from_text({
          'my-tsig-key.': self._tsig_test_key
        }))
        update.add('updatetest', 300, 'A', '10.42.1.1')
        update_res = dns.query.tcp(update, '172.0.0.1')

        query_updated = dns.message.make_query('updatetest.example.org', 'A')
        query_res = self.sendUDPQuery(query)

        self.assertRcodeEqual(update_res, dns.rcode.NOERROR)
        self.assertRcodeEqual(query_res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(query_res, expected)

    def testUnknownSignerDnsUpdate(self):
        """
        Test if a DNSUPDATE signed with an unknown key doesn't get accepted
        """
        update = dns.update.UpdateMessage('example.org', keyring=dns.tsigkeyring.from_text({
          'unknown-key.': 'PTshiG20eZoNoPLMx6D0vxCkqhDymX/FtOIVXsI8+zE='
        }))
        update.add('update_unknown_signer', 300, 'A', '10.42.1.2')
        update_res = dns.query.tcp(update, '172.0.0.1')

        query_updated = dns.message.make_query('update_unknown_signer.example.org', 'A')
        query_res = self.sendUDPQuery(query)

        self.assertRcodeEqual(update_res, dns.rcode.NOERROR)
        self.assertRcodeEqual(query_res, dns.rcode.NXDOMAIN)


if __name__ == '__main__':
    unittest.main()
    exit(0)
