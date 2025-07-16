import pytest
import dns
from recursortests import RecursorTest

@pytest.mark.external
class WellKnownTest(RecursorTest):
    _auths_zones = None
    _confdir = 'WellKnown'
    _roothints = None
    _root_DS = None
    _config_template = """dnssec=validate"""

    def testServFail(self):
        names = ['servfail.nl', 'dnssec-failed.org']
        results = []
        for name in names:
            query = dns.message.make_query(name, 'SOA')
            results.append(self.sendUDPQuery(query, timeout=5.0))

        self.assertEqual(len(results), len(names))

        for result in results:
            self.assertRcodeEqual(result, dns.rcode.SERVFAIL)

    def testNoError(self):
        names = ['powerdns.com', 'nlnetlabs.nl', 'knot-dns.cz']
        results = []
        for name in names:
            query = dns.message.make_query(name, 'SOA')
            results.append(self.sendUDPQuery(query))

        self.assertEqual(len(results), len(names))

        for result in results:
            self.assertRcodeEqual(result, dns.rcode.NOERROR)
