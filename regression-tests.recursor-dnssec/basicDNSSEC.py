import dns
from recursortests import RecursorTest
import os

class BasicDNSSEC(RecursorTest):
    __test__ = False
    _config_template = """dnssec=validate"""

    @classmethod
    def setUp(cls):
        confdir = os.path.join('configs', cls._confdir)
        cls.wipeRecursorCache(confdir)

    @classmethod
    def sendQuery(self, name, rdtype):
        """Helper function that creates the query"""
        msg = dns.message.make_query(name, rdtype, want_dnssec=True)
        msg.flags |= dns.flags.AD

        return self.sendUDPQuery(msg)

    def testSecureAnswer(self):
        res = self.sendQuery('ns.secure.example.', 'A')
        expected = dns.rrset.from_text('ns.secure.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMatchingRRSIGInAnswer(res, expected)
        self.assertMessageIsAuthenticated(res)

    def testInsecureAnswer(self):
        res = self.sendQuery('node1.insecure.example.', 'A')

        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testBogusAnswer(self):
        res = self.sendQuery('ted.bogus.example.', 'A')

        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.assertAnswerEmpty(res)

    def testSecureNXDOMAIN(self):
        res = self.sendQuery('nxdomain.secure.example.', 'A')

        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)

    def testInsecureNXDOMAIN(self):
        res = self.sendQuery('nxdomain.insecure.example.', 'A')

        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)

    def testBogusNXDOMAIN(self):
        res = self.sendQuery('nxdomain.bogus.example.', 'A')

        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

    def testSecureOptoutAnswer(self):
        res = self.sendQuery('node1.secure.optout.example.', 'A')
        expected = dns.rrset.from_text('node1.secure.optout.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.8')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMatchingRRSIGInAnswer(res, expected)
        self.assertMessageIsAuthenticated(res)

    def testInsecureOptoutAnswer(self):
        res = self.sendQuery('node1.insecure.optout.example.', 'A')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertNoRRSIGsInAnswer(res)
