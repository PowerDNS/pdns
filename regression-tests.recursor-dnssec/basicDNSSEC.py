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
    def sendQuery(self, name, rdtype, useTCP=False):
        """Helper function that creates the query"""
        msg = dns.message.make_query(name, rdtype, want_dnssec=True)
        msg.flags |= dns.flags.AD

        if useTCP:
            return self.sendTCPQuery(msg)
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

    def testSecureSubtreeInZoneAnswer(self):
        res = self.sendQuery('host1.sub.secure.example.', 'A')
        expected = dns.rrset.from_text('host1.sub.secure.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.11')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMatchingRRSIGInAnswer(res, expected)
        self.assertMessageIsAuthenticated(res)

    def testSecureSubtreeInZoneNXDOMAIN(self):
        res = self.sendQuery('host2.sub.secure.example.', 'A')

        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertMessageIsAuthenticated(res)

    def testSecureWildcardAnswer(self):
        res = self.sendQuery('something.wildcard.secure.example.', 'A')
        expected = dns.rrset.from_text('something.wildcard.secure.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.10')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMatchingRRSIGInAnswer(res, expected)
        self.assertMessageIsAuthenticated(res)

    def testSecureCNAMEWildCardAnswer(self):
        res = self.sendQuery('something.cnamewildcard.secure.example.', 'A')
        expectedCNAME = dns.rrset.from_text('something.cnamewildcard.secure.example.', 0, dns.rdataclass.IN, 'CNAME', 'host1.secure.example.')
        expectedA = dns.rrset.from_text('host1.secure.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.2')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMatchingRRSIGInAnswer(res, expectedCNAME)
        self.assertMatchingRRSIGInAnswer(res, expectedA)
        self.assertMessageIsAuthenticated(res)

    def testSecureCNAMEWildCardNXDOMAIN(self):
        # the answer to this query reaches the UDP truncation threshold, so let's use TCP
        res = self.sendQuery('something.cnamewildcardnxdomain.secure.example.', 'A', useTCP=True)
        expectedCNAME = dns.rrset.from_text('something.cnamewildcardnxdomain.secure.example.', 0, dns.rdataclass.IN, 'CNAME', 'doesntexist.secure.example.')

        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertMatchingRRSIGInAnswer(res, expectedCNAME)
        self.assertMessageIsAuthenticated(res)

    def testSecureNoData(self):
        res = self.sendQuery('host1.secure.example.', 'AAAA')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnswerEmpty(res)
        self.assertAuthorityHasSOA(res)
        self.assertMessageIsAuthenticated(res)

    def testSecureCNAMENoData(self):
        res = self.sendQuery('cname.secure.example.', 'AAAA')
        expectedCNAME = dns.rrset.from_text('cname.secure.example.', 0, dns.rdataclass.IN, 'CNAME', 'host1.secure.example.')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMatchingRRSIGInAnswer(res, expectedCNAME)
        self.assertAuthorityHasSOA(res)
        self.assertMessageIsAuthenticated(res)

    def testSecureWildCardNoData(self):
        res = self.sendQuery('something.cnamewildcard.secure.example.', 'AAAA')
        expectedCNAME = dns.rrset.from_text('something.cnamewildcard.secure.example.', 0, dns.rdataclass.IN, 'CNAME', 'host1.secure.example.')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMatchingRRSIGInAnswer(res, expectedCNAME)
        self.assertAuthorityHasSOA(res)
        self.assertMessageIsAuthenticated(res)

    def testInsecureToSecureCNAMEAnswer(self):
        res = self.sendQuery('cname-to-secure.insecure.example.', 'A')
        expectedA = dns.rrset.from_text('host1.secure.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.2')
        expectedCNAME = dns.rrset.from_text('cname-to-secure.insecure.example.', 0, dns.rdataclass.IN, 'CNAME', 'host1.secure.example.')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RD', 'RA'], ['DO'])
        self.assertRRsetInAnswer(res, expectedCNAME)
        self.assertMatchingRRSIGInAnswer(res, expectedA)

    def testSecureToInsecureCNAMEAnswer(self):
        res = self.sendQuery('cname-to-insecure.secure.example.', 'A')
        expectedA = dns.rrset.from_text('node1.insecure.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.6')
        expectedCNAME = dns.rrset.from_text('cname-to-insecure.secure.example.', 0, dns.rdataclass.IN, 'CNAME', 'node1.secure.example.')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RD', 'RA'], ['DO'])
        self.assertRRsetInAnswer(res, expectedA)
        self.assertMatchingRRSIGInAnswer(res, expectedCNAME)

