import dns
import os
from recursortests import RecursorTest


class SimpleCookiesTest(RecursorTest):
    _confdir = "SimpleCookies"
    _auth_zones = RecursorTest._default_auth_zones

    _config_template = (
        """
recursor:
  auth_zones:
  - zone: authzone.example
    file: configs/%s/authzone.zone
dnssec:
  validation: validate
outgoing:
  cookies: true"""
        % _confdir
    )

    _expectedCookies = "Unsupported"

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, "authzone.zone")
        with open(authzonepath, "w") as authzone:
            authzone.write(
                """$ORIGIN authzone.example.
@ 3600 IN SOA {soa}
@ 3600 IN A 192.0.2.88
""".format(soa=cls._SOA)
            )
        super(SimpleCookiesTest, cls).generateRecursorYamlConfig(confdir)

    def checkCookies(self):
        confdir = os.path.join("configs", self._confdir)
        output = self.recControl(confdir, "dump-cookies", "-")
        for line in output.splitlines():
            tokens = line.split()
            if tokens[0] == ";" or tokens[0] == "dump-cookies:":
                continue
            print(tokens)
            self.assertEqual(len(tokens), 5)
            self.assertEqual(tokens[3], self._expectedCookies)

    def testSOAs(self):
        for zone in [".", "example.", "secure.example."]:
            expected = dns.rrset.from_text(zone, 0, dns.rdataclass.IN, "SOA", self._SOA)
            query = dns.message.make_query(zone, "SOA", want_dnssec=True)
            query.flags |= dns.flags.AD

            res = self.sendUDPQuery(query)

            self.assertMessageIsAuthenticated(res)
            self.assertRRsetInAnswer(res, expected)
            self.assertMatchingRRSIGInAnswer(res, expected)
        self.checkCookies()

    def testA(self):
        expected = dns.rrset.from_text(
            "ns.secure.example.", 0, dns.rdataclass.IN, "A", "{prefix}.9".format(prefix=self._PREFIX)
        )
        query = dns.message.make_query("ns.secure.example", "A", want_dnssec=True)
        query.flags |= dns.flags.AD

        res = self.sendUDPQuery(query)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)
        self.checkCookies()

    def testDelegation(self):
        query = dns.message.make_query("example", "NS", want_dnssec=True)
        query.flags |= dns.flags.AD

        expectedNS = dns.rrset.from_text("example.", 0, "IN", "NS", "ns1.example.", "ns2.example.")

        res = self.sendUDPQuery(query)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expectedNS)
        self.checkCookies()

    def testBogus(self):
        query = dns.message.make_query("ted.bogus.example", "A", want_dnssec=True)

        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.checkCookies()

    def testAuthZone(self):
        query = dns.message.make_query("authzone.example", "A", want_dnssec=True)

        expectedA = dns.rrset.from_text("authzone.example.", 0, "IN", "A", "192.0.2.88")

        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expectedA)
        self.checkCookies()

    def testLocalhost(self):
        queryA = dns.message.make_query("localhost", "A", want_dnssec=True)
        expectedA = dns.rrset.from_text("localhost.", 0, "IN", "A", "127.0.0.1")

        queryPTR = dns.message.make_query("1.0.0.127.in-addr.arpa", "PTR", want_dnssec=True)
        expectedPTR = dns.rrset.from_text("1.0.0.127.in-addr.arpa.", 0, "IN", "PTR", "localhost.")

        resA = self.sendUDPQuery(queryA)
        resPTR = self.sendUDPQuery(queryPTR)

        self.assertRcodeEqual(resA, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(resA, expectedA)

        self.assertRcodeEqual(resPTR, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(resPTR, expectedPTR)
        self.checkCookies()

    def testLocalhostSubdomain(self):
        queryA = dns.message.make_query("foo.localhost", "A", want_dnssec=True)
        expectedA = dns.rrset.from_text("foo.localhost.", 0, "IN", "A", "127.0.0.1")

        resA = self.sendUDPQuery(queryA)

        self.assertRcodeEqual(resA, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(resA, expectedA)
        self.checkCookies()

    def testIslandOfSecurity(self):
        query = dns.message.make_query("cname-to-islandofsecurity.secure.example.", "A", want_dnssec=True)

        expectedA = dns.rrset.from_text("node1.islandofsecurity.example.", 0, "IN", "A", "192.0.2.20")

        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expectedA)
        self.checkCookies()


class SimpleCookiesAuthEnabledTest(SimpleCookiesTest):
    _confdir = "SimpleCookiesAuthEnabled"
    _auth_zones = SimpleCookiesTest._auth_zones
    _expectedCookies = "Supported"

    @classmethod
    def generateAuthConfig(cls, confdir, threads):
        super(SimpleCookiesAuthEnabledTest, cls).generateAuthConfig(
            confdir, threads, "edns-cookie-secret=01234567890123456789012345678901"
        )
