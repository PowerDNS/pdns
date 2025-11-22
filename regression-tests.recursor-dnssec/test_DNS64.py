import dns
import os

from recursortests import RecursorTest


class DNS64Test(RecursorTest):
    _confdir = "DNS64"
    _auth_zones = RecursorTest._default_auth_zones
    _config_template = """
    serve-rfc6303=no
    auth-zones=example.dns64=configs/%s/example.dns64.zone
    auth-zones+=in-addr.arpa=configs/%s/in-addr.arpa.zone
    auth-zones+=ip6.arpa=configs/%s/ip6.arpa.zone

    dns64-prefix=64:ff9b::/96
    """ % (_confdir, _confdir, _confdir)

    _lua_dns_script_file = """
      function nodata(dq)
        if dq.qtype == pdns.AAAA and dq.qname:equal("formerr.example.dns64") then
          dq.rcode = pdns.FORMERR
          return true
        end
        return false
       end
    """

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, "example.dns64.zone")
        with open(authzonepath, "w") as authzone:
            authzone.write(
                """$ORIGIN example.dns64
@ 3600 IN SOA {soa}
www 3600 IN A 192.0.2.42
www 3600 IN TXT "does exist"
txt 3600 IN TXT "a and aaaa do not exist"
aaaa 3600 IN AAAA 2001:db8::1
cname 3600 IN CNAME cname2.example.dns64.
cname2 3600 IN CNAME www.example.dns64.
cname3 3600 IN CNAME txt.example.dns64.
formerr 3600 IN A 192.0.2.43
""".format(soa=cls._SOA)
            )

        authzonepath = os.path.join(confdir, "in-addr.arpa.zone")
        with open(authzonepath, "w") as authzone:
            authzone.write(
                """$ORIGIN in-addr.arpa
@ 3600 IN SOA {soa}
42.2.0.192 IN PTR www.example.dns64.
""".format(soa=cls._SOA)
            )

        authzonepath = os.path.join(confdir, "ip6.arpa.zone")
        with open(authzonepath, "w") as authzone:
            authzone.write(
                """$ORIGIN ip6.arpa
@ 3600 IN SOA {soa}
1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2 IN PTR aaaa.example.dns64.
""".format(soa=cls._SOA)
            )

        super(DNS64Test, cls).generateRecursorConfig(confdir)

    # this type (A) exists for this name
    def testExistingA(self):
        qname = "www.example.dns64."
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, "A", "192.0.2.42")

        query = dns.message.make_query(qname, "A", want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    # there is no A record, we should get a NODATA
    def testNonExistingA(self):
        qname = "aaaa.example.dns64."

        query = dns.message.make_query(qname, "A", want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(len(res.answer), 0)

    # this type (AAAA) does not exist for this name but there is an A record, we should get a DNS64-wrapped AAAA
    def testNonExistingAAAA(self):
        qname = "www.example.dns64."
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, "AAAA", "64:ff9b::c000:22a")

        query = dns.message.make_query(qname, "AAAA", want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    # there is a CNAME from that name to a second one, then to a name for which this type (AAAA)
    # does not exist, but an A record does, so we should get a DNS64-wrapped AAAA
    def testCNAMEToA(self):
        qname = "cname.example.dns64."
        expectedResults = [
            dns.rrset.from_text(qname, 0, dns.rdataclass.IN, "CNAME", "cname2.example.dns64."),
            dns.rrset.from_text("cname2.example.dns64.", 0, dns.rdataclass.IN, "CNAME", "www.example.dns64."),
            dns.rrset.from_text("www.example.dns64.", 0, dns.rdataclass.IN, "AAAA", "64:ff9b::c000:22a"),
        ]

        query = dns.message.make_query(qname, "AAAA", want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            for expected in expectedResults:
                self.assertRRsetInAnswer(res, expected)

    # there is a CNAME from the name to a name that is NODATA for both A and AAAA
    # so we should get a NODATA with a single SOA record (#14362)
    def testCNAMEToNoData(self):
        qname = "cname3.example.dns64."

        expectedAnswer = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, "CNAME", "txt.example.dns64.")
        query = dns.message.make_query(qname, "AAAA", want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query, 2.0, True, {"one_rr_per_rrset": True})  # we want to detect dups
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(len(res.answer), 1)
            self.assertEqual(len(res.authority), 1)
            self.assertRRsetInAnswer(res, expectedAnswer)
            self.assertAuthorityHasSOA(res)

    # this type (AAAA) does not exist for this name and there is no A record either, we should get a NXDomain
    def testNXD(self):
        qname = "nxd.example.dns64."

        query = dns.message.make_query(qname, "AAAA", want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)

    # this type (AAAA) does not exist for this name and there is no A record either, we should get a NODATA as TXT does exist
    def testNoData(self):
        qname = "txt.example.dns64."

        query = dns.message.make_query(qname, "AAAA", want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query, 2.0, True, {"one_rr_per_rrset": True})  # we want to detect dups
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(len(res.answer), 0)
            self.assertEqual(len(res.authority), 1)

    # there is an AAAA record, we should get it
    def testExistingAAAA(self):
        qname = "aaaa.example.dns64."
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, "AAAA", "2001:db8::1")

        query = dns.message.make_query(qname, "AAAA", want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    # If the AAAA is handled by Lua code, we should not get a dns64 result
    def testFormerr(self):
        qname = "formerr.example.dns64"

        query = dns.message.make_query(qname, "AAAA", want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.FORMERR)

    # If the AAAA times out, we still should get a dns64 result
    def testTimeout(self):
        qname = "8.delay1.example."
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, "AAAA", "64:ff9b::c000:264")

        query = dns.message.make_query(qname, "AAAA", want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    # there is a TXT record, we should get it
    def testExistingTXT(self):
        qname = "www.example.dns64."
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, "TXT", '"does exist"')

        query = dns.message.make_query(qname, "TXT", want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    # the PTR records for the DNS64 prefix should be generated
    def testNonExistingPTR(self):
        qname = "a.2.2.0.0.0.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa."
        expectedCNAME = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, "CNAME", "42.2.0.192.in-addr.arpa.")
        expected = dns.rrset.from_text("42.2.0.192.in-addr.arpa.", 0, dns.rdataclass.IN, "PTR", "www.example.dns64.")

        query = dns.message.make_query(qname, "PTR", want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            print(res)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expectedCNAME)
            self.assertRRsetInAnswer(res, expected)

    # but not for other prefixes
    def testExistingPTR(self):
        qname = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, "PTR", "aaaa.example.dns64.")

        query = dns.message.make_query(qname, "PTR", want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)
