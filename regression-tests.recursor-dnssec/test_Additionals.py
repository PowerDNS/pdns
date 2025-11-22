import dns
import os
from recursortests import RecursorTest


class AdditionalsDefaultTest(RecursorTest):
    _confdir = "AdditionalsDefault"
    _auth_zones = RecursorTest._default_auth_zones
    _config_template = """
    dnssec=validate
    disable-packetcache
    """
    _lua_config_file = """
    addAllowedAdditionalQType(pdns.MX, {pdns.A, pdns.AAAA})
    """

    def testMX(self):
        expected = dns.rrset.from_text(
            "secure.example.", 0, dns.rdataclass.IN, "MX", "10 mx1.secure.example.", "20 mx2.secure.example."
        )
        adds1 = dns.rrset.from_text("mx1.secure.example.", 0, dns.rdataclass.IN, "A", "192.0.2.18")
        adds2 = dns.rrset.from_text("mx2.secure.example.", 0, dns.rdataclass.IN, "AAAA", "1::2")
        query1 = dns.message.make_query("secure.example", "MX", want_dnssec=True)
        query1.flags |= dns.flags.AD
        query2 = dns.message.make_query("mx1.secure.example", "A", want_dnssec=True)
        query2.flags |= dns.flags.AD
        query3 = dns.message.make_query("mx2.secure.example", "AAAA", want_dnssec=True)
        query3.flags |= dns.flags.AD

        res = self.sendUDPQuery(query1)
        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)
        self.assertAdditionalEmpty(res)
        # fill the cache
        self.sendUDPQuery(query2)
        self.sendUDPQuery(query3)
        # query 1 again
        res = self.sendUDPQuery(query1)
        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)
        self.assertRRsetInAdditional(res, adds1)
        self.assertRRsetInAdditional(res, adds2)


class AdditionalsResolveImmediatelyTest(RecursorTest):
    _confdir = "AdditionalsResolveImmediately"
    _auth_zones = RecursorTest._default_auth_zones
    _config_template = """
    dnssec=validate
    disable-packetcache
    """
    _lua_config_file = """
    addAllowedAdditionalQType(pdns.MX, {pdns.A, pdns.AAAA}, { mode = pdns.AdditionalMode.ResolveImmediately})
    addAllowedAdditionalQType(pdns.NAPTR, {pdns.A, pdns.AAAA, pdns.SRV}, { mode = pdns.AdditionalMode.ResolveImmediately})
    addAllowedAdditionalQType(pdns.SRV, {pdns.A, pdns.AAAA}, { mode = pdns.AdditionalMode.ResolveImmediately})
    """

    def testMX(self):
        expected = dns.rrset.from_text(
            "secure.example.", 0, dns.rdataclass.IN, "MX", "10 mx1.secure.example.", "20 mx2.secure.example."
        )
        adds1 = dns.rrset.from_text("mx1.secure.example.", 0, dns.rdataclass.IN, "A", "192.0.2.18")
        adds2 = dns.rrset.from_text("mx2.secure.example.", 0, dns.rdataclass.IN, "AAAA", "1::2")
        query1 = dns.message.make_query("secure.example", "MX", want_dnssec=True)
        query1.flags |= dns.flags.AD

        res = self.sendUDPQuery(query1)
        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)
        self.assertRRsetInAdditional(res, adds1)
        self.assertRRsetInAdditional(res, adds2)
        self.assertMatchingRRSIGInAdditional(res, adds1)
        self.assertMatchingRRSIGInAdditional(res, adds2)

    def testNAPTR(self):
        exp = dns.rrset.from_text(
            "naptr.secure.example.",
            0,
            dns.rdataclass.IN,
            "NAPTR",
            '10 10 "s" "Z" "C" service2.secure.example.',
            '10 10 "s" "Y" "B" service1.secure.example.',
            '10 10 "a" "X" "A" s1.secure.example.',
        )
        adds1 = dns.rrset.from_text("s1.secure.example.", 0, dns.rdataclass.IN, "A", "192.0.2.19")
        adds2 = dns.rrset.from_text(
            "service1.secure.example.", 0, dns.rdataclass.IN, "SRV", "20 100 8080 a.secure.example."
        )
        adds3 = dns.rrset.from_text(
            "service2.secure.example.", 0, dns.rdataclass.IN, "SRV", "20 100 8080 b.secure.example."
        )
        adds4 = dns.rrset.from_text("a.secure.example.", 0, dns.rdataclass.IN, "A", "192.0.2.20", "192.0.2.22")
        adds5 = dns.rrset.from_text("b.secure.example.", 0, dns.rdataclass.IN, "A", "192.0.2.21")
        adds6 = dns.rrset.from_text("b.secure.example.", 0, dns.rdataclass.IN, "AAAA", "1::3")
        adds7 = dns.rrset.from_text("s1.secure.example.", 0, dns.rdataclass.IN, "A", "192.0.2.19")

        query1 = dns.message.make_query("naptr.secure.example", "NAPTR", want_dnssec=True)
        query1.flags |= dns.flags.AD
        res = self.sendUDPQuery(query1)
        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, exp)
        self.assertMatchingRRSIGInAnswer(res, exp)
        self.assertRRsetInAdditional(res, adds1)
        self.assertMatchingRRSIGInAdditional(res, adds1)
        self.assertRRsetInAdditional(res, adds2)
        self.assertMatchingRRSIGInAdditional(res, adds2)
        self.assertRRsetInAdditional(res, adds3)
        self.assertMatchingRRSIGInAdditional(res, adds3)
        self.assertRRsetInAdditional(res, adds4)
        self.assertMatchingRRSIGInAdditional(res, adds4)
        self.assertRRsetInAdditional(res, adds5)
        self.assertMatchingRRSIGInAdditional(res, adds5)
        self.assertRRsetInAdditional(res, adds6)
        self.assertMatchingRRSIGInAdditional(res, adds6)
        self.assertRRsetInAdditional(res, adds7)
        self.assertMatchingRRSIGInAdditional(res, adds7)


class AdditionalsResolveCacheOnlyTest(RecursorTest):
    _confdir = "AdditionalsResolveCacheOnly"
    _auth_zones = RecursorTest._default_auth_zones
    _config_template = """
    dnssec=validate
    disable-packetcache
    """
    _lua_config_file = """
    addAllowedAdditionalQType(pdns.MX, {pdns.A, pdns.AAAA}, { mode = pdns.AdditionalMode.ResolveImmediately})
    """

    def testMX(self):
        expected = dns.rrset.from_text(
            "secure.example.", 0, dns.rdataclass.IN, "MX", "10 mx1.secure.example.", "20 mx2.secure.example."
        )
        adds1 = dns.rrset.from_text("mx1.secure.example.", 0, dns.rdataclass.IN, "A", "192.0.2.18")
        adds2 = dns.rrset.from_text("mx2.secure.example.", 0, dns.rdataclass.IN, "AAAA", "1::2")
        query1 = dns.message.make_query("secure.example", "MX", want_dnssec=True)
        query1.flags |= dns.flags.AD

        res = self.sendUDPQuery(query1)
        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)
        self.assertRRsetInAdditional(res, adds1)
        self.assertRRsetInAdditional(res, adds2)
        self.assertMatchingRRSIGInAdditional(res, adds1)
        self.assertMatchingRRSIGInAdditional(res, adds2)
