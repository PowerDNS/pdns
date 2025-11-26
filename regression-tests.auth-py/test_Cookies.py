#!/usr/bin/env python
import dns

from authtests import AuthTest


class TestEdnsCookies(AuthTest):
    _config_template = """
launch={backend}
edns-cookie-secret=aabbccddeeff11223344556677889900
"""

    _zones = {
        "example.org": """
example.org.                 3600 IN SOA  {soa}
example.org.                 3600 IN NS   ns1.example.org.
example.org.                 3600 IN NS   ns2.example.org.
ns1.example.org.             3600 IN A    192.0.2.10
ns2.example.org.             3600 IN A    192.0.2.11

www.example.org.             3600 IN A    192.0.2.5
        """,
    }

    def sendAndExpectNoCookie(self, msg, rcode):
        res = self.sendUDPQuery(msg)
        self.assertRcodeEqual(res, rcode)
        self.assertFalse(any([opt.otype == dns.edns.COOKIE for opt in res.options]))

    def getCookieFromServer(self):
        opts = [dns.edns.GenericOption(dns.edns.COOKIE, b"\x22\x11\x33\x44\x55\x66\x77\x88")]
        query = dns.message.make_query("www.example.org", "A", options=opts)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, 23)  # BADCOOKIE
        for opt in res.options:
            if opt.otype == dns.edns.COOKIE:
                return opt
        self.fail()
        return None

    def testNoCookie(self):
        query = dns.message.make_query("www.example.org", "A", use_edns=0)
        self.sendAndExpectNoCookie(query, dns.rcode.NOERROR)

    def testClientCookieTooShort(self):
        opts = [dns.edns.GenericOption(dns.edns.COOKIE, b"\x22")]
        query = dns.message.make_query("www.example.org", "A", options=opts)
        self.sendAndExpectNoCookie(query, dns.rcode.FORMERR)

        opts = [dns.edns.GenericOption(dns.edns.COOKIE, b"\x22\x11\x33\x44\x55\x66\x77")]
        query = dns.message.make_query("www.example.org", "A", options=opts)
        self.sendAndExpectNoCookie(query, dns.rcode.FORMERR)

    def testServerCookieTooShort(self):
        opts = [dns.edns.GenericOption(dns.edns.COOKIE, b"\x22\x11\x33\x44\x55\x66\x77\x88\x99")]
        query = dns.message.make_query("www.example.org", "A", options=opts)
        self.sendAndExpectNoCookie(query, dns.rcode.FORMERR)

        opts = [
            dns.edns.GenericOption(
                dns.edns.COOKIE, b"\x22\x11\x33\x44\x55\x66\x77\x88" + b"\x22\x11\x33\x44\x55\x66\x77"
            )
        ]
        query = dns.message.make_query("www.example.org", "A", options=opts)
        self.sendAndExpectNoCookie(query, dns.rcode.FORMERR)

    def testOnlyClientCookie(self):
        opts = [dns.edns.GenericOption(dns.edns.COOKIE, b"\x22\x11\x33\x44\x55\x66\x77\x88")]
        query = dns.message.make_query("www.example.org", "A", options=opts)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, 23)  # BADCOOKIE
        self.assertTrue(any([opt.otype == dns.edns.COOKIE for opt in res.options]))

    def testOnlyClientCookieTCP(self):
        opts = [dns.edns.GenericOption(dns.edns.COOKIE, b"\x22\x11\x33\x44\x55\x66\x77\x88")]
        query = dns.message.make_query("www.example.org", "A", options=opts)
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertTrue(any(opt.otype == dns.edns.COOKIE for opt in res.options))

    def testCorrectCookie(self):
        opts = [self.getCookieFromServer()]
        query = dns.message.make_query("www.example.org", "A", options=opts)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testBrokenCookie(self):
        data = self.getCookieFromServer().data
        # replace a byte in the client cookie
        data = data.replace(b"\x11", b"\x12")
        opts = [dns.edns.GenericOption(dns.edns.COOKIE, data)]
        query = dns.message.make_query("www.example.org", "A", options=opts)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, 23)
        for opt in res.options:
            if opt.otype == dns.edns.COOKIE:
                self.assertNotEqual(opt.data, opts[0].data)
                return
        self.fail()


class TestEdnsRandomCookies(TestEdnsCookies):
    _config_template = """
launch={backend}
edns-cookie-secret=random
"""
