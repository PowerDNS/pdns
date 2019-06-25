import dns
from recursortests import RecursorTest


class testTrustAnchorsEnabled(RecursorTest):
    """This test will do a query for "trustanchor.server CH TXT" and hopes to get
    a proper answer"""

    _auth_zones = None
    _confdir = 'TrustAnchorsEnabled'
    _roothints = None
    _root_DS = None
    _config_template = """
     allow-trust-anchor-query=yes
"""
    _lua_config_file = """
addDS("powerdns.com", "44030 8 1 B763646757DF621DD1204AD3BFA0675B49BE3279")
addNTA("example")
addNTA("example.com", "some reason")
"""

    def testTrustanchorDotServer(self):
        expected = dns.rrset.from_text_list(
            'trustanchor.server.', 86400, dns.rdataclass.CH, 'TXT',
            ['". 20326"', '"powerdns.com. 44030"'])
        query = dns.message.make_query('trustanchor.server', 'TXT',
                                       dns.rdataclass.CH)
        result = self.sendUDPQuery(query)

        self.assertRcodeEqual(result, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(result, expected)

    def testNegativerustanchorDotServer(self):
        expected = dns.rrset.from_text_list(
            'negativetrustanchor.server.', 86400, dns.rdataclass.CH, 'TXT',
            ['"example."', '"example.com. some reason"'])
        query = dns.message.make_query('negativetrustanchor.server', 'TXT',
                                       dns.rdataclass.CH)
        result = self.sendUDPQuery(query)

        self.assertRcodeEqual(result, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(result, expected)


class testTrustAnchorsDisabled(RecursorTest):
    """This test will do a query for "trustanchor.server CH TXT" and hopes to get
    a proper answer"""

    _auth_zones = None
    _confdir = 'TrustAnchorsDisabled'
    _roothints = None
    _root_DS = None
    _config_template = """
"""

    def testTrustanchorDotServer(self):
        query = dns.message.make_query('trustanchor.server', 'TXT',
                                       dns.rdataclass.CH)
        result = self.sendUDPQuery(query)

        self.assertRcodeEqual(result, dns.rcode.SERVFAIL)

    def testNegativerustanchorDotServer(self):
        query = dns.message.make_query('negativetrustanchor.server', 'TXT',
                                       dns.rdataclass.CH)
        result = self.sendUDPQuery(query)

        self.assertRcodeEqual(result, dns.rcode.SERVFAIL)
