import dns
from recursortests import RecursorTest

class testSimple(RecursorTest):
    _confdir = 'NTA'

    _config_template = """dnssec=validate"""
    _lua_config_file = """addNTA("bogus.example")
addNTA('secure.optout.example', 'Should be Insecure, even with DS configured')
addTA('secure.optout.example', '64215 13 1 b88284d7a8d8605c398e8942262f97b9a5a31787')"""

    def testDirectNTA(self):
        """Ensure a direct query to a bogus name with an NTA is Insecure"""

        msg = dns.message.make_query("ted.bogus.example.", dns.rdatatype.A)
        msg.flags = dns.flags.from_text('AD RD')
        msg.use_edns(edns=0, ednsflags=dns.flags.edns_from_text('DO'))

        res = self.sendUDPQuery(msg)

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testCNAMENTA(self):
        """Ensure a CNAME from a secure zone to a bogus one with an NTA is Insecure"""
        msg = dns.message.make_query("cname-to-bogus.secure.example.", dns.rdatatype.A)
        msg.flags = dns.flags.from_text('AD RD')
        msg.use_edns(edns=0, ednsflags=dns.flags.edns_from_text('DO'))

        res = self.sendUDPQuery(msg)

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testSecureWithNTAandDS(self):
        """#4391: when there is a TA *and* NTA configured for a name, the result must be insecure"""
        msg = dns.message.make_query("node1.secure.optout.example.", dns.rdatatype.A)
        msg.flags = dns.flags.from_text('AD RD')
        msg.use_edns(edns=0, ednsflags=dns.flags.edns_from_text('DO'))

        res = self.sendUDPQuery(msg)

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
