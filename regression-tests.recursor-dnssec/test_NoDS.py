import dns
from recursortests import RecursorTest


class NoDSTest(RecursorTest):
    _confdir = 'NoDS'
    _auth_zones = RecursorTest._default_auth_zones

    _config_template = """dnssec=validate"""
    _lua_config_file = """clearTA(".")"""

    def testNoDSInsecure(self):
        """#4430 When the root DS is removed, the result must be Insecure"""

        msg = dns.message.make_query("ted.bogus.example.", dns.rdatatype.A)
        msg.flags = dns.flags.from_text('AD RD')
        msg.use_edns(edns=0, ednsflags=dns.flags.edns_from_text('DO'))

        res = self.sendUDPQuery(msg)

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
