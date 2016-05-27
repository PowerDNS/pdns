import dns
from recursortests import RecursorTest

class testSimple(RecursorTest):
    _confdir = 'NTA'

    _config_template = """dnssec=validate"""
    _lua_config_file = """addNTA("bogus.example")"""

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
