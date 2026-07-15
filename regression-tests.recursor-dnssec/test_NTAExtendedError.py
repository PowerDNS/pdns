import dns
import extendederrors
from recursortests import RecursorTest


class NTAExtendedErrorTest(RecursorTest):
    _confdir = "NTAExtendedError"
    _auth_zones = RecursorTest._default_auth_zones

    _config_template = """dnssec=validate
nta-extended-error=yes"""
    _lua_config_file = """addNTA("bogus.example", "Negative Trust Anchor for testing")
addNTA("insecure.example", "NTA on an already-insecure (unsigned) delegation")"""

    def testDirectNTAHasEDE(self):
        """A name under an NTA is Insecure (no AD) and carries EDE 33, on the fresh
        answer and on the following cache hit."""
        msg = dns.message.make_query("ted.bogus.example.", dns.rdatatype.A)
        msg.flags = dns.flags.from_text("AD RD")
        msg.use_edns(edns=0, ednsflags=dns.flags.edns_from_text("DO"))

        for _ in range(2):
            res = self.sendUDPQuery(msg)
            self.assertMessageHasFlags(res, ["QR", "RA", "RD"], ["DO"])
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(self.getEDE(res), extendederrors.ExtendedErrorOption(33, b""))

    def testCNAMEIntoNTAHasEDE(self):
        """A secure CNAME whose chased target is under an NTA carries EDE 33."""
        msg = dns.message.make_query("cname-to-bogus.secure.example.", dns.rdatatype.A)
        msg.flags = dns.flags.from_text("AD RD")
        msg.use_edns(edns=0, ednsflags=dns.flags.edns_from_text("DO"))

        res = self.sendUDPQuery(msg)
        self.assertMessageHasFlags(res, ["QR", "RA", "RD"], ["DO"])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(self.getEDE(res), extendederrors.ExtendedErrorOption(33, b""))

    def testSecureOutsideNTAHasNoEDE(self):
        """A secure name outside any NTA validates (AD set) and carries no EDE 33."""
        msg = dns.message.make_query("host1.secure.example.", dns.rdatatype.A)
        msg.flags = dns.flags.from_text("AD RD")
        msg.use_edns(edns=0, ednsflags=dns.flags.edns_from_text("DO"))

        res = self.sendUDPQuery(msg)
        self.assertMessageHasFlags(res, ["QR", "RA", "RD", "AD"], ["DO"])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertIsNone(self.getEDE(res))

    def testNTAOnAlreadyInsecureHasEDE(self):
        """insecure.example is an unsigned delegation, so it is Insecure regardless of the
        NTA. With an NTA configured for it the name is "covered", so EDE 33 is emitted even
        though the NTA is not what made the answer insecure."""
        msg = dns.message.make_query("node1.insecure.example.", dns.rdatatype.A)
        msg.flags = dns.flags.from_text("AD RD")
        msg.use_edns(edns=0, ednsflags=dns.flags.edns_from_text("DO"))

        res = self.sendUDPQuery(msg)
        self.assertMessageHasFlags(res, ["QR", "RA", "RD"], ["DO"])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(self.getEDE(res), extendederrors.ExtendedErrorOption(33, b""))


class NTAExtendedErrorDisabledTest(RecursorTest):
    _confdir = "NTAExtendedErrorDisabled"
    _auth_zones = RecursorTest._default_auth_zones

    _config_template = """dnssec=validate
nta-extended-error=no"""
    _lua_config_file = """addNTA("bogus.example", "Negative Trust Anchor for testing")"""

    def testNTAWithFeatureDisabledHasNoEDE(self):
        """With nta-extended-error=no the NTA still works (Insecure, no AD) but no EDE 33
        is attached."""
        msg = dns.message.make_query("ted.bogus.example.", dns.rdatatype.A)
        msg.flags = dns.flags.from_text("AD RD")
        msg.use_edns(edns=0, ednsflags=dns.flags.edns_from_text("DO"))

        res = self.sendUDPQuery(msg)
        self.assertMessageHasFlags(res, ["QR", "RA", "RD"], ["DO"])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertIsNone(self.getEDE(res))
