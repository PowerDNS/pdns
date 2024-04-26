import dns
import os
from recursortests import RecursorTest

class testRDNotAllowed(RecursorTest):
    _confdir = 'RDFlagNotAllowed'

    _config_template = """
"""
    def testRD0(self):
        query = dns.message.make_query('ns.secure.example', 'A', want_dnssec=True)
        query.flags |= dns.flags.AD
        query.flags &= ~dns.flags.RD

        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.REFUSED)
        self.assertAnswerEmpty(res)

class testRDAllowed(RecursorTest):
    _confdir = 'RDFlagAllowed'

    _config_template = """
    disable-packetcache=yes
    allow-no-rd=yes
"""
    def testRD0(self):
        expected = dns.rrset.from_text('ns.secure.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.9'.format(prefix=self._PREFIX))
        query = dns.message.make_query('ns.secure.example', 'A', want_dnssec=True)
        query.flags |= dns.flags.AD
        query.flags &= ~dns.flags.RD

        # First time empty answer
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnswerEmpty(res)

        # Second time with RD=1 fills the record cache
        query.flags |= dns.flags.RD

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)

        # Third time with RD=0 retrieves record cache content
        query.flags &= ~dns.flags.RD

        res = self.sendUDPQuery(query)
        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)
