import dns
import os
import subprocess
from recursortests import RecursorTest

class testNamedForward(RecursorTest):
    """
    This is forwarding test using a name as target
    """

    _confdir = 'NamedForward'
    _config_template = """
dnssec=validate
forward-zones-recurse=.=dns.quad9.net
system-resolver-ttl=10
    """

    @classmethod
    def setUpClass(cls):

        # we don't need all the auth stuff
        cls.setUpSockets()

        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)

        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

    def testA(self):
        expected = dns.rrset.from_text('dns.google.', 0, dns.rdataclass.IN, 'A', '8.8.8.8', '8.8.4.4')
        query = dns.message.make_query('dns.google', 'A', want_dnssec=True)
        query.flags |= dns.flags.AD

        res = self.sendUDPQuery(query)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)
