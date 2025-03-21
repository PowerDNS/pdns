import dns
import os
from recursortests import RecursorTest

class ProxyByTableTest(RecursorTest):
    """
    This test makes sure that we correctly use the proxy-mapped address during the ACL check
    """
    _confdir = 'ProxyByTable'
    _auth_zones = RecursorTest._default_auth_zones

    _config_template = """dnssec=validate
    auth-zones=authzone.example=configs/%s/authzone.zone
    allow-from=3.4.5.0/24
    """ % _confdir

    _lua_config_file = """
    addProxyMapping("127.0.0.0/24", "3.4.5.6:99")
    """

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'authzone.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN authzone.example.
@ 3600 IN SOA {soa}
@ 3600 IN A 192.0.2.88
""".format(soa=cls._SOA))
        super(ProxyByTableTest, cls).generateRecursorConfig(confdir)


    def testA(self):
        expected = dns.rrset.from_text('ns.secure.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.9'.format(prefix=self._PREFIX))
        query = dns.message.make_query('ns.secure.example', 'A', want_dnssec=True)
        query.flags |= dns.flags.AD

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)

            self.assertMessageIsAuthenticated(res)
            self.assertRRsetInAnswer(res, expected)
            self.assertMatchingRRSIGInAnswer(res, expected)


