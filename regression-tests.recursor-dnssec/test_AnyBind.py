import dns
import os
import socket
from recursortests import RecursorTest

class AnyBindTest(RecursorTest):
    _confdir = 'AnyBind'
    _auth_zones = RecursorTest._default_auth_zones

    _config_template = """dnssec=validate
    local-address=0.0.0.0
auth-zones=authzone.example=configs/%s/authzone.zone""" % _confdir

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'authzone.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN authzone.example.
@ 3600 IN SOA {soa}
@ 3600 IN A 192.0.2.88
""".format(soa=cls._SOA))
        super(AnyBindTest, cls).generateRecursorConfig(confdir)

    @classmethod
    def setUpSockets(cls):
        print("Setting up UDP socket..")
        cls._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cls._sock.settimeout(2.0)
        cls._sock.connect(("127.0.0.2", cls._recursorPort))

    def testA(self):
        """Test to see if we get a reply from 127.0.0.2 if rec is bound to ANY address"""
        expected = dns.rrset.from_text('ns.secure.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.9'.format(prefix=self._PREFIX))
        query = dns.message.make_query('ns.secure.example', 'A', want_dnssec=True)
        query.flags |= dns.flags.AD

        res = self.sendUDPQuery(query)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)

