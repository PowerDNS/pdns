import dns
import os

from recursortests import RecursorTest

class DNS64RecursorTest(RecursorTest):

    _confdir = 'DNS64'
    _config_template = """
    auth-zones=example.dns64=configs/%s/example.dns64.zone
    auth-zones+=in-addr.arpa=configs/%s/in-addr.arpa.zone
    auth-zones+=ip6.arpa=configs/%s/ip6.arpa.zone

    dns64-prefix=64:ff9b::/96
    """ % (_confdir, _confdir, _confdir)

    @classmethod
    def setUpClass(cls):

        # we don't need all the auth stuff
        cls.setUpSockets()
        cls.startResponders()

        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)

        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

    @classmethod
    def tearDownClass(cls):
        cls.tearDownRecursor()

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'example.dns64.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN example.dns64
@ 3600 IN SOA {soa}
www 3600 IN A 192.0.2.42
www 3600 IN TXT "does exist"
aaaa 3600 IN AAAA 2001:db8::1
""".format(soa=cls._SOA))

        authzonepath = os.path.join(confdir, 'in-addr.arpa.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN in-addr.arpa
@ 3600 IN SOA {soa}
42.2.0.192 IN PTR www.example.dns64.
""".format(soa=cls._SOA))

        authzonepath = os.path.join(confdir, 'ip6.arpa.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN ip6.arpa
@ 3600 IN SOA {soa}
1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2 IN PTR aaaa.example.dns64.
""".format(soa=cls._SOA))

        super(DNS64RecursorTest, cls).generateRecursorConfig(confdir)

    # this type (A) exists for this name
    def testExistingA(self):
        qname = 'www.example.dns64.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.42')

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    # there is no A record, we should get a NODATA
    def testNonExistingA(self):
        qname = 'aaaa.example.dns64.'

        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEquals(len(res.answer), 0)

    # this type (AAAA) does not exist for this name but there is an A record, we should get a DNS64-wrapped AAAA
    def testNonExistingAAAA(self):
        qname = 'www.example.dns64.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'AAAA', '64:ff9b::c000:22a')

        query = dns.message.make_query(qname, 'AAAA', want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    # this type (AAAA) does not exist for this name and there is no A record either, we should get a NXDomain
    def testNonExistingAAAA(self):
        qname = 'nxd.example.dns64.'

        query = dns.message.make_query(qname, 'AAAA', want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)

    # there is an AAAA record, we should get it
    def testExistingAAAA(self):
        qname = 'aaaa.example.dns64.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'AAAA', '2001:db8::1')

        query = dns.message.make_query(qname, 'AAAA', want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    # there is a TXT record, we should get it
    def testExistingTXT(self):
        qname = 'www.example.dns64.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'TXT', '"does exist"')

        query = dns.message.make_query(qname, 'TXT', want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    # the PTR records for the DNS64 prefix should be generated
    def testNonExistingPTR(self):
        qname = 'a.2.2.0.0.0.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa.'
        expectedCNAME = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'CNAME', '42.2.0.192.in-addr.arpa.')
        expected = dns.rrset.from_text('42.2.0.192.in-addr.arpa.', 0, dns.rdataclass.IN, 'PTR', 'www.example.dns64.')

        query = dns.message.make_query(qname, 'PTR', want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            print(res)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expectedCNAME)
            self.assertRRsetInAnswer(res, expected)

    # but not for other prefixes
    def testExistingPTR(self):
        qname = '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.'
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'PTR', 'aaaa.example.dns64.')

        query = dns.message.make_query(qname, 'PTR', want_dnssec=True)
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)
