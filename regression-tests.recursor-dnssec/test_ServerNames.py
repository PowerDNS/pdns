import dns
from recursortests import RecursorTest


class ServerNamesTest(RecursorTest):
    """
    This tests all kinds naming things
    """

    _confdir = "ServerNames"
    _auth_zones = RecursorTest._default_auth_zones
    _servername = "awesome-pdns1.example.com"
    _versionbind = "Awesome!"
    _versionbind_expected = dns.rrset.from_text("version.bind.", 86400, "CH", "TXT", _versionbind)
    _idserver_expected = dns.rrset.from_text("id.server.", 86400, "CH", "TXT", _servername)

    _config_template = """
server-id=%s
version-string=%s
    """ % (_servername, _versionbind)

    def testVersionBindUDP(self):
        """
        Send a version.bind CH TXT query over UDP and look for the version string
        """
        query = dns.message.make_query("version.bind", "TXT", "CH", use_edns=False)
        response = self.sendUDPQuery(query)

        self.assertEqual(len(response.answer), 1)
        self.assertRRsetInAnswer(response, self._versionbind_expected)

    def testVersionBindTCP(self):
        """
        Send a version.bind CH TXT query over TCP and look for the version string
        """
        query = dns.message.make_query("version.bind", "TXT", "CH", use_edns=False)
        response = self.sendTCPQuery(query)

        self.assertEqual(len(response.answer), 1)
        self.assertRRsetInAnswer(response, self._versionbind_expected)

    def testVersionBindUDPEDNS(self):
        """
        Send a version.bind CH TXT query over UDP (with EDNS) and look for the version string
        """
        query = dns.message.make_query("version.bind", "TXT", "CH", use_edns=True)
        response = self.sendUDPQuery(query)

        self.assertEqual(len(response.answer), 1)
        self.assertRRsetInAnswer(response, self._versionbind_expected)

    def testVersionBindTCPEDNS(self):
        """
        Send a version.bind CH TXT query over TCP (with EDNS) and look for the version string
        """
        query = dns.message.make_query("version.bind", "TXT", "CH", use_edns=True)
        response = self.sendTCPQuery(query)

        self.assertEqual(len(response.answer), 1)
        self.assertRRsetInAnswer(response, self._versionbind_expected)

    def testIdServerUDP(self):
        """
        Send an id.server CH TXT query over UDP and look for the server id
        """
        query = dns.message.make_query("id.server", "TXT", "CH", use_edns=False)
        response = self.sendUDPQuery(query)

        self.assertEqual(len(response.answer), 1)
        self.assertRRsetInAnswer(response, self._idserver_expected)

    def testIdServerTCP(self):
        """
        Send an id.server CH TXT query over TCP and look for the server id
        """
        query = dns.message.make_query("id.server", "TXT", "CH", use_edns=False)
        response = self.sendTCPQuery(query)

        self.assertEqual(len(response.answer), 1)
        self.assertRRsetInAnswer(response, self._idserver_expected)

    def testIdServerUDPEDNS(self):
        """
        Send an id.server CH TXT query over UDP (with EDNS) and look for the server id
        """
        query = dns.message.make_query("id.server", "TXT", "CH", use_edns=True)
        response = self.sendUDPQuery(query)

        self.assertEqual(len(response.answer), 1)
        self.assertRRsetInAnswer(response, self._idserver_expected)

    def testIdServerTCPEDNS(self):
        """
        Send an id.server CH TXT query over TCP (with EDNS) and look for the server id
        """
        query = dns.message.make_query("id.server", "TXT", "CH", use_edns=True)
        response = self.sendTCPQuery(query)

        self.assertEqual(len(response.answer), 1)
        self.assertRRsetInAnswer(response, self._idserver_expected)

    def testNSIDUDP(self):
        """
        Send a .|NS query with NSID option
        """
        opts = [dns.edns.GenericOption(dns.edns.NSID, b"")]
        query = dns.message.make_query(".", "NS", "IN", use_edns=True, options=opts)
        response = self.sendUDPQuery(query)

        self.assertEqual(len(response.options), 1)
        if dns.version.MAJOR < 2 or (dns.version.MAJOR == 2 and dns.version.MINOR < 6):
            self.assertEqual(response.options[0].data, self._servername.encode("ascii"))
        else:
            self.assertEqual(response.options[0].to_text(), "NSID " + self._servername)

    def testNSIDTCP(self):
        """
        Send a .|NS query with NSID option
        """
        opts = [dns.edns.GenericOption(dns.edns.NSID, b"")]
        query = dns.message.make_query(".", "NS", "IN", use_edns=True, options=opts)
        response = self.sendTCPQuery(query)

        self.assertEqual(len(response.options), 1)
        if dns.version.MAJOR < 2 or (dns.version.MAJOR == 2 and dns.version.MINOR < 6):
            self.assertEqual(response.options[0].data, self._servername.encode("ascii"))
        else:
            self.assertEqual(response.options[0].to_text(), "NSID " + self._servername)
