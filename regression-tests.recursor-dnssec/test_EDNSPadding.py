import dns

from recursortests import RecursorTest


class EDNSPaddingBase(RecursorTest):
    """
    These tests are designed to check if we correctly respond to queries with
    ENDS PADDING options
    """
    _confdir = 'EDNSPadding'

    _auth_zones = {}


class EDNSPaddingTestDisabled(EDNSPaddingBase):
    _confdir = 'EDNSPaddingDisabled'

    _config_template = """
edns-padding=%s
edns-padding-max-bytes=%i
""" % ('no', 512)

    def testNoPaddinginQuery(self):
        query = dns.message.make_query('version.bind.', 'TXT', 'CH',
                                       use_edns=0, payload=4096)
        response = self.sendUDPQuery(query)
        self.assertRcodeEqual(response, dns.rcode.NOERROR)
        self.assertEqual(response.options, ())

    def testPaddinginQuery(self):
        opt = dns.edns.GenericOption(dns.edns.PADDING, 20 * '\0')
        query = dns.message.make_query('version.bind.', 'TXT', 'CH',
                                       use_edns=0, payload=4096, options=[opt])
        response = self.sendUDPQuery(query)
        self.assertRcodeEqual(response, dns.rcode.NOERROR)
        self.assertEqual(response.options, ())


class EDNSPaddingTestEnabled(EDNSPaddingBase):
    _confdir = 'EDNSPaddingEnabled'

    _config_template = """
edns-padding=%s
edns-padding-max-bytes=%i
""" % ('yes', 512)

    def testNoPaddinginQuery(self):
        query = dns.message.make_query('version.bind.', 'TXT', 'CH',
                                       use_edns=0, payload=4096)
        response = self.sendUDPQuery(query)
        self.assertRcodeEqual(response, dns.rcode.NOERROR)
        self.assertEqual(response.options, ())

    def testPaddinginQuery(self):
        opt = dns.edns.GenericOption(dns.edns.PADDING, 20 * '\0')
        query = dns.message.make_query('version.bind.', 'TXT', 'CH',
                                       use_edns=0, payload=4096, options=[opt])
        response = self.sendUDPQuery(query)
        self.assertRcodeEqual(response, dns.rcode.NOERROR)
        self.assertEqual(len(response.options), 1)
        self.assertEqual(response.options[0],
                         dns.edns.GenericOption(dns.edns.PADDING, 512 * '\0'))

    def testPaddingInQueryWithTooSmallBufsize(self):
        opt = dns.edns.GenericOption(dns.edns.PADDING, 20 * '\0')
        query = dns.message.make_query('version.bind.', 'TXT', 'CH',
                                       use_edns=0, payload=512, options=[opt])
        response = self.sendUDPQuery(query)
        self.assertRcodeEqual(response, dns.rcode.NOERROR)
        self.assertEqual(len(response.options), 1)
        self.assertEqual(response.options[0],
                         dns.edns.GenericOption(dns.edns.PADDING, 326 * '\0'))
