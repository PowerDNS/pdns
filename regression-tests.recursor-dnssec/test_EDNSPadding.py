import dns
import os
import socket

import paddingoption

from recursortests import RecursorTest

class TestRecursorEDNSPadding(RecursorTest):

    @classmethod
    def setUpClass(cls):
        cls.setUpSockets()

        cls.startResponders()

        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)
        cls.generateAllAuthConfig(confdir)

        # we only need these auths and this cuts the needed time in half
        if cls._auth_zones:
            for auth_suffix in ['8', '9', '10']:
                authconfdir = os.path.join(confdir, 'auth-%s' % auth_suffix)
                ipaddress = cls._PREFIX + '.' + auth_suffix
                cls.startAuth(authconfdir, ipaddress)

        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

        print("Launching tests..")

    def checkPadding(self, message, numberOfBytes=None):
      self.assertEqual(message.edns, 0)
      self.assertEquals(len(message.options), 1)
      for option in message.options:
          self.assertEquals(option.otype, 12)
          if numberOfBytes:
              self.assertEquals(option.olen, numberOfBytes)

    def checkNoPadding(self, message):
      self.assertEqual(message.edns, 0)
      self.assertEquals(len(message.options), 0)

    def sendUDPQueryOverIPv6(self, query, timeout=2.0):
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      sock.settimeout(2.0)
      sock.connect(("127.0.0.1", self._recursorPort))

      if timeout:
        sock.settimeout(timeout)

      try:
        sock.send(query.to_wire())
        data = sock.recv(4096)
      except socket.timeout:
        data = None
      finally:
        if timeout:
          sock.settimeout(None)

      message = None
      if data:
        message = dns.message.from_wire(data)
      return message

class PaddingDefaultTest(TestRecursorEDNSPadding):

    _confdir = 'PaddingDefault'

    def testQueryWithPadding(self):
        name = 'secure.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.17')
        po = paddingoption.PaddingOption(64)
        query = dns.message.make_query(name, 'A', want_dnssec=True, options=[po])
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkNoPadding(res)
        self.assertRRsetInAnswer(res, expected)

    def testqueryWithoutPadding(self):
        name = 'secure.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.17')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkNoPadding(res)
        self.assertRRsetInAnswer(res, expected)

class PaddingAllowedAlwaysTest(TestRecursorEDNSPadding):

    _confdir = 'PaddingAlways'
    _config_template = """edns-padding-from=127.0.0.1
edns-padding-mode=always
edns-padding-tag=7830
    """

    def testQueryWithPadding(self):
        name = 'secure.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.17')
        po = paddingoption.PaddingOption(64)
        query = dns.message.make_query(name, 'A', want_dnssec=True, options=[po])
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkPadding(res)
        self.assertRRsetInAnswer(res, expected)

    def testqueryWithoutPadding(self):
        name = 'secure.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.17')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkPadding(res)
        self.assertRRsetInAnswer(res, expected)

class PaddingAllowedWhenPaddedTest(TestRecursorEDNSPadding):

    _confdir = 'PaddingWhenPadded'
    _config_template = """edns-padding-from=127.0.0.1
edns-padding-mode=padded-queries-only
edns-padding-tag=7830
    """

    def testQueryWithPadding(self):
        name = 'secure.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.17')
        po = paddingoption.PaddingOption(64)
        query = dns.message.make_query(name, 'A', want_dnssec=True, options=[po])
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkPadding(res)
        self.assertRRsetInAnswer(res, expected)

    def testqueryWithoutPadding(self):
        name = 'secure.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.17')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkNoPadding(res)
        self.assertRRsetInAnswer(res, expected)

class PaddingAllowedAlwaysSameTagTest(TestRecursorEDNSPadding):

    # we use the default tag (0) for padded responses, which will cause
    # the same packet cache entry (with padding ) to be returned to a client
    # not allowed by the edns-padding-from list
    _confdir = 'PaddingAlwaysSameTag'
    _config_template = """edns-padding-from=127.0.0.1
edns-padding-mode=always
edns-padding-tag=0
local-address=127.0.0.1, ::1
    """

    def testQueryWithPadding(self):
        name = 'secure.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.17')
        po = paddingoption.PaddingOption(64)
        query = dns.message.make_query(name, 'A', want_dnssec=True, options=[po])
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkPadding(res)
        self.assertRRsetInAnswer(res, expected)

        res = self.sendUDPQueryOverIPv6(query)
        self.checkPadding(res)
        self.assertRRsetInAnswer(res, expected)

    def testqueryWithoutPadding(self):
        name = 'secure.example.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.17')
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkPadding(res)
        self.assertRRsetInAnswer(res, expected)

        res = self.sendUDPQueryOverIPv6(query)
        self.checkPadding(res)
        self.assertRRsetInAnswer(res, expected)
