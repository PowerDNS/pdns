#!/usr/bin/env python

import dns
import os
import socket

import paddingoption

from authtests import AuthTest

class AuthEDNSPaddingTest(AuthTest):
    _config_template = """
launch=bind
"""

    _zones = {
        'example.org': """
example.org.                 3600 IN SOA  {soa}
example.org.                 3600 IN NS   ns1.example.org.
example.org.                 3600 IN NS   ns2.example.org.
ns1.example.org.             3600 IN A    192.0.2.10
ns2.example.org.             3600 IN A    192.0.2.11

www.example.org.             3600 IN A    192.0.2.5
        """,
    }

    @classmethod
    def setUpClass(cls):
        cls.setUpSockets()

        cls.startResponders()

        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)

        cls.generateAllAuthConfig(confdir)
        cls.startAuth(confdir, "0.0.0.0")

        print("Launching tests..")

    @classmethod
    def setUpSockets(cls):
         print("Setting up UDP socket..")
         cls._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
         cls._sock.settimeout(2.0)
         cls._sock.connect((cls._PREFIX + ".2", cls._authPort))

    def checkPadding(self, message):
        self.assertEqual(message.edns, 0)
        self.assertEqual(len(message.options), 1)
        for option in message.options:
            self.assertEqual(option.otype, 12)

    def checkNoEDNS(self, message):
        self.assertEqual(message.edns, -1)

class TestEDNSPadding(AuthEDNSPaddingTest):

    def testQueryWithPadding(self):
        name = 'www.example.org.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.5')
        po = paddingoption.PaddingOption(64)
        query = dns.message.make_query(name, 'A', options=[po])
        res = self.sendUDPQuery(query)
        self.checkPadding(res)
        self.assertRRsetInAnswer(res, expected)

    def testQueryWithoutPadding(self):
        name = 'www.example.org.'
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.5')
        query = dns.message.make_query(name, 'A')
        res = self.sendUDPQuery(query)
        self.checkNoEDNS(res)
        self.assertRRsetInAnswer(res, expected)
