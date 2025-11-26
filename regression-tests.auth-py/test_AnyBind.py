#!/usr/bin/env python
import dns
import os
import socket

from authtests import AuthTest


class TestBindAny(AuthTest):
    _config_template = """
launch={backend}
"""

    _zones = {
        "example.org": """
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

        confdir = os.path.join("configs", cls._confdir)
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

    def testA(self):
        """Test to see if we get a reply from 127.0.0.2 if auth is bound to ANY address"""
        query = dns.message.make_query("www.example.org", "A")
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, 0)
