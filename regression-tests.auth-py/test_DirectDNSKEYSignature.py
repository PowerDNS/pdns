#!/usr/bin/env python

import dns
import os
import socket
from authtests import AuthTest


class TestDirectDNSKEYSignature(AuthTest):
    _config_template = """
    launch={backend}
    direct-dnskey=yes
    direct-dnskey-signature=yes
    """

    _zones = {
        "example.org": """
example.org.                 3600 IN SOA     {soa}
example.org.                 3600 IN NS      ns1.example.org.
example.org.                 3600 IN NS      ns2.example.org.
ns1.example.org.             3600 IN A       192.0.2.1
ns2.example.org.             3600 IN A       192.0.2.2
example.org.                 3600 IN DNSKEY  257 3 13 kRMX25/TJovOrsWq9Hv6QEFpzYsxItaOWPduFEwPz+5FM97SEHyCx+fc /XUN9gtktpXx45LAZpg/sFFEQH89og==
example.org.                 3600 IN DNSKEY  256 3 13 Fy1p5/TTniw9Ukwca3Fnjo4tQk9ZK5zSwX9HZhHC2Tta/+3OZ9+y/Noz G51m/vs/I3oo9OqF+znxOi69yuGZaQ==
example.org.                 3600 IN RRSIG   DNSKEY 13 2 3600 20250118211239 20241228221941 22273 example.org. 8HNifVnXhm5u+YDL8wWuJou5BWPzRYainXaP45qn2/yoPqBXSwhGFA2a kmh2Lqpj2D7qcs3KJ/QAR1QZ9CUAjw==
        """
    }

    @classmethod
    def setUpClass(cls):
        cls.setUpSockets()
        cls.startResponders()
        confdir = os.path.join("configs", cls._confdir)
        cls.createConfigDir(confdir)
        cls.generateAllAuthConfig(confdir)
        cls.startAuth(confdir, "0.0.0.0")
        print("Launching tests...")

    @classmethod
    def setUpSockets(cls):
        print("Setting up UDP socket...")
        cls._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cls._sock.settimeout(2.0)
        cls._sock.connect((cls._PREFIX + ".2", cls._authPort))

    def testDNSKEYQuery(self):
        """Test to verify DNSKEY and RRSIG records are served correctly"""
        query = dns.message.make_query("example.org", "DNSKEY", use_edns=True, want_dnssec=True)
        res = self.sendUDPQuery(query)

        # Ensure no error in response
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

        # Validate DNSKEY record
        dnskey_found = any(rrset.rdtype == dns.rdatatype.DNSKEY for rrset in res.answer)
        self.assertTrue(dnskey_found, "DNSKEY record not found in the answer section")

        # Validate RRSIG record for DNSKEY
        rrsig_found = any(
            rrset.rdtype == dns.rdatatype.RRSIG and rrset.covers == dns.rdatatype.DNSKEY and rrset[0].key_tag == 22273
            for rrset in res.answer
        )
        self.assertTrue(rrsig_found, "RRSIG for DNSKEY not found in the answer section")

    def testDNSKEYQueryWithoutDNSSEC(self):
        """Test to ensure no RRSIG records are returned without the DNSSEC flag"""
        query = dns.message.make_query("example.org", "DNSKEY", use_edns=True, want_dnssec=False)
        res = self.sendUDPQuery(query)

        # Ensure no error in response
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

        # Ensure DNSKEY is present but no RRSIG
        dnskey_found = any(rrset.rdtype == dns.rdatatype.DNSKEY for rrset in res.answer)
        self.assertTrue(dnskey_found, "DNSKEY record not found in the answer section")

        rrsig_found = any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in res.answer)
        self.assertFalse(rrsig_found, "RRSIG records found unexpectedly without DNSSEC flag")
