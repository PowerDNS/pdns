import clientsubnetoption
import dns
import os
import socket
import struct
import subprocess
import threading
import time
import unittest

from authtests import AuthTest
from proxyprotocol import ProxyProtocol


class TestProxyProtocolLuaRecords(AuthTest):
    _config_template = """
launch={backend}
any-to-tcp=no
proxy-protocol-from=127.0.0.1
enable-lua-records
edns-subnet-processing=yes
"""

    _zones = {
        "example.org": """
example.org.                 3600 IN SOA  {soa}
example.org.                 3600 IN NS   ns1.example.org.
example.org.                 3600 IN NS   ns2.example.org.
ns1.example.org.             3600 IN A    {prefix}.10
ns2.example.org.             3600 IN A    {prefix}.11

myip.example.org.            3600 IN LUA  TXT     "who:toString()..'/'..bestwho:toString()"
        """
    }

    @classmethod
    def setUpClass(cls):
        super(TestProxyProtocolLuaRecords, cls).setUpClass()

    def testWhoAmI(self):
        """
        See if LUA who picks up the inner address from the PROXY protocol
        """

        for testWithECS in True, False:
            # first test with an unproxied query - should get ignored

            options = []
            expectedText = "192.0.2.1/192.0.2.1"

            if testWithECS:
                ecso = clientsubnetoption.ClientSubnetOption("192.0.2.5", 32)
                options.append(ecso)
                expectedText = "192.0.2.1/192.0.2.5"

            query = dns.message.make_query(
                "myip.example.org", "TXT", "IN", use_edns=testWithECS, options=options, payload=512
            )

            res = self.sendUDPQuery(query)

            self.assertEqual(res, None)  # query was ignored correctly

            # now send a proxied query
            queryPayload = query.to_wire()
            ppPayload = ProxyProtocol.getPayload(False, False, False, "192.0.2.1", "10.1.2.3", 12345, 53, [])
            payload = ppPayload + queryPayload

            # UDP
            self._sock.settimeout(2.0)

            try:
                self._sock.send(payload)
                data = self._sock.recv(4096)
            except socket.timeout:
                data = None
            finally:
                self._sock.settimeout(None)

            res = None
            if data:
                res = dns.message.from_wire(data)

            expected = [dns.rrset.from_text("myip.example.org.", 0, dns.rdataclass.IN, "TXT", expectedText)]
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(res.answer, expected)

            # TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect(("127.0.0.1", self._authPort))

            try:
                sock.send(ppPayload)
                sock.send(struct.pack("!H", len(queryPayload)))
                sock.send(queryPayload)
                data = sock.recv(2)
                if data:
                    (datalen,) = struct.unpack("!H", data)
                    data = sock.recv(datalen)
            except socket.timeout as e:
                print("Timeout: %s" % (str(e)))
                data = None
            except socket.error as e:
                print("Network error: %s" % (str(e)))
                data = None
            finally:
                sock.close()

            res = None
            if data:
                res = dns.message.from_wire(data)

            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(res.answer, expected)


class TestProxyProtocolNOTIFY(AuthTest):
    _config_template = """
launch={backend}
any-to-tcp=no
proxy-protocol-from=127.0.0.1
secondary
"""

    _secondary_zones = {"example.org": "192.0.2.1", "example.com": "192.0.2.2"}

    _zones = {}

    @classmethod
    def generateAuthZone(cls, confdir, zonename, zonecontent):
        try:
            os.unlink(os.path.join(confdir, "%s.zone" % zonename))
        except Exception:
            pass

    @classmethod
    def generateAuthConfig(cls, confdir):
        super(TestProxyProtocolNOTIFY, cls).generateAuthConfig(confdir)
        if cls._backend == "lmdb":
            for zonename in cls._secondary_zones:
                pdnsutilCmd = [
                    os.environ["PDNSUTIL"],
                    "--config-dir=%s" % confdir,
                    "create-secondary-zone",
                    zonename,
                    cls._secondary_zones[zonename],
                ]

                print(" ".join(pdnsutilCmd))
                try:
                    subprocess.check_output(pdnsutilCmd, stderr=subprocess.STDOUT)
                except subprocess.CalledProcessError as e:
                    raise AssertionError("%s failed (%d): %s" % (pdnsutilCmd, e.returncode, e.output))

    @classmethod
    def generateAuthNamedConf(cls, confdir, zones):
        with open(os.path.join(confdir, "named.conf"), "w") as namedconf:
            namedconf.write(
                """
options {
    directory "%s";
};"""
                % confdir
            )
            for zonename in cls._secondary_zones:
                zone = "." if zonename == "ROOT" else zonename

                namedconf.write(
                    """
        zone "%s" {
            type secondary;
            file "%s.zone";
            masters { %s; };
        };"""
                    % (zone, zonename, cls._secondary_zones[zone])
                )

    @classmethod
    def setUpClass(cls):
        super(TestProxyProtocolNOTIFY, cls).setUpClass()

    def testNOTIFY(self):
        """
        Check that NOTIFY is properly accepted/rejected based on the PROXY header inner address
        """

        query = dns.message.make_query("example.org", "SOA")
        query.set_opcode(dns.opcode.NOTIFY)

        queryPayload = query.to_wire()

        for task in ("192.0.2.1", dns.rcode.NOERROR), ("192.0.2.2", dns.rcode.REFUSED):
            ip, expectedrcode = task

            ppPayload = ProxyProtocol.getPayload(False, False, False, ip, "10.1.2.3", 12345, 53, [])
            payload = ppPayload + queryPayload

            self._sock.settimeout(2.0)

            try:
                self._sock.send(payload)
                data = self._sock.recv(4096)
            except socket.timeout:
                data = None
            finally:
                self._sock.settimeout(None)

            res = None
            if data:
                res = dns.message.from_wire(data)

            self.assertRcodeEqual(res, expectedrcode)


class TestProxyProtocolAXFRACL(AuthTest):
    _config_template = """
launch={backend}
any-to-tcp=no
proxy-protocol-from=127.0.0.1
allow-axfr-ips=192.0.2.53
"""

    @classmethod
    def setUpClass(cls):
        super(TestProxyProtocolAXFRACL, cls).setUpClass()

    def testAXFR(self):
        """
        Check that AXFR is properly accepted/rejected based on the PROXY header inner address
        """

        query = dns.message.make_query("example.org", "AXFR")

        queryPayload = query.to_wire()

        for task in (
            ("192.0.2.1", dns.rcode.NOTAUTH),
            ("127.0.0.1", dns.rcode.NOTAUTH),
            ("192.0.2.53", dns.rcode.NOERROR),
        ):
            ip, expectedrcode = task

            ppPayload = ProxyProtocol.getPayload(False, True, False, ip, "10.1.2.3", 12345, 53, [])

            # TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect(("127.0.0.1", self._authPort))

            try:
                sock.send(ppPayload)
                sock.send(struct.pack("!H", len(queryPayload)))
                sock.send(queryPayload)
                data = sock.recv(2)
                if data:
                    (datalen,) = struct.unpack("!H", data)
                    data = sock.recv(datalen)
            except socket.timeout as e:
                print("Timeout: %s" % (str(e)))
                data = None
            except socket.error as e:
                print("Network error: %s" % (str(e)))
                data = None
            finally:
                sock.close()

            res = None
            if data:
                res = dns.message.from_wire(data)

            self.assertRcodeEqual(res, expectedrcode)
