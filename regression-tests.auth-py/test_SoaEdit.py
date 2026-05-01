#!/usr/bin/env python

import collections
import dns
import os
import socket
import subprocess
import time
from authtests import AuthTest


class TestSoaEditSpreadBase(AuthTest):
    # 1.example.org hashes to 0.860233, or '8 seconds' under a 10 seconds spread
    # 2.example.org hashes to 0.121543, or '1 second' under a 10 second spread
    _zones = {
        "1.example.org": """
1.example.org.                 3600 IN SOA     {soa}
1.example.org.                 3600 IN NS      ns1.1.example.org.
1.example.org.                 3600 IN NS      ns2.1.example.org.
ns1.1.example.org.             3600 IN A       192.0.2.1
ns2.1.example.org.             3600 IN A       192.0.2.2
        """,
        "2.example.org": """
2.example.org.                 3600 IN SOA     {soa}
2.example.org.                 3600 IN NS      ns1.2.example.org.
2.example.org.                 3600 IN NS      ns2.2.example.org.
ns1.2.example.org.             3600 IN A       192.0.2.1
ns2.2.example.org.             3600 IN A       192.0.2.2
        """,
    }

    _zone_keys = {
        "1.example.org": """
Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: Lt0v0Gol3pRUFM7fDdcy0IWN0O/MnEmVPA+VylL8Y4U=
        """,
        "2.example.org": """
Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: Lt0v0Gol3pRUFM7fDdcy0IWN0O/MnEmVPA+VylL8Y4U=
        """,
    }

    _auth_env = {"LD_PRELOAD": os.environ.get("LIBFAKETIME"), "FAKETIME": "@2025-12-25 00:00:00", "TZ": "UTC"}

    def testSOAQuery(self):
        """Test to verify SOA serials are served correctly"""

        serials = collections.defaultdict(list)
        done = False

        for i in range(15):
            for j in [1, 2]:
                query = dns.message.make_query(f"{j}.example.org", "SOA", use_edns=True)
                res = self.sendUDPQuery(query)

                # Ensure no error in response
                self.assertRcodeEqual(res, dns.rcode.NOERROR)

                # Validate SOA record
                soa_found = any(rrset.rdtype == dns.rdatatype.SOA for rrset in res.answer)
                self.assertTrue(soa_found, "SOA record not found in the answer section")

                serials[j].append(res.answer[0][0].serial)
                self.assertListEqual(serials[j], sorted(serials[j]))

            if set(serials[1]) == self.expected and set(serials[2]) == self.expected:
                done = True
                break

            time.sleep(1)

        print(serials)

        self.assertTrue(done, serials)

    def testPdnsutilDelay(self):
        """Test to verify that the calculated delay is correct"""

        for i, delay in [(1, 8), (2, 1)]:
            pdnsutilCmd = [
                os.environ["PDNSUTIL"],
                "--config-dir=%s" % os.path.join("configs", self._confdir),
                "zone",
                "show",
                "-v",
                f"{i}.example.org",
            ]

            print(" ".join(pdnsutilCmd))
            try:
                output = subprocess.check_output(pdnsutilCmd, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                raise AssertionError("%s failed (%d): %s" % (pdnsutilCmd, e.returncode, e.output))

            print(output)

            spreadline = list(filter(lambda x: x.startswith(b"soa-edit spread delay: "), output.split(b"\n")))[0]
            sdelay = int(spreadline.split()[3])
            self.assertEqual(sdelay, delay)


class TestSoaEditSpreadInceptionIncrement(TestSoaEditSpreadBase):
    _config_template = """
launch={backend}
default-soa-edit=INCEPTION-INCREMENT
soa-edit-spread=10
    """

    expected = {2025121801, 2025122501}


class TestSoaEditSpreadIncrementWeeks(TestSoaEditSpreadBase):
    _config_template = """
launch={backend}
default-soa-edit=INCREMENT-WEEKS
soa-edit-spread=10
    """

    expected = {2921, 2922}


class TestSoaEditSpreadInceptionEpoch(TestSoaEditSpreadBase):
    _config_template = """
launch={backend}
default-soa-edit=INCEPTION-EPOCH
soa-edit-spread=10
    """

    expected = {2920*604800, 2921*604800}


# with thanks to https://adamj.eu/tech/2025/05/30/python-unittest-common-tests/
del TestSoaEditSpreadBase  # Hide base class from test discovery
