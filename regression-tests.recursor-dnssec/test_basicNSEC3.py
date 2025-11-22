from __future__ import print_function
from basicDNSSEC import BasicDNSSEC
import os
import subprocess


class basicNSEC3Test(BasicDNSSEC):
    __test__ = True
    _confdir = "basicNSEC3"
    _auth_zones = BasicDNSSEC._auth_zones

    @classmethod
    def secureZone(cls, confdir, zonename, key=None):
        zone = "." if zonename == "ROOT" else zonename
        if not key:
            pdnsutilCmd = [os.environ["PDNSUTIL"], "--config-dir=%s" % confdir, "secure-zone", zone]
        else:
            keyfile = os.path.join(confdir, "dnssec.key")
            with open(keyfile, "w") as fdKeyfile:
                fdKeyfile.write(key)

            pdnsutilCmd = [
                os.environ["PDNSUTIL"],
                "--config-dir=%s" % confdir,
                "import-zone-key",
                zone,
                keyfile,
                "active",
                "ksk",
            ]

        print(" ".join(pdnsutilCmd))
        try:
            subprocess.check_output(pdnsutilCmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise AssertionError("%s failed (%d): %s" % (pdnsutilCmd, e.returncode, e.output))

        params = "1 0 50 AABBCCDDEEFF112233"

        if zone == "optout.example":
            params = "1 1 50 AABBCCDDEEFF112233"

        pdnsutilCmd = [os.environ["PDNSUTIL"], "--config-dir=%s" % confdir, "set-nsec3", zone, params]

        print(" ".join(pdnsutilCmd))
        try:
            subprocess.check_output(pdnsutilCmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise AssertionError("%s failed (%d): %s" % (pdnsutilCmd, e.returncode, e.output))
