import dns
import os
import subprocess
import time

from recursortests import RecursorTest


class LockedCacheTest(RecursorTest):
    """
    Test that a locked cached entry is *not* updated by the same additional encountered in a second query
    """

    _confdir = "LockedCache"
    _auth_zones = RecursorTest._default_auth_zones

    _config_template = """
    dnssec=validate
    record-cache-locked-ttl-perc=100
    """

    def getCacheTTL(self):
        rec_controlCmd = [os.environ["RECCONTROL"], "--config-dir=%s" % "configs/" + self._confdir, "dump-cache", "-"]
        try:
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT, text=True)
            for i in ret.splitlines():
                pieces = i.split(" ")
                print(pieces)
                if pieces[0] == "mx1.secure.example." and pieces[4] == "A":
                    return pieces[2]
            raise AssertionError("Cache Line not found")
        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

    def testMX(self):
        expected1 = dns.rrset.from_text(
            "secure.example.", 0, dns.rdataclass.IN, "MX", "10 mx1.secure.example.", "20 mx2.secure.example."
        )
        expected2 = dns.rrset.from_text(
            "sub.secure.example.", 0, dns.rdataclass.IN, "MX", "10 mx1.secure.example.", "20 mx2.secure.example."
        )
        query1 = dns.message.make_query("secure.example", "MX", want_dnssec=True)
        query1.flags |= dns.flags.AD
        query2 = dns.message.make_query("sub.secure.example", "MX", want_dnssec=True)
        query2.flags |= dns.flags.AD

        res = self.sendUDPQuery(query1)
        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected1)
        self.assertMatchingRRSIGInAnswer(res, expected1)
        ttl1 = self.getCacheTTL()
        time.sleep(2)
        res = self.sendUDPQuery(query2)
        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected2)
        self.assertMatchingRRSIGInAnswer(res, expected2)
        ttl2 = self.getCacheTTL()
        self.assertGreater(ttl1, ttl2)


class NotLockedCacheTest(RecursorTest):
    """
    Test that a not locked cached entry *is* updated by the same additional encountered in a second query
    """

    _confdir = "NotLockedCache"
    _auth_zones = RecursorTest._default_auth_zones

    _config_template = """
    dnssec=validate
    """

    def getCacheTTL(self):
        rec_controlCmd = [os.environ["RECCONTROL"], "--config-dir=%s" % "configs/" + self._confdir, "dump-cache", "-"]
        try:
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT, text=True)
            for i in ret.splitlines():
                pieces = i.split(" ")
                print(pieces)
                if pieces[0] == "mx1.secure.example." and pieces[4] == "A":
                    return int(pieces[2])
            return -1

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

    def testMX(self):
        expected1 = dns.rrset.from_text(
            "secure.example.", 0, dns.rdataclass.IN, "MX", "10 mx1.secure.example.", "20 mx2.secure.example."
        )
        expected2 = dns.rrset.from_text(
            "sub.secure.example.", 0, dns.rdataclass.IN, "MX", "10 mx1.secure.example.", "20 mx2.secure.example."
        )
        query1 = dns.message.make_query("secure.example", "MX", want_dnssec=True)
        query1.flags |= dns.flags.AD
        query2 = dns.message.make_query("sub.secure.example", "MX", want_dnssec=True)
        query2.flags |= dns.flags.AD

        res = self.sendUDPQuery(query1)
        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected1)
        self.assertMatchingRRSIGInAnswer(res, expected1)
        ttl1 = self.getCacheTTL()
        time.sleep(2)
        res = self.sendUDPQuery(query2)
        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected2)
        self.assertMatchingRRSIGInAnswer(res, expected2)
        ttl2 = self.getCacheTTL()
        self.assertAlmostEqual(ttl1, ttl2, delta=1)
