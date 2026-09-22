import os
import subprocess

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype

from recursortests import RecursorTest


class LocallyHostedTest(RecursorTest):
    _confdir = "LocallyHosted"
    _auth_zones = RecursorTest._default_auth_zones

    def testQueryWithNSNamesInArpa(self):
        """Do a query for a name under a bogus zone with nameservers in in-addr.arpa
        in the delegation. This should yield a SERVFAIL"""

        msg = dns.message.make_query("a.bad-auth-with-fake-1918-ns.secure.example.", dns.rdatatype.A)
        msg.flags = dns.flags.from_text("RD")
        msg.use_edns(edns=0, ednsflags=dns.flags.edns_from_text("DO"))

        res = self.sendUDPQuery(msg)

        if res.rcode != dns.rcode.SERVFAIL:
            # we *may* have hit the correct nameserver on the first try.
            # Wipe the cache and try again
            rec_controlCmd = [os.environ["RECCONTROL"], f"--config-dir=configs/{self._confdir}", "wipe-cache", "example$"]
            try:
                subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                print(e.output)
                raise

            res = self.sendUDPQuery(msg)

        print(res)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.assertMessageHasFlags(res, ["QR", "RA", "RD"], ["DO"])
