#!/usr/bin/env python
import os

import dns
import dns.query
import dns.rcode
import dns.tsig
import dns.tsigkeyring
import dns.update

from authtests import AuthTest


class DNSUpdateLuaPolicyBase(AuthTest):
    _backend = "gsqlite3"

    _config_template_default = """
module-dir={PDNS_MODULE_DIR}
daemon=no
socket-dir={confdir}
cache-ttl=0
negquery-cache-ttl=0
query-cache-ttl=0
log-dns-queries=yes
log-dns-details=yes
loglevel=9
distributor-threads=1"""

    # Only allow ACME style TXT records to be updated
    _update_policy = """
function updatepolicy(input)
  local qname = input:getQName():toString()
  return input:getQType() == pdns.TXT and string.sub(qname, 1, 16) == "_acme-challenge."
end
"""

    _tsig_keys = {
        "allowed-key.": "QWxsb3dlZEtleVNlY3JldEZvclRlc3RpbmdQdXJwb3Nlcw==",
        "other-key.": "T3RoZXJLZXlTZWNyZXRGb3JUZXN0aW5nUHVycG9zZXMhIQ==",
    }

    @classmethod
    def generateAllAuthConfig(cls, confdir):
        super().generateAllAuthConfig(confdir)
        with open(os.path.join(confdir, "update-policy.lua"), "w") as policy:
            policy.write(cls._update_policy)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        for zone in ["allowed.example", "noacl.example", "tsig.example"]:
            os.system("$PDNSUTIL --config-dir=configs/auth zone create %s" % zone)
        for keyname, secret in cls._tsig_keys.items():
            os.system("$PDNSUTIL --config-dir=configs/auth tsigkey import %s hmac-sha256 %s" % (keyname, secret))
        os.system("$PDNSUTIL --config-dir=configs/auth metadata set allowed.example ALLOW-DNSUPDATE-FROM 127.0.0.0/8")
        os.system("$PDNSUTIL --config-dir=configs/auth metadata set tsig.example ALLOW-DNSUPDATE-FROM 127.0.0.0/8")
        os.system("$PDNSUTIL --config-dir=configs/auth metadata set tsig.example TSIG-ALLOW-DNSUPDATE allowed-key")

    def sendUpdate(self, zone, name, rdtype, content, keyname=None):
        if keyname:
            keyring = dns.tsigkeyring.from_text({keyname: self._tsig_keys[keyname]})
            update = dns.update.UpdateMessage(zone, keyring=keyring, keyname=keyname, keyalgorithm=dns.tsig.HMAC_SHA256)
        else:
            update = dns.update.UpdateMessage(zone)
        update.add(name, 3600, rdtype, content)
        res = dns.query.udp(update, self._PREFIX + ".1", port=self._authPort, timeout=2.0)
        return res.rcode()

    def checkUpdate(self, zone, name, rdtype, content, expectedRcode, keyname=None):
        rcode = self.sendUpdate(zone, name, rdtype, content, keyname)
        self.assertEqual(dns.rcode.to_text(rcode), dns.rcode.to_text(expectedRcode))

        query = dns.message.make_query(name, rdtype)
        res = self.sendUDPQuery(query)
        self.assertEqual(len(res.answer), 1 if expectedRcode == dns.rcode.NOERROR else 0)


class TestLuaPolicyWithoutBuiltinChecks(DNSUpdateLuaPolicyBase):
    # Without lua-dnsupdate-policy-builtin-checks, the Lua policy is the only
    # authorization method, so the settings below are expected to be ignored.
    _config_template = """
launch=gsqlite3
gsqlite3-database=configs/auth/powerdns.sqlite
gsqlite3-pragma-foreign-keys=yes
dnsupdate=yes
allow-dnsupdate-from=
dnsupdate-require-tsig=yes
lua-dnsupdate-policy-script=configs/auth/update-policy.lua
logging-structured
"""

    def testRefusedByLuaPolicy(self):
        self.checkUpdate("allowed.example", "host1.allowed.example.", "A", "192.0.2.1", dns.rcode.REFUSED)

    def testAllowDNSUpdateFromIgnored(self):
        self.checkUpdate("noacl.example", "_acme-challenge.test1.noacl.example.", "TXT", '"test1"', dns.rcode.NOERROR)

    def testTSIGAllowDNSUpdateIgnored(self):
        self.checkUpdate("tsig.example", "_acme-challenge.test2.tsig.example.", "TXT", '"test2"', dns.rcode.NOERROR)


class TestLuaPolicyWithBuiltinChecks(DNSUpdateLuaPolicyBase):
    _config_template = """
launch=gsqlite3
gsqlite3-database=configs/auth/powerdns.sqlite
gsqlite3-pragma-foreign-keys=yes
dnsupdate=yes
allow-dnsupdate-from=192.0.2.0/24
lua-dnsupdate-policy-script=configs/auth/update-policy.lua
lua-dnsupdate-policy-builtin-checks=yes
logging-structured
"""

    def testAllowedUpdate(self):
        self.checkUpdate(
            "allowed.example", "_acme-challenge.test3.allowed.example.", "TXT", '"test3"', dns.rcode.NOERROR
        )

    def testRefusedByLuaPolicy(self):
        self.checkUpdate("allowed.example", "host2.allowed.example.", "A", "192.0.2.2", dns.rcode.REFUSED)

    def testRefusedByAllowDNSUpdateFrom(self):
        self.checkUpdate("noacl.example", "_acme-challenge.test4.noacl.example.", "TXT", '"test4"', dns.rcode.REFUSED)

    def testRefusedByTSIGAllowDNSUpdateUnsigned(self):
        self.checkUpdate("tsig.example", "_acme-challenge.test5.tsig.example.", "TXT", '"test5"', dns.rcode.REFUSED)

    def testRefusedByTSIGAllowDNSUpdateWrongKey(self):
        self.checkUpdate(
            "tsig.example", "_acme-challenge.test6.tsig.example.", "TXT", '"test6"', dns.rcode.REFUSED, "other-key."
        )

    def testAllowedByTSIGAllowDNSUpdate(self):
        self.checkUpdate(
            "tsig.example", "_acme-challenge.test7.tsig.example.", "TXT", '"test7"', dns.rcode.NOERROR, "allowed-key."
        )


class TestLuaPolicyWithBuiltinChecksRequireTSIG(DNSUpdateLuaPolicyBase):
    _config_template = """
launch=gsqlite3
gsqlite3-database=configs/auth/powerdns.sqlite
gsqlite3-pragma-foreign-keys=yes
dnsupdate=yes
allow-dnsupdate-from=127.0.0.0/8
dnsupdate-require-tsig=yes
lua-dnsupdate-policy-script=configs/auth/update-policy.lua
lua-dnsupdate-policy-builtin-checks=yes
logging-structured
"""

    def testRefusedByRequireTSIG(self):
        self.checkUpdate("noacl.example", "_acme-challenge.test8.noacl.example.", "TXT", '"test8"', dns.rcode.REFUSED)

    def testAllowedWithTSIG(self):
        self.checkUpdate(
            "tsig.example", "_acme-challenge.test9.tsig.example.", "TXT", '"test9"', dns.rcode.NOERROR, "allowed-key."
        )

    def testRefusedByLuaPolicyWithTSIG(self):
        self.checkUpdate("tsig.example", "host3.tsig.example.", "A", "192.0.2.3", dns.rcode.REFUSED, "allowed-key.")
