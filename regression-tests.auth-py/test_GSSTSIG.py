#!/usr/bin/env python
import os
import subprocess

from authtests import AuthTest


class GSSTSIGBase(AuthTest):
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

    _config_template = """
launch=gsqlite3
gsqlite3-database=configs/auth/powerdns.sqlite
gsqlite3-pragma-foreign-keys=yes
gsqlite3-dnssec=yes
enable-gss-tsig=yes
allow-dnsupdate-from=0.0.0.0/0
dnsupdate=yes
dnsupdate-require-tsig=no
"""
    _auth_env = {"KRB5_CONFIG": "./kerberos-client/krb5.conf", "KRB5_KTNAME": "./kerberos-client/kt.keytab"}

    @classmethod
    def secureZone(cls, confdir, zonename, key=None):
        # This particular test uses a sqlite-only configuration, unlike
        # all the other tests in that directory. Because of this, we
        # need to perform an explicit create-zone, otherwise import-zone-key
        # would fail.
        zone = "." if zonename == "ROOT" else zonename
        pdnsutilCmd = [os.environ["PDNSUTIL"], "--config-dir=%s" % confdir, "create-zone", zone]
        print(" ".join(pdnsutilCmd))
        try:
            subprocess.check_output(pdnsutilCmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise AssertionError("%s failed (%d): %s" % (pdnsutilCmd, e.returncode, e.output))
        super(GSSTSIGBase, cls).secureZone(confdir, zonename, key)

    @classmethod
    def setUpClass(cls):
        super(GSSTSIGBase, cls).setUpClass()
        os.system("$PDNSUTIL --config-dir=configs/auth delete-zone example.net")
        os.system("$PDNSUTIL --config-dir=configs/auth delete-zone noacceptor.net")
        os.system("$PDNSUTIL --config-dir=configs/auth delete-zone wrongacceptor.net")
        os.system("$PDNSUTIL --config-dir=configs/auth create-zone example.net")
        os.system("$PDNSUTIL --config-dir=configs/auth create-zone noacceptor.net")
        os.system("$PDNSUTIL --config-dir=configs/auth create-zone wrongacceptor.net")

        os.system(
            "$PDNSUTIL --config-dir=configs/auth replace-rrset example.net example.net SOA 3600 'ns1.example.net otto.example.net 2022010403 10800 3600 604800 3600'"
        )
        os.system(
            "$PDNSUTIL --config-dir=configs/auth replace-rrset noacceptor.net noacceptor.net SOA 3600 'ns1.noacceptor.net otto.example.net 2022010403 10800 3600 604800 3600'"
        )
        os.system(
            "$PDNSUTIL --config-dir=configs/auth replace-rrset wrongacceptor.net wrongacceptor.net SOA 3600 'ns1.wrongacceptor.net otto.example.net 2022010403 10800 3600 604800 3600'"
        )

        os.system(
            "$PDNSUTIL --config-dir=configs/auth set-meta example.net GSS-ACCEPTOR-PRINCIPAL DNS/ns1.example.net@EXAMPLE.COM"
        )
        os.system(
            "$PDNSUTIL --config-dir=configs/auth set-meta wrongacceptor.net GSS-ACCEPTOR-PRINCIPAL DNS/ns1.example.net@EXAMPLE.COM"
        )
        os.system("$PDNSUTIL --config-dir=configs/auth set-meta example.net TSIG-ALLOW-DNSUPDATE testuser1@EXAMPLE.COM")

    def kinit(self, user):
        ret = subprocess.run(["kinit", "-Vt", "./kerberos-client/kt.keytab", user], env=self._auth_env)
        self.assertEqual(ret.returncode, 0)

    def nsupdate(self, commands, expected=0, unauth=False):
        full = "server 127.0.0.1 %s\n" % self._authPort
        full += commands + "\nsend\nquit\n"
        if unauth:
            ret = subprocess.run(["nsupdate"], input=full, capture_output=True, text=True)
        else:
            ret = subprocess.run(["nsupdate", "-g"], input=full, env=self._auth_env, capture_output=True, text=True)
        self.assertEqual(ret.returncode, expected)

    def checkInDB(self, zone, record):
        ret = os.system("$PDNSUTIL --config-dir=configs/auth list-zone %s | egrep -q %s" % (zone, record))
        self.assertEqual(ret, 0)

    def checkNotInDB(self, zone, record):
        ret = os.system("$PDNSUTIL --config-dir=configs/auth list-zone %s | fgrep -q %s" % (zone, record))
        self.assertNotEqual(ret, 0)


class TestBasicGSSTSIG(GSSTSIGBase):
    _config_template = """
launch=gsqlite3
gsqlite3-database=configs/auth/powerdns.sqlite
gsqlite3-pragma-foreign-keys=yes
gsqlite3-dnssec=yes
enable-gss-tsig=yes
allow-dnsupdate-from=0.0.0.0/0
dnsupdate=yes
"""

    def testAllowedUpdate(self):
        self.checkNotInDB("example.net", "inserted1.example.net")
        self.kinit("testuser1")
        self.nsupdate("add inserted1.example.net 10 A 1.2.3.1")
        self.checkInDB("example.net", "^inserted1.example.net.*10.*IN.*A.*1.2.3.1$")

    def testDisallowedUpdate(self):
        self.kinit("testuser2")
        self.nsupdate("add inserted2.example.net 10 A 1.2.3.2", 2)
        self.checkNotInDB("example.net", "inserted2.example.net")

    def testNoAcceptor(self):
        self.kinit("testuser1")
        self.nsupdate("add inserted3.noacceptor.net 10 A 1.2.3.3", 2)
        self.checkNotInDB("noacceptor.net", "inserted3.noacceptor.net")

    def testWrongAcceptor(self):
        self.kinit("testuser1")
        self.nsupdate("add inserted4.wrongacceptor.net 10 A 1.2.3.4", 2)
        self.checkNotInDB("wrongacceptor.net", "inserted4.wrongacceptor.net")


class TestLuaGSSTSIG(GSSTSIGBase):
    _config_template = """
launch=gsqlite3
gsqlite3-database=configs/auth/powerdns.sqlite
gsqlite3-pragma-foreign-keys=yes
gsqlite3-dnssec=yes
enable-gss-tsig=yes
allow-dnsupdate-from=0.0.0.0/0
dnsupdate=yes
lua-dnsupdate-policy-script=kerberos-client/update-policy.lua
"""

    def testDisallowedByLuaUpdate(self):
        self.kinit("testuser1")
        self.nsupdate("add inserted10.example.net 10 A 1.2.3.10", 2)
        self.checkNotInDB("example.net", "inserted10.example.net")

    def testAllowedByLuaUpdate(self):
        self.kinit("testuser2")
        self.nsupdate("add inserted11.example.net 10 A 1.2.3.11")
        self.checkInDB("example.net", "^inserted11.example.net.*10.*IN.*A.*1.2.3.11$")

    def testNoAcceptor(self):
        self.kinit("testuser1")
        self.nsupdate("add inserted12.noacceptor.net 10 A 1.2.3.12", 2)
        self.checkNotInDB("noacceptor.net", "inserted12.noacceptor.net")

    def testWrongAcceptor(self):
        self.kinit("testuser1")
        self.nsupdate("add inserted13.wrongacceptor.net 10 A 1.2.3.13", 2)
        self.checkNotInDB("wrongacceptor.net", "inserted13.wrongacceptor.net")


class TestUnauthTSIG(GSSTSIGBase):
    _config_template = """
launch=gsqlite3
gsqlite3-database=configs/auth/powerdns.sqlite
gsqlite3-pragma-foreign-keys=yes
gsqlite3-dnssec=yes
enable-gss-tsig=no
allow-dnsupdate-from=0.0.0.0/0
dnsupdate=yes
"""

    def testNoAcceptor(self):
        self.checkNotInDB("noacceptor.net", "inserted20.noacceptor.net")
        self.nsupdate("add inserted20.noacceptor.net 10 A 1.2.3.3", 0, True)
        self.checkInDB("noacceptor.net", "inserted20.noacceptor.net")


class TestAuthTSIG(GSSTSIGBase):
    _config_template = """
launch=gsqlite3
gsqlite3-database=configs/auth/powerdns.sqlite
gsqlite3-pragma-foreign-keys=yes
gsqlite3-dnssec=yes
enable-gss-tsig=no
allow-dnsupdate-from=0.0.0.0/0
dnsupdate=yes
dnsupdate-require-tsig=yes
"""

    def testNoAcceptor(self):
        self.nsupdate("add inserted30.noacceptor.net 10 A 1.2.3.3", 2, True)
        self.checkNotInDB("noacceptor.net", "inserted30.noacceptor.net")


class TestBasicRequiredGSSTSIG(GSSTSIGBase):
    _config_template = """
launch=gsqlite3
gsqlite3-database=configs/auth/powerdns.sqlite
gsqlite3-pragma-foreign-keys=yes
gsqlite3-dnssec=yes
enable-gss-tsig=yes
allow-dnsupdate-from=0.0.0.0/0
dnsupdate=yes
dnsupdate-require-tsig=yes
"""

    def testAllowedUpdate(self):
        self.checkNotInDB("example.net", "inserted40.example.net")
        self.kinit("testuser1")
        self.nsupdate("add inserted40.example.net 10 A 1.2.3.1")
        self.checkInDB("example.net", "^inserted40.example.net.*10.*IN.*A.*1.2.3.1$")

    def testDisallowedUpdate(self):
        self.kinit("testuser2")
        self.nsupdate("add inserted41.example.net 10 A 1.2.3.2", 2)
        self.checkNotInDB("example.net", "inserted41.example.net")

    def testNoAcceptor(self):
        self.kinit("testuser1")
        self.nsupdate("add inserted42.noacceptor.net 10 A 1.2.3.3", 2)
        self.checkNotInDB("noacceptor.net", "inserted42.noacceptor.net")

    def testWrongAcceptor(self):
        self.kinit("testuser1")
        self.nsupdate("add inserted43.wrongacceptor.net 10 A 1.2.3.4", 2)
        self.checkNotInDB("wrongacceptor.net", "inserted43.wrongacceptor.net")
