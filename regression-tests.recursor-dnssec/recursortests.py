#!/usr/bin/env python2

from __future__ import print_function
import errno
import shutil
import os
import socket
import struct
import subprocess
import sys
import time
import unittest
import dns
import dns.message

from eqdnsmessage import AssertEqualDNSMessageMixin

class RecursorTest(AssertEqualDNSMessageMixin, unittest.TestCase):
    """
    Setup all recursors and auths required for the tests
    """

    _confdir = 'recursor'

    _recursorStartupDelay = 2.0
    _recursorPort = 5300

    _recursor = None

    _PREFIX = os.environ['PREFIX']

    _config_template_default = """
daemon=no
trace=yes
dont-query=
local-address=127.0.0.1
packetcache-ttl=0
packetcache-servfail-ttl=0
max-cache-ttl=15
threads=1
loglevel=9
disable-syslog=yes
"""
    _config_template = """
"""
    _config_params = []
    _lua_config_file = None
    _lua_dns_script_file = None
    _roothints = """
.                        3600 IN NS  ns.root.
ns.root.                 3600 IN A   %s.8
""" % _PREFIX
    _root_DS = "63149 13 1 a59da3f5c1b97fcd5fa2b3b2b0ac91d38a60d33a"

    # The default SOA for zones in the authoritative servers
    _SOA = "ns1.example.net. hostmaster.example.net. 1 3600 1800 1209600 300"

    # The definitions of the zones on the authoritative servers, the key is the
    # zonename and the value is the zonefile content. several strings are replaced:
    #   - {soa} => value of _SOA
    #   - {prefix} value of _PREFIX
    _zones = {
        'ROOT': """
.                        3600 IN SOA  {soa}
.                        3600 IN NS   ns.root.
ns.root.                 3600 IN A    {prefix}.8

example.                 3600 IN NS   ns1.example.
example.                 3600 IN NS   ns2.example.
example.                 3600 IN DS   53174 13 1 50c9e913818767c236c06c2d8272723cb78cbf26

ns1.example.             3600 IN A    {prefix}.10
ns2.example.             3600 IN A    {prefix}.18
        """,
        'example': """
example.                 3600 IN SOA  {soa}
example.                 3600 IN NS   ns1.example.
example.                 3600 IN NS   ns2.example.
ns1.example.             3600 IN A    {prefix}.10
ns2.example.             3600 IN A    {prefix}.18

secure.example.          3600 IN NS   ns.secure.example.
secure.example.          3600 IN DS   64723 13 1 53eb985040d3a89bacf29dbddb55a65834706f33
ns.secure.example.       3600 IN A    {prefix}.9

cname-secure.example.    3600 IN NS   ns.cname-secure.example.
cname-secure.example.    3600 IN DS   49148 13 1 a10314452d5ec4d97fcc6d7e275d217261fe790f
ns.cname-secure.example. 3600 IN A    {prefix}.15

dname-secure.example. 3600 IN NS ns.dname-secure.example.
dname-secure.example. 3600 IN DS 42043 13 2 11c67f46b7c4d5968bc5f6cc944d58377b762bda53ddb4f3a6dbe6faf7a9940f
ns.dname-secure.example. 3600 IN A {prefix}.13

bogus.example.           3600 IN NS   ns.bogus.example.
bogus.example.           3600 IN DS   65034 13 1 6df3bb50ea538e90eacdd7ae5419730783abb0ee
ns.bogus.example.        3600 IN A    {prefix}.12

insecure.example.        3600 IN NS   ns.insecure.example.
ns.insecure.example.     3600 IN A    {prefix}.13

optout.example.          3600 IN NS   ns1.optout.example.
optout.example.          3600 IN DS   59332 13 1 e664f886ae1b5df03d918bc1217d22afc29925b9
ns1.optout.example.      3600 IN A    {prefix}.14

insecure-formerr.example. 3600 IN NS   ns1.insecure-formerr.example.
ns1.insecure-formerr.example. 3600 IN A    {prefix}.2

ecs-echo.example. 3600 IN NS   ns1.ecs-echo.example.
ns1.ecs-echo.example. 3600 IN A    {prefix}.21

islandofsecurity.example.          3600 IN NS   ns1.islandofsecurity.example.
ns1.islandofsecurity.example.      3600 IN A    {prefix}.9

sortcname.example.                 3600 IN CNAME sort
sort.example.                      3600 IN A     17.38.42.80
sort.example.                      3600 IN A     192.168.0.1
sort.example.                      3600 IN A     17.238.240.5
sort.example.                      3600 IN MX    25 mx

delay1.example.                     3600 IN NS   ns1.delay1.example.
ns1.delay1.example.                 3600 IN A    {prefix}.16
delay1.example.                     3600 IN DS 42043 13 2 7319fa605cf117f36e3de070157577ebb9a05a1d1f963d80eda55b5d6e793eb2

delay2.example.                     3600 IN NS   ns1.delay2.example.
ns1.delay2.example.                 3600 IN A    {prefix}.17
delay2.example.                     3600 IN DS 42043 13 2 60a047b87740c8564c21d5fd34626c10a77a6c41e3b34564230119c2f13937b8
        """,
        'secure.example': """
secure.example.          3600 IN SOA  {soa}
secure.example.          3600 IN NS   ns.secure.example.
ns.secure.example.       3600 IN A    {prefix}.9

secure.example.          3600 IN A    192.0.2.17

host1.secure.example.    3600 IN A    192.0.2.2
cname.secure.example.    3600 IN CNAME host1.secure.example.
cname-to-insecure.secure.example. 3600 IN CNAME node1.insecure.example.
cname-to-bogus.secure.example.    3600 IN CNAME ted.bogus.example.
cname-to-islandofsecurity.secure.example. 3600 IN CNAME node1.islandofsecurity.example.

host1.sub.secure.example. 3600 IN A    192.0.2.11

;; See #4158
sub2.secure.example. 3600 IN CNAME doesnotmatter.insecure.example.
insecure.sub2.secure.example. 3600 IN NS ns1.insecure.example.

*.wildcard.secure.example.    3600 IN A    192.0.2.10

*.cnamewildcard.secure.example. 3600 IN CNAME host1.secure.example.

*.cnamewildcardnxdomain.secure.example. 3600 IN CNAME doesntexist.secure.example.

cname-to-formerr.secure.example. 3600 IN CNAME host1.insecure-formerr.example.

dname-secure.secure.example. 3600 IN DNAME dname-secure.example.
dname-insecure.secure.example. 3600 IN DNAME insecure.example.
dname-bogus.secure.example. 3600 IN DNAME bogus.example.
        """,
        'dname-secure.example': """
dname-secure.example. 3600 IN SOA {soa}
dname-secure.example. 3600 IN NS ns.dname-secure.example.
ns.dname-secure.example. 3600 IN A {prefix}.13

host1.dname-secure.example. IN A 192.0.2.21

cname-to-secure.dname-secure.example. 3600 IN CNAME host1.secure.example.
cname-to-insecure.dname-secure.example. 3600 IN CNAME node1.insecure.example.
cname-to-bogus.dname-secure.example.    3600 IN CNAME ted.bogus.example.
""",
        'cname-secure.example': """
cname-secure.example.          3600 IN SOA   {soa}
cname-secure.example.          3600 IN NS    ns.cname-secure.example.
ns.cname-secure.example.       3600 IN A     {prefix}.15
cname-secure.example.          3600 IN CNAME secure.example.
        """,
        'bogus.example': """
bogus.example.           3600 IN SOA  {soa}
bogus.example.           3600 IN NS   ns1.bogus.example.
ns1.bogus.example.       3600 IN A    {prefix}.12
ted.bogus.example.       3600 IN A    192.0.2.1
bill.bogus.example.      3600 IN AAAA 2001:db8:12::3
        """,
        'insecure.sub2.secure.example': """
insecure.sub2.secure.example.        3600 IN SOA  {soa}
insecure.sub2.secure.example.        3600 IN NS   ns1.insecure.example.

node1.insecure.sub2.secure.example.  3600 IN A    192.0.2.18
        """,
        'insecure.example': """
insecure.example.        3600 IN SOA  {soa}
insecure.example.        3600 IN NS   ns1.insecure.example.
ns1.insecure.example.    3600 IN A    {prefix}.13

node1.insecure.example.  3600 IN A    192.0.2.6

cname-to-secure.insecure.example. 3600 IN CNAME host1.secure.example.

dname-to-secure.insecure.example. 3600 IN DNAME dname-secure.example.
        """,
        'optout.example': """
optout.example.        3600 IN SOA  {soa}
optout.example.        3600 IN NS   ns1.optout.example.
ns1.optout.example.    3600 IN A    {prefix}.14

insecure.optout.example.     3600 IN NS ns1.insecure.optout.example.
ns1.insecure.optout.example. 3600 IN A  {prefix}.15

secure.optout.example.     3600 IN NS ns1.secure.optout.example.
secure.optout.example.     3600 IN DS 64215 13 1 b88284d7a8d8605c398e8942262f97b9a5a31787
ns1.secure.optout.example. 3600 IN A  {prefix}.15
        """,
        'insecure.optout.example': """
insecure.optout.example.        3600 IN SOA  {soa}
insecure.optout.example.        3600 IN NS   ns1.insecure.optout.example.
ns1.insecure.optout.example.    3600 IN A    {prefix}.15

node1.insecure.optout.example.  3600 IN A    192.0.2.7
        """,
        'secure.optout.example': """
secure.optout.example.          3600 IN SOA  {soa}
secure.optout.example.          3600 IN NS   ns1.secure.optout.example.
ns1.secure.optout.example.      3600 IN A    {prefix}.15

node1.secure.optout.example.    3600 IN A    192.0.2.8
        """,
        'islandofsecurity.example': """
islandofsecurity.example.          3600 IN SOA  {soa}
islandofsecurity.example.          3600 IN NS   ns1.islandofsecurity.example.
ns1.islandofsecurity.example.      3600 IN A    {prefix}.9

node1.islandofsecurity.example.    3600 IN A    192.0.2.20
        """,
        'undelegated.secure.example': """
undelegated.secure.example.        3600 IN SOA  {soa}
undelegated.secure.example.        3600 IN NS   ns1.undelegated.secure.example.

node1.undelegated.secure.example.  3600 IN A    192.0.2.21
        """,
        'undelegated.insecure.example': """
undelegated.insecure.example.        3600 IN SOA  {soa}
undelegated.insecure.example.        3600 IN NS   ns1.undelegated.insecure.example.

node1.undelegated.insecure.example.  3600 IN A    192.0.2.22
        """,

        'delay1.example': """
delay1.example.                       3600 IN SOA  {soa}
delay1.example.                       3600 IN NS n1.delay1.example.
ns1.delay1.example.                   3600 IN A    {prefix}.16
*.delay1.example.                     0    LUA TXT ";" "local socket=require('socket')" "socket.sleep(tonumber(qname:getRawLabels()[1])/10)" "return 'a'"
        """,
        
        'delay2.example': """
delay2.example.                       3600 IN SOA  {soa}
delay2.example.                       3600 IN NS n1.delay2.example.
ns1.delay2.example.                   3600 IN A    {prefix}.17
*.delay2.example.                     0    LUA TXT ";" "local socket=require('socket')" "socket.sleep(tonumber(qname:getRawLabels()[1])/10)" "return 'a'"
        """
    }

    # The private keys for the zones (note that DS records should go into
    # the zonecontent in _zones
    _zone_keys = {
        'ROOT': """
Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: rhWuEydDz3QaIspSVj683B8Xq5q/ozzA38XUgzD4Fbo=
        """,

        'example': """
Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: Lt0v0Gol3pRUFM7fDdcy0IWN0O/MnEmVPA+VylL8Y4U=
        """,

        'secure.example': """
Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: 1G4WRoOFJJXk+fotDCHVORtJmIG2OUhKi8AO2jDPGZA=
        """,

        'bogus.example': """
Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: f5jV7Q8kd5hDpMWObsuQ6SQda0ftf+JrO3uZwEg6nVw=
        """,

        'optout.example': """
Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: efmq9G+J4Y2iPnIBRwJiy6Z/nIHSzpsCy/7XHhlS19A=
        """,

        'secure.optout.example': """
Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: xcNUxt1Knj14A00lKQFDboluiJyM2f7FxpgsQaQ3AQ4=
        """,

        'islandofsecurity.example': """
Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: o9F5iix8V68tnMcuOaM2Lt8XXhIIY//SgHIHEePk6cM=
        """,

        'cname-secure.example': """
Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: kvoV/g4IO/tefSro+FLJ5UC7H3BUf0IUtZQSUOfQGyA=
""",

        'dname-secure.example': """
Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: Ep9uo6+wwjb4MaOmqq7LHav2FLrjotVOeZg8JT1Qk04=
""",

        'delay1.example': """
Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: Ep9uo6+wwjb4MaOmqq7LHav2FLrjotVOeZg8JT1Qk04=
""",

        'delay2.example': """
Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: Ep9uo6+wwjb4MaOmqq7LHav2FLrjotVOeZg8JT1Qk04=
"""
    }

    # This dict is keyed with the suffix of the IP address and its value
    # is a list of zones hosted on that IP. Note that delegations should
    # go into the _zones's zonecontent
    _auth_zones = {
        '8': {'threads': 1,
              'zones': ['ROOT']},
        '9': {'threads': 1,
              'zones': ['secure.example', 'islandofsecurity.example']},
        '10': {'threads': 1,
               'zones': ['example']},

        # 11 is used by CircleCI provided resolver

        '12': {'threads': 1,
               'zones': ['bogus.example', 'undelegated.secure.example', 'undelegated.insecure.example']},
        '13': {'threads': 1,
               'zones': ['insecure.example', 'insecure.sub2.secure.example', 'dname-secure.example']},
        '14': {'threads': 1,
               'zones': ['optout.example']},
        '15': {'threads': 1,
               'zones': ['insecure.optout.example', 'secure.optout.example', 'cname-secure.example']},
        '16': {'threads': 2,
               'zones': ['delay1.example']},
        '17': {'threads': 2,
               'zones': ['delay2.example']},
        '18': {'threads': 1,
               'zones': ['example']}
    }

    _auth_cmd = ['authbind',
                 os.environ['PDNS']]
    _auth_env = {}
    _auths = {}

    @classmethod
    def createConfigDir(cls, confdir):
        try:
            shutil.rmtree(confdir)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
        os.mkdir(confdir, 0o755)

    @classmethod
    def generateAuthZone(cls, confdir, zonename, zonecontent):
        with open(os.path.join(confdir, '%s.zone' % zonename), 'w') as zonefile:
            zonefile.write(zonecontent.format(prefix=cls._PREFIX, soa=cls._SOA))

    @classmethod
    def generateAuthNamedConf(cls, confdir, zones):
        with open(os.path.join(confdir, 'named.conf'), 'w') as namedconf:
            namedconf.write("""
options {
    directory "%s";
};""" % confdir)
            for zonename in zones:
                zone = '.' if zonename == 'ROOT' else zonename

                namedconf.write("""
        zone "%s" {
            type master;
            file "%s.zone";
        };""" % (zone, zonename))

    @classmethod
    def generateAuthConfig(cls, confdir, threads):
        bind_dnssec_db = os.path.join(confdir, 'bind-dnssec.sqlite3')

        with open(os.path.join(confdir, 'pdns.conf'), 'w') as pdnsconf:
            pdnsconf.write("""
module-dir=../regression-tests/modules
launch=bind
daemon=no
local-ipv6=
bind-config={confdir}/named.conf
bind-dnssec-db={bind_dnssec_db}
socket-dir={confdir}
cache-ttl=0
negquery-cache-ttl=0
query-cache-ttl=0
log-dns-queries=yes
log-dns-details=yes
loglevel=9
enable-lua-records
dname-processing=yes
distributor-threads={threads}""".format(confdir=confdir,
                                        bind_dnssec_db=bind_dnssec_db,
                                        threads=threads))

        pdnsutilCmd = [os.environ['PDNSUTIL'],
                       '--config-dir=%s' % confdir,
                       'create-bind-db',
                       bind_dnssec_db]

        print(' '.join(pdnsutilCmd))
        try:
            subprocess.check_output(pdnsutilCmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise AssertionError('%s failed (%d): %s' % (pdnsutilCmd, e.returncode, e.output))

    @classmethod
    def secureZone(cls, confdir, zonename, key=None):
        zone = '.' if zonename == 'ROOT' else zonename
        if not key:
            pdnsutilCmd = [os.environ['PDNSUTIL'],
                           '--config-dir=%s' % confdir,
                           'secure-zone',
                           zone]
        else:
            keyfile = os.path.join(confdir, 'dnssec.key')
            with open(keyfile, 'w') as fdKeyfile:
                fdKeyfile.write(key)

            pdnsutilCmd = [os.environ['PDNSUTIL'],
                           '--config-dir=%s' % confdir,
                           'import-zone-key',
                           zone,
                           keyfile,
                           'active',
                           'ksk']

        print(' '.join(pdnsutilCmd))
        try:
            subprocess.check_output(pdnsutilCmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise AssertionError('%s failed (%d): %s' % (pdnsutilCmd, e.returncode, e.output))

    @classmethod
    def generateAllAuthConfig(cls, confdir):
        if cls._auth_zones:
            for auth_suffix, zoneinfo in cls._auth_zones.items():
                threads = zoneinfo['threads']
                zones = zoneinfo['zones']
                authconfdir = os.path.join(confdir, 'auth-%s' % auth_suffix)

                os.mkdir(authconfdir)

                cls.generateAuthConfig(authconfdir, threads)
                cls.generateAuthNamedConf(authconfdir, zones)

                for zone in zones:
                    cls.generateAuthZone(authconfdir,
                                         zone,
                                         cls._zones[zone])
                    if cls._zone_keys.get(zone, None):
                        cls.secureZone(authconfdir, zone, cls._zone_keys.get(zone))

    @classmethod
    def startAllAuth(cls, confdir):
        if cls._auth_zones:
            for auth_suffix, _ in cls._auth_zones.items():
                authconfdir = os.path.join(confdir, 'auth-%s' % auth_suffix)
                ipaddress = cls._PREFIX + '.' + auth_suffix
                cls.startAuth(authconfdir, ipaddress)

    @classmethod
    def startAuth(cls, confdir, ipaddress):
        print("Launching pdns_server..")
        authcmd = list(cls._auth_cmd)
        authcmd.append('--config-dir=%s' % confdir)
        authcmd.append('--local-address=%s' % ipaddress)
        print(' '.join(authcmd))

        logFile = os.path.join(confdir, 'pdns.log')
        with open(logFile, 'w') as fdLog:
            cls._auths[ipaddress] = subprocess.Popen(authcmd, close_fds=True,
                                                     stdout=fdLog, stderr=fdLog,
                                                     env=cls._auth_env)

        time.sleep(2)

        if cls._auths[ipaddress].poll() is not None:
            try:
                cls._auths[ipaddress].kill()
            except OSError as e:
                if e.errno != errno.ESRCH:
                    raise
                with open(logFile, 'r') as fdLog:
                    print(fdLog.read())
            sys.exit(cls._auths[ipaddress].returncode)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        params = tuple([getattr(cls, param) for param in cls._config_params])
        if len(params):
            print(params)

        recursorconf = os.path.join(confdir, 'recursor.conf')

        with open(recursorconf, 'w') as conf:
            conf.write("# Autogenerated by recursortests.py\n")
            conf.write(cls._config_template_default)
            conf.write(cls._config_template % params)
            conf.write("\n")
            conf.write("socket-dir=%s\n" % confdir)
            if cls._lua_config_file or cls._root_DS:
                luaconfpath = os.path.join(confdir, 'conffile.lua')
                with open(luaconfpath, 'w') as luaconf:
                    if cls._root_DS:
                        luaconf.write("addTA('.', '%s')\n" % cls._root_DS)
                    if cls._lua_config_file:
                        luaconf.write(cls._lua_config_file)
                conf.write("lua-config-file=%s\n" % luaconfpath)
            if cls._lua_dns_script_file:
                luascriptpath = os.path.join(confdir, 'dnsscript.lua')
                with open(luascriptpath, 'w') as luascript:
                    luascript.write(cls._lua_dns_script_file)
                conf.write("lua-dns-script=%s\n" % luascriptpath)
            if cls._roothints:
                roothintspath = os.path.join(confdir, 'root.hints')
                with open(roothintspath, 'w') as roothints:
                    roothints.write(cls._roothints)
                conf.write("hint-file=%s\n" % roothintspath)

    @classmethod
    def startResponders(cls):
        pass

    @classmethod
    def startRecursor(cls, confdir, port):
        print("Launching pdns_recursor..")
        recursorcmd = [os.environ['PDNSRECURSOR'],
                       '--config-dir=%s' % confdir,
                       '--local-port=%s' % port,
                       '--security-poll-suffix=']
        print(' '.join(recursorcmd))

        logFile = os.path.join(confdir, 'recursor.log')
        with open(logFile, 'w') as fdLog:
            cls._recursor = subprocess.Popen(recursorcmd, close_fds=True,
                                             stdout=fdLog, stderr=fdLog)

        if 'PDNSRECURSOR_FAST_TESTS' in os.environ:
            delay = 0.5
        else:
            delay = cls._recursorStartupDelay

        time.sleep(delay)

        if cls._recursor.poll() is not None:
            try:
                cls._recursor.kill()
            except OSError as e:
                if e.errno != errno.ESRCH:
                    raise
                with open(logFile, 'r') as fdLog:
                    print(fdLog.read())
            sys.exit(cls._recursor.returncode)

    @classmethod
    def wipeRecursorCache(cls, confdir):
        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % confdir,
                          'wipe-cache',
                          '.$']
        try:
            subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise AssertionError('%s failed (%d): %s' % (rec_controlCmd, e.returncode, e.output))

    @classmethod
    def setUpSockets(cls):
        print("Setting up UDP socket..")
        cls._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cls._sock.settimeout(2.0)
        cls._sock.connect(("127.0.0.1", cls._recursorPort))

    @classmethod
    def setUpClass(cls):
        cls.setUpSockets()

        cls.startResponders()

        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)
        cls.generateAllAuthConfig(confdir)
        cls.startAllAuth(confdir)

        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

        print("Launching tests..")

    @classmethod
    def tearDownClass(cls):
        cls.tearDownRecursor()
        cls.tearDownAuth()
        cls.tearDownResponders()

    @classmethod
    def tearDownResponders(cls):
        pass

    @classmethod
    def tearDownAuth(cls):
        if 'PDNSRECURSOR_FAST_TESTS' in os.environ:
            delay = 0.1
        else:
            delay = 1.0

        for _, auth in cls._auths.items():
            try:
                auth.terminate()
                if auth.poll() is None:
                    time.sleep(delay)
                    if auth.poll() is None:
                        auth.kill()
                    auth.wait()
            except OSError as e:
                if e.errno != errno.ESRCH:
                    raise

    @classmethod
    def tearDownRecursor(cls):
        if 'PDNSRECURSOR_FAST_TESTS' in os.environ:
            delay = 0.1
        else:
            delay = 1.0
        try:
            if cls._recursor:
                cls._recursor.terminate()
                if cls._recursor.poll() is None:
                    time.sleep(delay)
                    if cls._recursor.poll() is None:
                        cls._recursor.kill()
                    cls._recursor.wait()
        except OSError as e:
            # There is a race-condition with the poll() and
            # kill() statements, when the process is dead on the
            # kill(), this is fine
            if e.errno != errno.ESRCH:
                raise

    @classmethod
    def sendUDPQuery(cls, query, timeout=2.0, decode=True, fwparams=dict()):
        if timeout:
            cls._sock.settimeout(timeout)

        try:
            cls._sock.send(query.to_wire())
            data = cls._sock.recv(4096)
        except socket.timeout:
            data = None
        finally:
            if timeout:
                cls._sock.settimeout(None)

        message = None
        if data:
            if not decode:
                return data
            message = dns.message.from_wire(data, **fwparams)
        return message

    @classmethod
    def sendTCPQuery(cls, query, timeout=2.0):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout:
            sock.settimeout(timeout)

        sock.connect(("127.0.0.1", cls._recursorPort))

        try:
            wire = query.to_wire()
            sock.send(struct.pack("!H", len(wire)))
            sock.send(wire)
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

        message = None
        if data:
            message = dns.message.from_wire(data)
        return message

    @classmethod
    def sendTCPQueries(cls, queries, timeout=2.0):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout:
            sock.settimeout(timeout)

        sock.connect(("127.0.0.1", cls._recursorPort))
        data = []
        try:
            for query in queries:
                wire = query.to_wire()
                sock.send(struct.pack("!H", len(wire)))
                sock.send(wire)
            for i in range(len(queries)):
                try:
                    datalen = sock.recv(2)
                    if datalen:
                        (datalen,) = struct.unpack("!H", datalen)
                        data.append(sock.recv(datalen))
                except socket.timeout as e:
                    continue
        except socket.error as e:
            print("Network error: %s" % (str(e)))
            data = None
        finally:
            sock.close()

        messages = []
        for d in data:
            messages.append(dns.message.from_wire(d))
        return messages

    def setUp(self):
        # This function is called before every tests
        super(RecursorTest, self).setUp()

    ## Functions for comparisons
    def assertMessageHasFlags(self, msg, flags, ednsflags=[]):
        """Asserts that msg has all the flags from flags set

        @param msg: the dns.message.Message to check
        @param flags: a list of strings with flag mnemonics (like ['RD', 'RA'])
        @param ednsflags: a list of strings with edns-flag mnemonics (like ['DO'])"""

        if not isinstance(msg, dns.message.Message):
            raise TypeError("msg is not a dns.message.Message")

        if isinstance(flags, list):
            for elem in flags:
                if not isinstance(elem, str):
                    raise TypeError("flags is not a list of strings")
        else:
            raise TypeError("flags is not a list of strings")

        if isinstance(ednsflags, list):
            for elem in ednsflags:
                if not isinstance(elem, str):
                    raise TypeError("ednsflags is not a list of strings")
        else:
            raise TypeError("ednsflags is not a list of strings")

        msgFlags = dns.flags.to_text(msg.flags).split()
        missingFlags = [flag for flag in flags if flag not in msgFlags]

        msgEdnsFlags = dns.flags.edns_to_text(msg.ednsflags).split()
        missingEdnsFlags = [ednsflag for ednsflag in ednsflags if ednsflag not in msgEdnsFlags]

        if len(missingFlags) or len(missingEdnsFlags) or len(msgFlags) > len(flags):
            raise AssertionError("Expected flags '%s' (EDNS: '%s'), found '%s' (EDNS: '%s') in query %s" %
                                 (' '.join(flags), ' '.join(ednsflags),
                                  ' '.join(msgFlags), ' '.join(msgEdnsFlags),
                                  msg.question[0]))

    def assertMessageIsAuthenticated(self, msg):
        """Asserts that the message has the AD bit set

        @param msg: the dns.message.Message to check"""

        if not isinstance(msg, dns.message.Message):
            raise TypeError("msg is not a dns.message.Message")

        msgFlags = dns.flags.to_text(msg.flags)
        self.assertTrue('AD' in msgFlags, "No AD flag found in the message for %s" % msg.question[0].name)

    def assertRRsetInAnswer(self, msg, rrset):
        """Asserts the rrset (without comparing TTL) exists in the
        answer section of msg

        @param msg: the dns.message.Message to check
        @param rrset: a dns.rrset.RRset object"""

        ret = ''
        if not isinstance(msg, dns.message.Message):
            raise TypeError("msg is not a dns.message.Message")

        if not isinstance(rrset, dns.rrset.RRset):
            raise TypeError("rrset is not a dns.rrset.RRset")

        found = False
        for ans in msg.answer:
            ret += "%s\n" % ans.to_text()
            if ans.match(rrset.name, rrset.rdclass, rrset.rdtype, 0, None):
                self.assertEqual(ans, rrset, "'%s' != '%s'" % (ans.to_text(), rrset.to_text()))
                found = True

        if not found:
            raise AssertionError("RRset not found in answer\n\n%s" % ret)

    def assertMatchingRRSIGInAnswer(self, msg, coveredRRset, keys=None):
        """Looks for coveredRRset in the answer section and if there is an RRSIG RRset
        that covers that RRset. If keys is not None, this function will also try to
        validate the RRset against the RRSIG

        @param msg: The dns.message.Message to check
        @param coveredRRset: The RRSet to check for
        @param keys: a dictionary keyed by dns.name.Name with node or rdataset values to use for validation"""

        if not isinstance(msg, dns.message.Message):
            raise TypeError("msg is not a dns.message.Message")

        if not isinstance(coveredRRset, dns.rrset.RRset):
            raise TypeError("coveredRRset is not a dns.rrset.RRset")

        msgRRsigRRSet = None
        msgRRSet = None

        ret = ''
        for ans in msg.answer:
            ret += ans.to_text() + "\n"

            if ans.match(coveredRRset.name, coveredRRset.rdclass, coveredRRset.rdtype, 0, None):
                msgRRSet = ans
            if ans.match(coveredRRset.name, dns.rdataclass.IN, dns.rdatatype.RRSIG, coveredRRset.rdtype, None):
                msgRRsigRRSet = ans
            if msgRRSet and msgRRsigRRSet:
                break

        if not msgRRSet:
            raise AssertionError("RRset for '%s' not found in answer" % msg.question[0].to_text())

        if not msgRRsigRRSet:
            raise AssertionError("No RRSIGs found in answer for %s:\nFull answer:\n%s" % (msg.question[0].to_text(), ret))

        if keys:
            try:
                dns.dnssec.validate(msgRRSet, msgRRsigRRSet.to_rdataset(), keys)
            except dns.dnssec.ValidationFailure as e:
                raise AssertionError("Signature validation failed for %s:\n%s" % (msg.question[0].to_text(), e))

    def assertNoRRSIGsInAnswer(self, msg):
        """Checks if there are _no_ RRSIGs in the answer section of msg"""

        if not isinstance(msg, dns.message.Message):
            raise TypeError("msg is not a dns.message.Message")

        ret = ""
        for ans in msg.answer:
            if ans.rdtype == dns.rdatatype.RRSIG:
                ret += ans.name.to_text() + "\n"

        if len(ret):
            raise AssertionError("RRSIG found in answers for:\n%s" % ret)

    def assertAnswerEmpty(self, msg):
        self.assertTrue(len(msg.answer) == 0, "Data found in the the answer section for %s:\n%s" % (msg.question[0].to_text(), '\n'.join([i.to_text() for i in msg.answer])))

    def assertRcodeEqual(self, msg, rcode):
        if not isinstance(msg, dns.message.Message):
            raise TypeError("msg is not a dns.message.Message but a %s" % type(msg))

        if not isinstance(rcode, int):
            if isinstance(rcode, str):
                rcode = dns.rcode.from_text(rcode)
            else:
                raise TypeError("rcode is neither a str nor int")

        if msg.rcode() != rcode:
            msgRcode = dns.rcode._by_value[msg.rcode()]
            wantedRcode = dns.rcode._by_value[rcode]

            raise AssertionError("Rcode for %s is %s, expected %s." % (msg.question[0].to_text(), msgRcode, wantedRcode))

    def assertAuthorityHasSOA(self, msg):
        if not isinstance(msg, dns.message.Message):
            raise TypeError("msg is not a dns.message.Message but a %s" % type(msg))

        found = False
        for rrset in msg.authority:
            if rrset.rdtype == dns.rdatatype.SOA:
                found = True
                break

        if not found:
            raise AssertionError("No SOA record found in the authority section:\n%s" % msg.to_text())

    def assertResponseMatches(self, query, expectedRRs, response):
        expectedResponse = dns.message.make_response(query)

        if query.flags & dns.flags.RD:
            expectedResponse.flags |= dns.flags.RA
        if query.flags & dns.flags.CD:
            expectedResponse.flags |= dns.flags.CD

        expectedResponse.answer = expectedRRs
        print(expectedResponse)
        print(response)
        self.assertEquals(response, expectedResponse)

    @classmethod
    def sendQuery(cls, name, rdtype, useTCP=False):
        """Helper function that creates the query"""
        msg = dns.message.make_query(name, rdtype, want_dnssec=True)
        msg.flags |= dns.flags.AD

        if useTCP:
            return cls.sendTCPQuery(msg)
        return cls.sendUDPQuery(msg)

    def createQuery(self, name, rdtype, flags, ednsflags):
        """Helper function that creates the query with the specified flags.
        The flags need to be strings (no checking is performed atm)"""
        msg = dns.message.make_query(name, rdtype)
        msg.flags = dns.flags.from_text(flags)
        msg.flags += dns.flags.from_text('RD')
        msg.use_edns(edns=0, ednsflags=dns.flags.edns_from_text(ednsflags))
        return msg
