#!/usr/bin/env python2

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

class RecursorTest(unittest.TestCase):
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
    _roothints = """
.                        3600 IN NS  ns.root.
ns.root.                 3600 IN A   %s.8
""" % _PREFIX
    _root_DS = "63149 13 1 a59da3f5c1b97fcd5fa2b3b2b0ac91d38a60d33a"

    # The default SOA for zones in the authoritative servers
    _SOA = "ns1.example.net. hostmaster.example.net. 1 3600 1800 1209600 300"

    # The definitions of the authoritative servers, the key is the suffix of the
    # IP address. The values are a dict of key zonename and the value is the
    # zonefile content. several strings are replaced:
    #   - {soa} => value of _SOA
    #   - {prefix} value of _PREFIX
    # Make this None to not launch auths
    _auths_zones = {
        '8': {
            '.': {
                'content': """
.                        3600 IN SOA {soa}
.                        3600 IN NS  ns.root.
ns.root.                 3600 IN A   {prefix}.8
net.                     3600 IN NS  ns1.example.net.
net.                     3600 IN NS  ns2.example.net.
net.                     3600 IN DS  53174 13 1 f8884460a162a688192fbb2ef414f267e8a77150
ns1.example.net.         3600 IN A   {prefix}.10
ns2.example.net.         3600 IN A   {prefix}.11""",

                'privateKey': """Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: rhWuEydDz3QaIspSVj683B8Xq5q/ozzA38XUgzD4Fbo=
""",
            }
        },
        '10': {
            'net': {
                'content': """
net.             3600 IN SOA {soa}
example.net.             3600 IN NS  ns1.example.net.
example.net.             3600 IN NS  ns2.example.net.
example.net.             3600 IN DS  64723 13 1 c51eab719a495db0097bdc17ad0ed37cf6af992b
ns1.example.net.         3600 IN A   {prefix}.10
ns2.example.net.         3600 IN A   {prefix}.11

bogus.net.               3600 IN NS  ns1.bogus.net.
bogus.net.               3600 IN DS  65034 13 1 6df3bb50ea538e90eacdd7ae5419730783abb0ee
ns1.bogus.net.           3600 IN A   {prefix}.12""",
                'privateKey':"""Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: Lt0v0Gol3pRUFM7fDdcy0IWN0O/MnEmVPA+VylL8Y4U="""
            },
            'example.net': {
                'content': """
example.net.             3600 IN SOA {soa}
example.net.             3600 IN NS  ns1.example.net.
example.net.             3600 IN NS  ns2.example.net.
ns1.example.net.         3600 IN A   {prefix}.10
ns2.example.net.         3600 IN A   {prefix}.11
            """,
                'privateKey':"""Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: 1G4WRoOFJJXk+fotDCHVORtJmIG2OUhKi8AO2jDPGZA=
"""
            }
        },
        '11': {
            'net': {
                'content': """
net.             3600 IN SOA {soa}
example.net.             3600 IN NS  ns1.example.net.
example.net.             3600 IN NS  ns2.example.net.
example.net.             3600 IN DS  64723 13 1 c51eab719a495db0097bdc17ad0ed37cf6af992b
ns1.example.net.         3600 IN A   {prefix}.10
ns2.example.net.         3600 IN A   {prefix}.11

bogus.net.               3600 IN NS  ns1.bogus.net.
bogus.net.               3600 IN DS  65034 13 1 6df3bb50ea538e90eacdd7ae5419730783abb0ee
ns1.bogus.net.           3600 IN A   {prefix}.12""",
                'privateKey':"""Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: Lt0v0Gol3pRUFM7fDdcy0IWN0O/MnEmVPA+VylL8Y4U="""
            },
            'example.net': {
                'content': """
example.net.             3600 IN SOA {soa}
example.net.             3600 IN NS  ns1.example.net.
example.net.             3600 IN NS  ns2.example.net.
ns1.example.net.         3600 IN A   {prefix}.10
ns2.example.net.         3600 IN A   {prefix}.11
            """,
                'privateKey':"""Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: 1G4WRoOFJJXk+fotDCHVORtJmIG2OUhKi8AO2jDPGZA=
"""
            }
        },
        '12': {
            'bogus.net': {
                'content': """
bogus.net.               3600 IN SOA  {soa}
bogus.net.               3600 IN NS   ns1.bogus.net.
ns1.bogus.net.           3600 IN A    {prefix}.12
ted.bogus.net.           3600 IN A    192.0.2.1
bill.bogus.net.          3600 IN AAAA 2001:db8:12::3""",
                'privateKey': """Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: f5jV7Q8kd5hDpMWObsuQ6SQda0ftf+JrO3uZwEg6nVw="""
            }
        }
    }

    _auths = {}

    @classmethod
    def createConfigDir(cls, confdir):
        try:
            shutil.rmtree(confdir)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
        os.mkdir(confdir, 0755)

    @classmethod
    def generateAuthZone(cls, confdir, zone, zonecontent):
        zonename = 'ROOT' if zone == '.' else zone

        with open(os.path.join(confdir, '%s.zone' % zonename), 'w') as zonefile:
            zonefile.write(zonecontent.format(prefix=cls._PREFIX, soa=cls._SOA))

    @classmethod
    def generateAuthNamedConf(cls, confdir, zones):
        with open(os.path.join(confdir, 'named.conf'), 'w') as namedconf:
            namedconf.write("""
options {
    directory "%s";
};""" % confdir)
            for zone, zonecontent in zones.items():
                zonename = 'ROOT' if zone == '.' else zone

                namedconf.write("""
        zone "%s" {
            type master;
            file "%s.zone";
        };""" % (zone, zonename))


    @classmethod
    def generateAuthConfig(cls, confdir):
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
distributor-threads=1""".format(confdir = confdir,
                                bind_dnssec_db=bind_dnssec_db))

        pdnsutilCmd = [ os.environ['PDNSUTIL'],
                        '--config-dir=%s' % confdir,
                        'create-bind-db',
                        bind_dnssec_db]

        print ' '.join(pdnsutilCmd)
        try:
            subprocess.check_output(pdnsutilCmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print e.output
            raise

    @classmethod
    def secureZone(cls, confdir, zone, key=None):
        if not key:
            pdnsutilCmd = [ os.environ['PDNSUTIL'],
                            '--config-dir=%s' % confdir,
                            'secure-zone',
                            zone]
        else:
            keyfile = os.path.join((confdir), 'dnssec.key')
            with open(keyfile, 'w') as fdKeyfile:
                fdKeyfile.write(key)

            pdnsutilCmd = [ os.environ['PDNSUTIL'],
                            '--config-dir=%s' % confdir,
                            'import-zone-key',
                            zone,
                            keyfile,
                            'active',
                            'ksk' ]

        print ' '.join(pdnsutilCmd)
        try:
            subprocess.check_output(pdnsutilCmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print e.output
            raise

    @classmethod
    def generateAllAuthConfig(cls, confdir):
        if cls._auths_zones:
            for auth_suffix, zones in cls._auths_zones.items():
                authconfdir = os.path.join(confdir, 'auth-%s' % auth_suffix)

                os.mkdir(authconfdir)

                cls.generateAuthConfig(authconfdir)
                cls.generateAuthNamedConf(authconfdir, zones)

                for zonename, elems in zones.items():
                    cls.generateAuthZone(authconfdir, zonename, elems['content'])
                    cls.secureZone(authconfdir, zonename, elems.get('privateKey', None))

    @classmethod
    def startAllAuth(cls, confdir):
        if cls._auths_zones:
            for auth_suffix, _ in cls._auths_zones.items():
                authconfdir = os.path.join(confdir, 'auth-%s' % auth_suffix)
                ipaddress = cls._PREFIX + '.' + auth_suffix
                cls.startAuth(authconfdir, ipaddress)

    @classmethod
    def startAuth(cls, confdir, ipaddress):
        print("Launching pdns_server..")
        authcmd = [ 'authbind',
                    os.environ['PDNS'],
                    '--config-dir=%s' % confdir,
                    '--local-address=%s' % ipaddress ]
        print(' '.join(authcmd))

        logFile = os.path.join(confdir, 'pdns.log')
        with open(logFile, 'w') as fdLog:
            cls._auths[ipaddress] = subprocess.Popen(authcmd, close_fds=True,
                                                  stdout=fdLog, stderr=fdLog)

        time.sleep(2)

        if cls._auths[ipaddress].poll() is not None:
            try:
                cls._auths[ipaddress].kill()
            except OSError as e:
                if e.errno != errno.ESRCH:
                    raise
                with open(logFile, 'r') as fdLog:
                    print fdLog.read()
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
                        luaconf.write("addDS('.', '%s')" % cls._root_DS)
                    if cls._lua_config_file:
                        luaconf.write(cls._lua_config_file)
                conf.write("lua-config-file=%s\n" % luaconfpath)
            if cls._roothints:
                roothintspath = os.path.join(confdir, 'root.hints')
                with open(roothintspath, 'w') as roothints:
                    roothints.write(cls._roothints)
                conf.write("hint-file=%s\n" % roothintspath)

    @classmethod
    def startRecursor(cls, confdir, port):
        print("Launching pdns_recursor..")
        recursorcmd = [os.environ['PDNSRECURSOR'],
                       '--config-dir=%s' % confdir,
                       '--local-port=%s' % port]
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
                    print fdLog.read()
            sys.exit(cls._recursor.returncode)

    @classmethod
    def wipeRecursorCache(cls, confdir):
        rec_controlCmd = [ os.environ['RECCONTROL'],
                           '--config-dir=%s' % confdir,
                           'wipe-cache',
                           '.$']
        try:
            subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print e.output
            raise

    @classmethod
    def setUpSockets(cls):
        print("Setting up UDP socket..")
        cls._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cls._sock.settimeout(2.0)
        cls._sock.connect(("127.0.0.1", cls._recursorPort))

    @classmethod
    def setUpClass(cls):
        cls.setUpSockets()
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
    def sendUDPQuery(cls, query, timeout=2.0):
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
            message = dns.message.from_wire(data)
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

    def setUp(self):
        # This function is called before every tests
        return


    ## Functions for comparisons
    def assertMessageHasFlags(cls, msg, flags, ednsflags=[]):
        """Asserts that msg has all the flags from flags set

        @param msg: the dns.message.Message to check
        @param flags: a list of strings with flag mnemonics (like ['RD', 'RA'])
        @param ednsflags: a list of strings with edns-flag mnemonics (like ['DO'])"""

        if type(msg) != dns.message.Message:
            raise TypeError("msg is not a dns.message.Message")

        if type(flags) == list:
            for elem in flags:
                if type(elem) != str:
                    raise TypeError("flags is not a list of strings")

        if type(ednsflags) == list:
            for elem in ednsflags:
                if type(elem) != str:
                    raise TypeError("ednsflags is not a list of strings")

        msgFlags = dns.flags.to_text(msg.flags).split()
        missingFlags = [flag for flag in flags if flag not in msgFlags]

        msgEdnsFlags = dns.flags.edns_to_text(msg.flags).split()
        missingEdnsFlags = [ednsflag for ednsflag in ednsflags if ednsflag not in msgEdnsFlags]

        if len(missingFlags) or len(missingEdnsFlags) or len(msgFlags) > len(flags):
            raise AssertionError("Expected flags '%s' (EDNS: '%s'), found '%s' (EDNS: '%s') in query %s"
                    % (' '.join(flags), ' '.join(ednsflags),
                       ' '.join(msgFlags), ' '.join(msgEdnsFlags),
                       msg.question[0]))

    def assertMessageIsAuthenticated(cls, msg):
        """Asserts that the message has the AD bit set

        @param msg: the dns.message.Message to check"""

        if type(msg) != dns.message.Message:
            raise TypeError("msg is not a dns.message.Message")

        msgFlags = dns.flags.to_text(msg.flags)
        cls.assertTrue('AD' in msgFlags, "No AD flag found in the message for %s" % msg.question[0].name)

    def assertRRsetInAnswer(cls, msg, rrset):
        """Asserts the rrset (without comparing TTL) exists in the
        answer section of msg

        @param msg: the dns.message.Message to check
        @param rrset: a dns.rrset.RRset object"""

        ret = ''
        if type(msg) != dns.message.Message:
            raise TypeError("msg is not a dns.message.Message")

        if type(rrset) != dns.rrset.RRset:
            raise TypeError("rrset is not a dns.rrset.RRset")

        found = False
        for ans in msg.answer:
            ret += "%s\n" % ans.to_text()
            if ans.match(rrset.name, rrset.rdclass, rrset.rdtype, 0, None):
                cls.assertEqual(ans, rrset)
                found = True

        if not found:
            raise AssertionError("RRset not found in answer")

    def assertMatchingRRSIGInAnswer(cls, msg, coveredRRset, keys=None):
        """Looks for coveredRRset in the answer section and if there is an RRSIG RRset
        that covers that RRset. If keys is not None, this function will also try to
        validate the RRset against the RRSIG

        @param msg: The dns.message.Message to check
        @param coveredRRset: The RRSet to check for
        @param keys: a dictionary keyed by dns.name.Name with node or rdataset values to use for validation"""

        if type(msg) != dns.message.Message:
            raise TypeError("msg is not a dns.message.Message")

        if type(coveredRRset) != dns.rrset.RRset:
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

    def assertNoRRSIGsInAnswer(cls, msg):
        """Checks if there are _no_ RRSIGs in the answer section of msg"""

        if type(msg) != dns.message.Message:
            raise TypeError("msg is not a dns.message.Message")

        ret = ""
        for ans in msg.answer:
            if ans.rdtype == dns.rdatatype.RRSIG:
                ret += ans.name.to_text() + "\n"

        if len(ret):
            raise AssertionError("RRSIG found in answers for:\n%s" % ret)

    def assertAnswerEmpty(cls, msg):
        cls.assertTrue(len(msg.answer) == 0, "Data found in the the answer section for %s:\n%s" % (msg.question[0].to_text(), '\n'.join([i.to_text() for i in msg.answer])))

    def assertRcodeEqual(cls, msg, rcode):
        if type(msg) != dns.message.Message:
            raise TypeError("msg is not a dns.message.Message but a %s" % type(msg))

        if type(rcode) != int:
            if type(rcode) == str:
                rcode = dns.rcode.from_text(rcode)
            else:
                raise TypeError("rcode is neither a str nor int")

        if msg.rcode() != rcode:
            msgRcode = dns.rcode._by_value[msg.rcode()]
            wantedRcode = dns.rcode._by_value[rcode]

            raise AssertionError("Rcode for %s is %s, expected %s." % (msg.question[0].to_text(), msgRcode, wantedRcode))
