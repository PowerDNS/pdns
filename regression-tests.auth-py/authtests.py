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

from pprint import pprint
from eqdnsmessage import AssertEqualDNSMessageMixin

class AuthTest(AssertEqualDNSMessageMixin, unittest.TestCase):
    """
    Setup auth required for the tests
    """

    _confdir = 'auth'
    _authPort = 5300

    _backend = os.getenv("AUTH_BACKEND", "bind")

    _backend_configs = dict(
        bind="""
bind-config={confdir}/named.conf
bind-dnssec-db={bind_dnssec_db}
""",    lmdb="",
        gsqlite3="")

    _config_params = []

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

    _config_template = ""

    _root_DS = "63149 13 1 a59da3f5c1b97fcd5fa2b3b2b0ac91d38a60d33a"

    # The default SOA for zones in the authoritative servers
    _SOA = "ns1.example.net. hostmaster.example.net. 1 3600 1800 1209600 300"

    # The definitions of the zones on the authoritative servers, the key is the
    # zonename and the value is the zonefile content. several strings are replaced:
    #   - {soa} => value of _SOA
    #   - {prefix} value of _PREFIX
    _zones = {
        'example.org': """
example.org.                 3600 IN SOA  {soa}
example.org.                 3600 IN NS   ns1.example.org.
example.org.                 3600 IN NS   ns2.example.org.
ns1.example.org.             3600 IN A    {prefix}.10
ns2.example.org.             3600 IN A    {prefix}.11
        """,
    }

    _zone_keys = {
        'example.org': """
Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: Lt0v0Gol3pRUFM7fDdcy0IWN0O/MnEmVPA+VylL8Y4U=
        """,
    }

    _auth_cmd = [os.environ['PDNS']]
    if sys.platform != 'darwin':
        _auth_cmd = ['authbind'] + _auth_cmd

    _auth_env = {}
    _auths = {}

    _PREFIX = os.environ['PREFIX']
    _PDNS_MODULE_DIR = os.environ['PDNS_MODULE_DIR']


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
            type primary;
            file "%s.zone";
        };""" % (zone, zonename))

    @classmethod
    def generateAuthConfig(cls, confdir):
        bind_dnssec_db = os.path.join(confdir, 'bind-dnssec.sqlite3')

        params = tuple([getattr(cls, param) for param in cls._config_params])

        with open(os.path.join(confdir, 'pdns.conf'), 'w') as pdnsconf:
            args = dict(backend=cls._backend,
                        confdir=confdir,
                        prefix=cls._PREFIX,
                        bind_dnssec_db=bind_dnssec_db,
                        PDNS_MODULE_DIR=cls._PDNS_MODULE_DIR
                        )

            pdnsconf.write((cls._config_template_default + cls._backend_configs[cls._backend]).format(**args))
            pdnsconf.write(cls._config_template.format(**args) % params)

        if cls._backend == 'gsqlite3':
            os.system("sqlite3 ./configs/auth/powerdns.sqlite < ../modules/gsqlite3backend/schema.sqlite3.sql")

        if cls._backend == 'lmdb':
            os.system("rm -f pdns.lmdb*")

        if cls._backend == 'bind':
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
        cls.generateAuthConfig(confdir)

        if cls._backend == 'bind':
            cls.generateAuthNamedConf(confdir, cls._zones.keys())

            for zonename, zonecontent in cls._zones.items():
                cls.generateAuthZone(confdir,
                                     zonename,
                                     zonecontent)
                if cls._zone_keys.get(zonename, None):
                    cls.secureZone(confdir, zonename, cls._zone_keys.get(zonename))
        elif cls._backend == 'lmdb':
            for zonename, zonecontent in cls._zones.items():
                cls.generateAuthZone(confdir,
                                     zonename,
                                     zonecontent)
                pdnsutilCmd = [os.environ['PDNSUTIL'],
                               '--config-dir=%s' % confdir,
                               'load-zone',
                               zonename,
                               os.path.join(confdir, '%s.zone' % zonename)]

                print(' '.join(pdnsutilCmd))
                try:
                    subprocess.check_output(pdnsutilCmd, stderr=subprocess.STDOUT)
                except subprocess.CalledProcessError as e:
                    raise AssertionError('%s failed (%d): %s' % (pdnsutilCmd, e.returncode, e.output))
                if cls._zone_keys.get(zonename, None):
                    cls.secureZone(confdir, zonename, cls._zone_keys.get(zonename))
        elif cls._backend == 'gsqlite3':
            # this is not a supported config from the user, but some of the test_*.py files use gsqlite3
            return
        else:
            raise RuntimeError("unknown backend " + cls._backend + " specified")


    @classmethod
    def waitForTCPSocket(cls, ipaddress, port):
        for try_number in range(0, 100):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                sock.connect((ipaddress, port))
                sock.close()
                return
            except Exception as err:
                if err.errno != errno.ECONNREFUSED:
                    print(f'Error occurred: {try_number} {err}', file=sys.stderr)
            time.sleep(0.1)

    @classmethod
    def startAuth(cls, confdir, ipaddress):

        print("Launching pdns_server..")
        authcmd = list(cls._auth_cmd)
        authcmd.append('--config-dir=%s' % confdir)
        authcmd.append('--local-address=%s' % ipaddress)
        authcmd.append('--local-port=%s' % cls._authPort)
        authcmd.append('--loglevel=9')
        authcmd.append('--zone-cache-refresh-interval=0')
        print(' '.join(authcmd))
        logFile = os.path.join(confdir, 'pdns.log')
        with open(logFile, 'w') as fdLog:
            cls._auths[ipaddress] = subprocess.Popen(authcmd, close_fds=True,
                                                     stdout=fdLog, stderr=fdLog,
                                                     env=cls._auth_env)
        cls.waitForTCPSocket(ipaddress, cls._authPort)

        if cls._auths[ipaddress].poll() is not None:
            print(f"\n*** startAuth log for {logFile} ***")
            with open(logFile, 'r') as fdLog:
                print(fdLog.read())
            print(f"*** End startAuth log for {logFile} ***")
            raise AssertionError('%s failed (%d)' % (authcmd, cls._auths[ipaddress].returncode))

    @classmethod
    def setUpSockets(cls):
         print("Setting up UDP socket..")
         cls._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
         cls._sock.settimeout(2.0)
         cls._sock.connect((cls._PREFIX + ".1", cls._authPort))

    @classmethod
    def startResponders(cls):
        pass

    @classmethod
    def setUpClass(cls):
        cls.setUpSockets()

        cls.startResponders()

        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)

        cls.generateAllAuthConfig(confdir)
        cls.startAuth(confdir, cls._PREFIX + ".1")

        print("Launching tests..")

    @classmethod
    def tearDownClass(cls):
        cls.tearDownAuth()
        cls.tearDownResponders()

    @classmethod
    def tearDownResponders(cls):
        pass

    @classmethod
    def killProcess(cls, p):
        # Don't try to kill it if it's already dead
        if p.poll() is not None:
            return
        try:
            p.terminate()
            for count in range(10):
                x = p.poll()
                if x is not None:
                    break
                time.sleep(0.1)
            if x is None:
                print("kill...", p, file=sys.stderr)
                p.kill()
                p.wait()
        except OSError as e:
            # There is a race-condition with the poll() and
            # kill() statements, when the process is dead on the
            # kill(), this is fine
            if e.errno != errno.ESRCH:
                raise

    @classmethod
    def tearDownAuth(cls):
        for _, auth in cls._auths.items():
            cls.killProcess(auth)

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

        sock.connect(("127.0.0.1", cls._authPort))

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
    def sendTCPQueryMultiResponse(cls, query, timeout=2.0, count=1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout:
            sock.settimeout(timeout)

        sock.connect(("127.0.0.1", cls._authPort))

        try:
            wire = query.to_wire()
            sock.send(struct.pack("!H", len(wire)))
            sock.send(wire)
        except socket.timeout as e:
            raise Exception("Timeout: %s" % (str(e)))
        except socket.error as e:
            raise Exception("Network error: %s" % (str(e)))

        messages = []
        for i in range(count):
            try:
                data = sock.recv(2)
                print("got data", repr(data))
                if data:
                    (datalen,) = struct.unpack("!H", data)
                    data = sock.recv(datalen)
                    messages.append(dns.message.from_wire(data))
                else:
                    break
            except socket.timeout as e:
                raise Exception("Timeout: %s" % (str(e)))
            except socket.error as e:
                raise Exception("Network error: %s" % (str(e)))

        return messages

    def setUp(self):
        # This function is called before every tests
        super(AuthTest, self).setUp()

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

    def assertRRsetInAdditional(self, msg, rrset):
        """Asserts the rrset (without comparing TTL) exists in the
        additional section of msg

        @param msg: the dns.message.Message to check
        @param rrset: a dns.rrset.RRset object"""

        ret = ''
        if not isinstance(msg, dns.message.Message):
            raise TypeError("msg is not a dns.message.Message")

        if not isinstance(rrset, dns.rrset.RRset):
            raise TypeError("rrset is not a dns.rrset.RRset")

        found = False
        for ans in msg.additional:
            ret += "%s\n" % ans.to_text()
            if ans.match(rrset.name, rrset.rdclass, rrset.rdtype, 0, None):
                self.assertEqual(ans, rrset, "'%s' != '%s'" % (ans.to_text(), rrset.to_text()))
                found = True

        if not found:
            raise AssertionError("RRset not found in answer\n\n%s" % ret)

    def sortRRsets(self, rrsets):
        """Sorts RRsets in a more useful way than dnspython's default behaviour

        @param rrsets: an array of dns.rrset.RRset objects"""

        return sorted(rrsets, key=lambda rrset: (rrset.name, rrset.rdtype))

    def assertAnyRRsetInAnswer(self, msg, rrsets):
        """Asserts that any of the supplied rrsets exists (without comparing TTL)
        in the answer section of msg

        @param msg: the dns.message.Message to check
        @param rrsets: an array of dns.rrset.RRset object"""

        if not isinstance(msg, dns.message.Message):
            raise TypeError("msg is not a dns.message.Message")

        found = False
        for rrset in rrsets:
            if not isinstance(rrset, dns.rrset.RRset):
                raise TypeError("rrset is not a dns.rrset.RRset")
            for ans in msg.answer:
                if ans.match(rrset.name, rrset.rdclass, rrset.rdtype, 0, None):
                    if ans == rrset:
                        found = True

        if not found:
            raise AssertionError("RRset not found in answer\n%s" %
                                 "\n".join(([ans.to_text() for ans in msg.answer])))

    def assertNoneRRsetInAnswer(self, msg, rrsets):
        """Asserts that none of the supplied rrsets exist (without comparing TTL)
        in the answer section of msg

        @param msg: the dns.message.Message to check
        @param rrsets: an array of dns.rrset.RRset object"""

        if not isinstance(msg, dns.message.Message):
            raise TypeError("msg is not a dns.message.Message")

        found = False
        for rrset in rrsets:
            if not isinstance(rrset, dns.rrset.RRset):
                raise TypeError("rrset is not a dns.rrset.RRset")
            for ans in msg.answer:
                if ans.match(rrset.name, rrset.rdclass, rrset.rdtype, 0, None):
                    if ans == rrset:
                        found = True

        if found:
            raise AssertionError("RRset incorrectly found in answer\n%s" %
                                 "\n".join(([ans.to_text() for ans in msg.answer])))

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

    def assertAnswerNotEmpty(self, msg):
        self.assertTrue(len(msg.answer) > 0, "Answer is empty")

    def assertRcodeEqual(self, msg, rcode):
        if not isinstance(msg, dns.message.Message):
            raise TypeError("msg is not a dns.message.Message but a %s" % type(msg))

        if not isinstance(rcode, int):
            if isinstance(rcode, str):
                rcode = dns.rcode.from_text(rcode)
            else:
                raise TypeError("rcode is neither a str nor int")

        if msg.rcode() != rcode:
            try:
                msgRcode = dns.rcode.to_text(msg.rcode())
                wantedRcode = dns.rcode.to_text(rcode)
            except AttributeError:
                msgRcode = msg.rcode()
                wantedRcode = rcode

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
