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
    _root_DS = None

    # The default SOA for zones in the authoritative servers
    _SOA = "ns.example.net. hostmaster.example.net. 1 3600 1800 1209600 300"

    # The definitions of the authoritative servers, the key is the suffix of the
    # IP address. The values are a dict of key zonename and the value is the
    # zonefile content. several strings are replaced:
    #   - {soa} => value of _SOA
    #   - {prefix} value of _PREFIX
    # Make this None to not launch auths
    _auths_zones = {
        '8': {
            '.':"""
.                        3600 IN SOA {soa}
.                        3600 IN NS  ns.root.
ns.root.                 3600 IN A   {prefix}.8
net.                     3600 IN NS  ns.example.net.
net.                     3600 IN NS  ns2.example.net.
ns.example.net.          3600 IN A   {prefix}.10
ns2.example.net.         3600 IN A   {prefix}.11"""
            },
        '10': {
            'example.net': """
example.net.             3600 IN SOA {soa}
example.net.             3600 IN NS  ns.example.net.
example.net.             3600 IN NS  ns2.example.net.
ns.example.net.          3600 IN A   {prefix}.10
ns2.example.net.         3600 IN A   {prefix}.11
            """
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
    def secureZone(cls, confdir, zone):
        pdnsutilCmd = [ os.environ['PDNSUTIL'],
                        '--config-dir=%s' % confdir,
                        'secure-zone',
                        zone]
        print ' '.join(pdnsutilCmd)
        try:
            subprocess.check_output(pdnsutilCmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print e.output
            raise

        if zone == '.':
            pdnsutilCmd = [ os.environ['PDNSUTIL'],
                            '--config-dir=%s' % confdir,
                            'show-zone',
                            zone]
            print ' '.join(pdnsutilCmd)
            try:
                output = subprocess.check_output(pdnsutilCmd, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                print e.output
                raise

            lines = output.split('\n')
            for line in lines:
                elems = line.split('DS = . IN DS ')
                if len(elems) == 2:
                    cls._root_DS = ' '.join(elems[1].split(' ')[0:4]) # FIXME
                    break

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
            conf.write("socket-dir=%s\n" % confdir)
            conf.write(cls._config_template % params)
            conf.write("\n")
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

        if cls._auths_zones:
            for auth_suffix, zones in cls._auths_zones.items():
                authconfdir = os.path.join(confdir, 'auth-%s' % auth_suffix)

                os.mkdir(authconfdir)

                cls.generateAuthConfig(authconfdir)
                cls.generateAuthNamedConf(authconfdir, zones)

                for zonename, zonecontent in zones.items():
                    cls.generateAuthZone(authconfdir, zonename, zonecontent)
                    cls.secureZone(authconfdir, zonename)

                ipaddress = cls._PREFIX + '.' + auth_suffix
                cls.startAuth(authconfdir, ipaddress)

        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

        print("Launching tests..")

    @classmethod
    def tearDownClass(cls):
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
