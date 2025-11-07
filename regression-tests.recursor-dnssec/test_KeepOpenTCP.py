import dns
import os
import socket
import struct

from recursortests import RecursorTest

class KeepOpenTCPTest(RecursorTest):
    _confdir = 'KeepOpenTCP'
    _auth_zones = RecursorTest._default_auth_zones

    _config_template = """dnssec=validate
packetcache-ttl=10
packetcache-servfail-ttl=10
auth-zones=authzone.example=configs/%s/authzone.zone""" % _confdir

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'authzone.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN authzone.example.
@ 3600 IN SOA {soa}
@ 3600 IN A 192.0.2.88
""".format(soa=cls._SOA))
        super(KeepOpenTCPTest, cls).generateRecursorConfig(confdir)

    def sendTCPQueryKeepOpen(cls, sock, query, timeout=2.0):
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

        message = None
        if data:
            message = dns.message.from_wire(data)
        return message

    def testNoTrailingData(self):
        count = 10
        sock = [None] * count
        expected = dns.rrset.from_text('ns.secure.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.9'.format(prefix=self._PREFIX))
        query = dns.message.make_query('ns.secure.example', 'A', want_dnssec=True)
        query.flags |= dns.flags.AD
        for i in range(count):
            sock[i] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock[i].settimeout(2.0)
            sock[i].connect(("127.0.0.1", self._recursorPort))

            res = self.sendTCPQueryKeepOpen(sock[i], query)
            self.assertMessageIsAuthenticated(res)
            self.assertRRsetInAnswer(res, expected)
            self.assertMatchingRRSIGInAnswer(res, expected)
            sock[i].settimeout(0.1)
            try:
                sock[i].recv(1)
                self.assertTrue(False)
            except socket.timeout as e:
                print("ok")

        for i in range(count):
            sock[i].settimeout(2.0)
            res = self.sendTCPQueryKeepOpen(sock[i], query)
            self.assertMessageIsAuthenticated(res)
            self.assertRRsetInAnswer(res, expected)
            self.assertMatchingRRSIGInAnswer(res, expected)
            sock[i].settimeout(0.1)
            try:
                sock[i].recv(1)
                self.assertTrue(False)
            except socket.timeout as e:
                print("ok")
        for i in range(count):
            sock[i].close()

