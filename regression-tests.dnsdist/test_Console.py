#!/usr/bin/env python
import base64
import cdbx
import dns
import os
import socket
import subprocess
import time
from dnsdisttests import DNSDistTest


class TestConsoleAllowed(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")

    _config_params = ["_consoleKeyB64", "_consolePort", "_testServerPort"]
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}
    """

    def testConsoleAllowed(self):
        """
        Console: Allowed
        """
        version = self.sendConsoleCommand("showVersion()")
        self.assertTrue(version.startswith("dnsdist "))


class TestConsoleAllowedV6(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")

    _config_params = ["_consoleKeyB64", "_consolePort", "_testServerPort"]
    _config_template = """
    setKey("%s")
    controlSocket("[::1]:%d")
    newServer{address="127.0.0.1:%d"}
    """

    def testConsoleAllowed(self):
        """
        Console: Allowed IPv6
        """
        if "SKIP_IPV6_TESTS" in os.environ:
            raise unittest.SkipTest("IPv6 tests are disabled")
        version = self.sendConsoleCommand("showVersion()", IPv6=True)
        self.assertTrue(version.startswith("dnsdist "))


class TestConsoleNotAllowed(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")

    _config_params = ["_consoleKeyB64", "_consolePort", "_testServerPort"]
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    setConsoleACL({'192.0.2.1'})
    newServer{address="127.0.0.1:%d"}
    """

    def testConsoleAllowed(self):
        """
        Console: Not allowed by the ACL
        """
        self.assertRaises(socket.error, self.sendConsoleCommand, "showVersion()")


class TestConsoleNoKey(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")

    _config_params = ["_consolePort", "_testServerPort"]
    _config_template = """
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}
    """

    def testConsoleAllowed(self):
        """
        Console: No key, the connection should not be allowed
        """
        self.assertRaises(socket.error, self.sendConsoleCommand, "showVersion()")


class TestConsoleConcurrentConnections(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")
    _maxConns = 2

    _config_params = ["_consoleKeyB64", "_consolePort", "_testServerPort", "_maxConns"]
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}
    setConsoleMaximumConcurrentConnections(%d)
    """

    def testConsoleConnectionsLimit(self):
        """
        Console: Check the maximum number of connections
        """
        conns = []
        # open the maximum number of connections
        for _ in range(self._maxConns):
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.connect(("127.0.0.1", self._consolePort))
            conns.append(conn)

        # we now hold all the slots, let's try to establish a new connection
        self.assertRaises(socket.error, self.sendConsoleCommand, "showVersion()")

        # free one slot
        conns[0].close()
        conns[0] = None
        time.sleep(1)

        # this should work
        version = self.sendConsoleCommand("showVersion()")
        self.assertTrue(version.startswith("dnsdist "))


def writeCDB(fname, variant=1):
    cdb = cdbx.CDB.make(fname + ".tmp")
    cdb.add(socket.inet_aton(f"127.0.0.{variant}"), b"this is the value of the source address tag")
    cdb.add(b"\x05qname\x03cdb\x05tests\x08powerdns\x03com\x00", b"this is the value of the qname tag")
    cdb.add(b"\x06suffix\x03cdb\x05tests\x08powerdns\x03com\x00", b"this is the value of the suffix tag")
    cdb.add(b"this is the value of the qname tag", b"this is the value of the second tag")
    cdb.commit().close()
    os.rename(fname + ".tmp", fname)
    cdb.close()


class TestConsoleAccessObjectsFromYAML(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")

    _cdbFileName = "/tmp/test-cdb-db"

    _yaml_config_template = """
console:
  key: "%s"
  listen_address: "127.0.0.1:%d"
  acl:
    - 127.0.0.0/8
key_value_stores:
  cdb:
    - name: "cdb-kvs"
      file_name: "%s"
      refresh_delay: 1
"""
    _yaml_config_params = ["_consoleKeyB64", "_consolePort", "_cdbFileName"]
    _config_params = []

    @classmethod
    def setUpCDB(cls):
        writeCDB(cls._cdbFileName, 1)

    @classmethod
    def setUpClass(cls):
        cls.setUpCDB()
        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

    def testConsoleCanAccessYamlObject(self):
        """
        Console: Check that we can access Yaml-defined objects
        """
        cdb = self.sendConsoleCommand("getObjectFromYAMLConfiguration('cdb-kvs')")
        self.assertTrue(
            cdb.startswith(
                'Command returned an object we can\'t print: Trying to cast a lua variable from "userdata" to'
            )
        )
        got = self.sendConsoleCommand(
            "if getObjectFromYAMLConfiguration('cdb-kvs'):reload() then return 'reloading worked' else return 'reloading failed' end"
        )
        self.assertEqual(got, "reloading worked\n")


class TestConsoleRings(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")

    _config_params = ["_consoleKeyB64", "_consolePort", "_testServerPort"]
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}
    """

    def testConsoleRingEntries(self):
        """
        Console: Ring entries
        """
        # check that the ring is empty first
        numberOfEntries = self.sendConsoleCommand("#getRingEntries()")
        self.assertEqual(int(numberOfEntries), 0)

        name = "a.console-ring.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN", use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        # we should now have 4 entries in the ring
        numberOfEntries = self.sendConsoleCommand("#getRingEntries()")
        self.assertEqual(int(numberOfEntries), 4)

        # check the first query
        index = 1
        qname = self.sendConsoleCommand(f"getRingEntries()[{index}].qname:toString()").rstrip()
        self.assertEqual(qname, name)
        qtype = self.sendConsoleCommand(f"getRingEntries()[{index}].qtype").rstrip()
        self.assertEqual(int(qtype), 1)
        protocol = self.sendConsoleCommand(f"getRingEntries()[{index}].protocol").rstrip()
        self.assertEqual(protocol, "DoUDP")
        requestor = self.sendConsoleCommand(f"getRingEntries()[{index}].requestor:toString()").rstrip()
        self.assertEqual(requestor, "127.0.0.1")
        isResponse = self.sendConsoleCommand(f"tostring(getRingEntries()[{index}].isResponse)").rstrip()
        self.assertEqual(isResponse, "false")

        # check the first response
        index = 2
        qname = self.sendConsoleCommand(f"getRingEntries()[{index}].qname:toString()").rstrip()
        self.assertEqual(qname, name)
        qtype = self.sendConsoleCommand(f"getRingEntries()[{index}].qtype").rstrip()
        self.assertEqual(int(qtype), 1)
        protocol = self.sendConsoleCommand(f"getRingEntries()[{index}].protocol").rstrip()
        self.assertEqual(protocol, "DoUDP")
        requestor = self.sendConsoleCommand(f"getRingEntries()[{index}].requestor:toString()").rstrip()
        self.assertEqual(requestor, "127.0.0.1")
        backend = self.sendConsoleCommand(f"getRingEntries()[{index}].backend:toStringWithPort()").rstrip()
        self.assertEqual(backend, f"127.0.0.1:{self._testServerPort}")
        isResponse = self.sendConsoleCommand(f"tostring(getRingEntries()[{index}].isResponse)").rstrip()
        self.assertEqual(isResponse, "true")


class TestConsoleViaBuiltInClient(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")

    _config_params = ["_consoleKeyB64", "_consolePort", "_testServerPort"]
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}
    """

    def testConsoleViaBuiltInclient(self):
        """
        Console: Built-in client
        """
        output = None
        try:
            confFile = os.path.join("configs", "dnsdist_%s.conf" % (self.__class__.__name__))
            testcmd = [os.environ["DNSDISTBIN"], "--client", "-C", confFile]
            process = subprocess.Popen(
                testcmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True
            )
            output = process.communicate(input=b"showVersion()\n")
        except subprocess.CalledProcessError as exc:
            raise AssertionError("%s failed (%d): %s" % (testcmd, process.returncode, process.output))

        if process.returncode != 0:
            raise AssertionError("%s failed (%d): %s" % (testcmd, process.returncode, output))

        self.assertTrue(output[0].startswith(b"dnsdist "))
