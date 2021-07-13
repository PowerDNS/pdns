#!/usr/bin/env python
import base64
import dns
import socket
import time
from dnsdisttests import DNSDistTest

class TestConsoleAllowed(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')

    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")
    newServer{address="127.0.0.1:%d"}
    """

    def testConsoleAllowed(self):
        """
        Console: Allowed
        """
        version = self.sendConsoleCommand('showVersion()')
        self.assertTrue(version.startswith('dnsdist '))

class TestConsoleNotAllowed(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')

    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")
    setConsoleACL({'192.0.2.1'})
    newServer{address="127.0.0.1:%d"}
    """

    def testConsoleAllowed(self):
        """
        Console: Not allowed by the ACL
        """
        self.assertRaises(socket.error, self.sendConsoleCommand, 'showVersion()')

class TestConsoleNoKey(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')

    _config_params = ['_consolePort', '_testServerPort']
    _config_template = """
    controlSocket("127.0.0.1:%s")
    newServer{address="127.0.0.1:%d"}
    """

    def testConsoleAllowed(self):
        """
        Console: No key, the connection should not be allowed
        """
        self.assertRaises(socket.error, self.sendConsoleCommand, 'showVersion()')

class TestConsoleConcurrentConnections(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _maxConns = 2

    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort', '_maxConns']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")
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
        self.assertRaises(socket.error, self.sendConsoleCommand, 'showVersion()')

        # free one slot
        conns[0].close()
        conns[0] = None
        time.sleep(1)

        # this should work
        version = self.sendConsoleCommand('showVersion()')
        self.assertTrue(version.startswith('dnsdist '))
