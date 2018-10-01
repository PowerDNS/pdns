#!/usr/bin/env python
import base64
import dns
from socket import error as SocketError
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
        self.assertRaises(SocketError, self.sendConsoleCommand, 'showVersion()')

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
        self.assertRaises(SocketError, self.sendConsoleCommand, 'showVersion()')
