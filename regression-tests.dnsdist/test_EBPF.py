#!/usr/bin/env python
import base64
import dns
import os
import unittest
import pycurl

from dnsdisttests import DNSDistTest, pickAvailablePort

@unittest.skipUnless('ENABLE_SUDO_TESTS' in os.environ, "sudo is not available")
class TestSimpleEBPF(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _tlsServerPort = pickAvailablePort()
    _dohWithNGHTTP2ServerPort = pickAvailablePort()
    _doqServerPort = pickAvailablePort()
    _doh3ServerPort = pickAvailablePort()
    _dohWithNGHTTP2BaseURL = ("https://%s:%d/" % (_serverName, _dohWithNGHTTP2ServerPort))
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _doh3ServerPort))

    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}

    bpf = newBPFFilter({ipv4MaxItems=10, ipv6MaxItems=10, qnamesMaxItems=10})
    setDefaultBPFFilter(bpf)
    bpf:blockQName(newDNSName("blocked.ebpf.tests.powerdns.com."), 65535)
    bpf:blockQName(newDNSName("blocked-any-only.ebpf.tests.powerdns.com."), 255)

    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="openssl" })
    addDOHLocal("127.0.0.1:%d", "%s", "%s", {"/"}, {library="nghttp2"})
    addDOQLocal("127.0.0.1:%d", "%s", "%s")
    addDOH3Local("127.0.0.1:%d", "%s", "%s")

    """
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort', '_tlsServerPort', '_serverCert', '_serverKey', '_dohWithNGHTTP2ServerPort', '_serverCert', '_serverKey', '_doqServerPort', '_serverCert', '_serverKey', '_doh3ServerPort', '_serverCert', '_serverKey']
    _sudoMode = True

    def testNotBlocked(self):
        # unblock 127.0.0.1, just in case
        self.sendConsoleCommand('bpf:unblock(newCA("127.0.0.1"))')

        name = 'simplea.ebpf.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        for method in ["sendUDPQuery", "sendTCPQuery", "sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper", "sendDOQQueryWrapper", "sendDOH3QueryWrapper"]:
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response, timeout=1)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            if method == 'sendDOQQueryWrapper':
                # dnspython sets the ID to 0
                receivedResponse.id = response.id
            self.assertEqual(response, receivedResponse)

    def testQNameBlocked(self):
        # unblock 127.0.0.1, just in case
        self.sendConsoleCommand('bpf:unblock(newCA("127.0.0.1"))')

        name = 'blocked.ebpf.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        # should be blocked over Do53 UDP
        for method in ["sendUDPQuery"]:
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False, timeout=0.5)
            self.assertEqual(receivedResponse, None)

        # not over other protocols
        for method in ["sendTCPQuery", "sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper", "sendDOQQueryWrapper", "sendDOH3QueryWrapper"]:
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response, timeout=1)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            if method == 'sendDOQQueryWrapper':
                # dnspython sets the ID to 0
                receivedResponse.id = response.id
            self.assertEqual(response, receivedResponse)

    def testQNameBlockedOnlyForAny(self):
        # unblock 127.0.0.1, just in case
        self.sendConsoleCommand('bpf:unblock(newCA("127.0.0.1"))')

        name = 'blocked-any-only.ebpf.tests.powerdns.com.'
        query = dns.message.make_query(name, 'ANY', 'IN', use_edns=False)

        # ANY should be blocked over Do53 UDP
        for method in ["sendUDPQuery"]:
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False, timeout=0.5)
            self.assertEqual(receivedResponse, None)

        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        # but A should NOT be blocked
        for method in ["sendUDPQuery"]:
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response, timeout=1)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

    def testClientIPBlocked(self):
        # block 127.0.0.1
        self.sendConsoleCommand('bpf:block(newCA("127.0.0.1"))')

        name = 'ip-blocked.ebpf.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        # should be blocked over Do53 UDP, Do53 TCP, DoH
        for method in ["sendUDPQuery", "sendTCPQuery", "sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper"]:
            sender = getattr(self, method)
            try:
                (_, receivedResponse) = sender(query, response=None, useQueue=False, timeout=0.5)
                self.assertEqual(receivedResponse, None)
            except TimeoutError:
                pass
            except pycurl.error:
                pass

        # not over QUIC-based protocols
        for method in ["sendDOQQueryWrapper", "sendDOH3QueryWrapper"]:
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response, timeout=1)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            if method == 'sendDOQQueryWrapper':
                # dnspython sets the ID to 0
                receivedResponse.id = response.id
            self.assertEqual(response, receivedResponse)

        # unblock 127.0.0.1
        self.sendConsoleCommand('bpf:unblock(newCA("127.0.0.1"))')
