#!/usr/bin/env python
import base64
import dns
import time
from dnsdisttests import DNSDistTest, pickAvailablePort
import extendederrors

class TestConfigurationUpdates(DNSDistTest):
    _yaml_config_template = """---
logging:
  structured:
    enabled: false

console:
  listen_address: "127.0.0.1:%d"
  key: "%s"
  acl:
    - 127.0.0.0/8

binds:
  - listen_address: "127.0.0.1:%d"
    protocol: Do53
  - listen_address: "127.0.0.1:%d"
    protocol: "DoT"
    tls:
      certificates:
        - certificate: "%s"
          key: "%s"
      provider: "openssl"
  - listen_address: "127.0.0.1:%d"
    protocol: "DoH"
    tls:
      certificates:
        - certificate: "%s"
          key: "%s"
    doh:
      provider: "nghttp2"
      paths:
        - "/"
  - listen_address: "127.0.0.1:%d"
    protocol: "DoQ"
    tls:
      certificates:
        - certificate: "%s"
          key: "%s"
  - listen_address: "127.0.0.1:%d"
    protocol: "DoH3"
    tls:
      certificates:
        - certificate: "%s"
          key: "%s"

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53
  - address: "127.0.0.1:%d"
    protocol: Do53
    tcp_only: true
    pools:
      - "tcp-pool"

query_rules:
  - name: "route TCP response test to the TCP-only pool"
    selector:
      type: "QName"
      qname: "TCP-response.config-updates.test.powerdns.com."
    action:
      type: "Pool"
      pool_name: "tcp-pool"
"""
    _dnsDistPort = pickAvailablePort()
    _tlsServerPort = pickAvailablePort()
    _dohWithNGHTTP2ServerPort = pickAvailablePort()
    _doqServerPort = pickAvailablePort()
    _doh3ServerPort = pickAvailablePort()
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _dohWithNGHTTP2BaseURL = ("https://%s:%d/" % (_serverName, _dohWithNGHTTP2ServerPort))
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _doh3ServerPort))
    _caCert = 'ca.pem'
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _consolePort = pickAvailablePort()
    _testServerPort = pickAvailablePort()
    _yaml_config_params = ['_consolePort', '_consoleKeyB64', '_dnsDistPort', '_tlsServerPort', '_serverCert', '_serverKey', '_dohWithNGHTTP2ServerPort', '_serverCert', '_serverKey', '_doqServerPort','_serverCert', '_serverKey', '_doh3ServerPort', '_serverCert', '_serverKey', '_testServerPort', '_testServerPort']
    _config_params = []
    _checkConfigExpectedOutput = b"DNS over HTTPS configured\nConfiguration 'configs/dnsdist_TestConfigurationUpdates.yml' OK!\n"

    def testRegular(self):
        """
        Configuration updates: regular
        """
        for protocol in ['UDP', 'TCP', 'DOT', 'DOH', 'DOQ', 'DOH3']:
            name = f'regular-{protocol}.config-updates.test.powerdns.com.'
            query = dns.message.make_query(name, 'A', 'IN')
            query.flags &= ~dns.flags.RD
            response = dns.message.make_response(query)
            rrset = dns.rrset.from_text(name,
                                        60,
                                        dns.rdataclass.IN,
                                        dns.rdatatype.A,
                                       '127.0.0.1')

            response.answer.append(rrset)

            method = f'send{protocol}Query'
            if not protocol in ['UDP', 'TCP']:
                if protocol == 'DOH':
                    method = 'sendDOHWithNGHTTP2QueryWrapper'
                else:
                    method += 'Wrapper'
            sender = getattr(self, method)

            (receivedQuery, receivedResponse) = sender(query, response=response)
            receivedQuery.id = query.id
            self.assertEqual(receivedQuery, query)
            self.assertEqual(receivedResponse, response)

            self.sendConsoleCommand(f'addAction(QNameRule("{name}"), RCodeAction(DNSRCode.REFUSED))')

            # the configuration should have been updated
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.REFUSED)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, response)

    def testResponseRule(self):
        """
        Configuration updates: response
        """
        for protocol in ['UDP', 'TCP']:
            name = f'{protocol}-response.config-updates.test.powerdns.com.'
            query = dns.message.make_query(name, 'A', 'IN')
            query.flags &= ~dns.flags.RD
            response = dns.message.make_response(query)
            rrset = dns.rrset.from_text(name,
                                        60,
                                        dns.rdataclass.IN,
                                        dns.rdatatype.A,
                                       '127.0.0.1')

            response.answer.append(rrset)

            method = f'send{protocol}Query'
            sender = getattr(self, method)

            (receivedQuery, receivedResponse) = sender(query, response=response)
            receivedQuery.id = query.id
            self.assertEqual(receivedQuery, query)
            self.assertEqual(receivedResponse, response)

            self.sendConsoleCommand(f'addResponseAction(QNameRule("{name}"), SetExtendedDNSErrorResponseAction(15))')
            if protocol == 'TCP':
                time.sleep(1)

            # the configuration should have been updated
            expectedResponse = dns.message.make_response(query)
            ede = extendederrors.ExtendedErrorOption(15, b'')
            expectedResponse.use_edns(edns=True, payload=4096, options=[ede])
            expectedResponse.answer.append(rrset)
            (_, receivedResponse) = sender(query, response=response)
            self.assertEqual(receivedResponse, expectedResponse)

class TestConfigurationUpdatesRecvMMSG(DNSDistTest):
    _yaml_config_template = """---
console:
  listen_address: "127.0.0.1:%d"
  key: "%s"
  acl:
    - 127.0.0.0/8

binds:
  - listen_address: "127.0.0.1:%d"
    protocol: Do53

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53

tuning:
  udp:
    messages_per_round: 10
"""
    _dnsDistPort = pickAvailablePort()
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _consolePort = pickAvailablePort()
    _testServerPort = pickAvailablePort()
    _yaml_config_params = ['_consolePort', '_consoleKeyB64', '_dnsDistPort', '_testServerPort']
    _config_params = []

    def testRecvMMSGUDP(self):
        """
        Configuration updates: recvmmsg UDP
        """
        name = 'recvmmsg-udp.config-updates.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response=response)
        receivedQuery.id = query.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)

        self.sendConsoleCommand(f'addAction(QNameRule("{name}"), RCodeAction(DNSRCode.REFUSED))')

        # the configuration should have been updated
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, response)

    def testUDPResponseRule(self):
        """
        Configuration updates: UDP response
        """
        name = 'recvmmsg-udp-response.config-updates.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')

        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response=response)
        receivedQuery.id = query.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)

        self.sendConsoleCommand(f'addResponseAction(QNameRule("{name}"), SetExtendedDNSErrorResponseAction(15))')

        # the configuration should have been updated
        expectedResponse = dns.message.make_response(query)
        ede = extendederrors.ExtendedErrorOption(15, b'')
        expectedResponse.use_edns(edns=True, payload=4096, options=[ede])
        expectedResponse.answer.append(rrset)
        (_, receivedResponse) = self.sendUDPQuery(query, response=response)
        self.assertEqual(receivedResponse, expectedResponse)
