#!/usr/bin/env python
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort

class IncomingProtocol:
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _tlsServerPort = pickAvailablePort()
    _dohWithNGHTTP2ServerPort = pickAvailablePort()
    _dohWithNGHTTP2BaseURL = ("https://%s:%d/dns-query" % (_serverName, _dohWithNGHTTP2ServerPort))
    _doqServerPort = pickAvailablePort()
    _doh3ServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _doh3ServerPort))

    def testIncomingProtocolRule(self):
        """
        Incoming protocol
        """
        name = 'incoming-protocol.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist sets RA = RD for TC responses
        query.flags &= ~dns.flags.RD

        for method in ["sendUDPQuery", "sendTCPQuery", "sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper", "sendDOQQueryWrapper", "sendDOH3QueryWrapper"]:
            sender = getattr(self, method)
            expectedResponse = dns.message.make_response(query)
            rrset = dns.rrset.from_text(name,
                                        60,
                                        dns.rdataclass.IN,
                                        dns.rdatatype.CNAME,
                                        method + ".")
            expectedResponse.answer.append(rrset)

            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            if method in ['sendDOQQueryWrapper', 'sendDOH3QueryWrapper']:
                # dnspython sets the ID to 0
                receivedResponse.id = expectedResponse.id
            self.assertEqual(expectedResponse, receivedResponse)

class IncomingProtocolLuaConfig(DNSDistTest, IncomingProtocol):
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="openssl" })
    addDOHLocal("127.0.0.1:%d", "%s", "%s", {"/dns-query"}, {library="nghttp2"})
    addDOQLocal("127.0.0.1:%d", "%s", "%s")
    addDOH3Local("127.0.0.1:%d", "%s", "%s")

    addAction(IncomingProtocolRule("DoUDP"), SpoofCNAMEAction("sendUDPQuery"))
    addAction(IncomingProtocolRule("DoTCP"), SpoofCNAMEAction("sendTCPQuery"))
    addAction(IncomingProtocolRule("DoT"), SpoofCNAMEAction("sendDOTQueryWrapper"))
    addAction(IncomingProtocolRule("DoH"), SpoofCNAMEAction("sendDOHWithNGHTTP2QueryWrapper"))
    addAction(IncomingProtocolRule("DoQ"), SpoofCNAMEAction("sendDOQQueryWrapper"))
    addAction(IncomingProtocolRule("DoH3"), SpoofCNAMEAction("sendDOH3QueryWrapper"))
    """
    _config_params = ['_testServerPort', '_tlsServerPort', '_serverCert', '_serverKey', '_dohWithNGHTTP2ServerPort', '_serverCert', '_serverKey', '_doqServerPort', '_serverCert', '_serverKey', '_doh3ServerPort', '_serverCert', '_serverKey']

class IncomingProtocolYAMLConfig(DNSDistTest, IncomingProtocol):
    _yaml_config_template = """
logging:
  structured:
    enabled: false
backends:
  - address: "127.0.0.1:%d"
    protocol: Do53
binds:
  - listen_address: "127.0.0.1:%d"
    reuseport: true
    protocol: "DoT"
    tls:
      certificates:
        - certificate: "%s"
          key: "%s"
  - listen_address: "127.0.0.1:%d"
    reuseport: true
    protocol: "DoH"
    tls:
      certificates:
        - certificate: "%s"
          key: "%s"
    doh:
      provider: "nghttp2"
  - listen_address: "127.0.0.1:%d"
    reuseport: true
    protocol: "DoQ"
    tls:
      certificates:
        - certificate: "%s"
          key: "%s"
  - listen_address: "127.0.0.1:%d"
    reuseport: true
    protocol: "DoH3"
    tls:
      certificates:
        - certificate: "%s"
          key: "%s"
query_rules:
  - name: "DoUDP"
    selector:
      type: "IncomingProtocol"
      protocol: "DoUDP"
    action:
      type: "SpoofCNAME"
      cname: "sendUDPQuery"
  - name: "DoTCP"
    selector:
      type: "IncomingProtocol"
      protocol: "DoTCP"
    action:
      type: "SpoofCNAME"
      cname: "sendTCPQuery"
  - name: "DoT"
    selector:
      type: "IncomingProtocol"
      protocol: "DoT"
    action:
      type: "SpoofCNAME"
      cname: "sendDOTQueryWrapper"
  - name: "DoH"
    selector:
      type: "IncomingProtocol"
      protocol: "DoH"
    action:
      type: "SpoofCNAME"
      cname: "sendDOHWithNGHTTP2QueryWrapper"
  - name: "DoQ"
    selector:
      type: "IncomingProtocol"
      protocol: "DoQ"
    action:
      type: "SpoofCNAME"
      cname: "sendDOQQueryWrapper"
  - name: "DoH3"
    selector:
      type: "IncomingProtocol"
      protocol: "DoH3"
    action:
      type: "SpoofCNAME"
      cname: "sendDOH3QueryWrapper"
"""
    _config_params = []
    _yaml_config_params = ['_testServerPort', '_tlsServerPort', '_serverCert', '_serverKey', '_dohWithNGHTTP2ServerPort', '_serverCert', '_serverKey', '_doqServerPort', '_serverCert', '_serverKey', '_doh3ServerPort', '_serverCert', '_serverKey']
    _checkConfigExpectedOutput = b"DNS over HTTPS configured\nConfiguration 'configs/dnsdist_IncomingProtocolYAMLConfig.yml' OK!\n"
