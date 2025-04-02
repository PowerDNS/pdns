#!/usr/bin/env python
import base64
import dns
import os
import unittest
import pycurl

from dnsdisttests import DNSDistTest, pickAvailablePort

class TestSNI(DNSDistTest):
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
    newServer{address="127.0.0.1:%d"}

    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="openssl" })
    addDOHLocal("127.0.0.1:%d", "%s", "%s", {"/"}, {library="nghttp2"})
    addDOQLocal("127.0.0.1:%d", "%s", "%s")
    addDOH3Local("127.0.0.1:%d", "%s", "%s")

    function displaySNI(dq)
      local sni = dq:getServerNameIndication()
      if sni ~= '%s' then
        return DNSAction.Spoof, '1.2.3.4'
      end
      return DNSAction.Allow
    end
    addAction(AllRule(), LuaAction(displaySNI))
    """
    _config_params = ['_testServerPort', '_tlsServerPort', '_serverCert', '_serverKey', '_dohWithNGHTTP2ServerPort', '_serverCert', '_serverKey', '_doqServerPort', '_serverCert', '_serverKey', '_doh3ServerPort', '_serverCert', '_serverKey', '_serverName']

    # enable these once Quiche > 0.22 is available, including https://github.com/cloudflare/quiche/pull/1895
    @unittest.skipUnless('ENABLE_SNI_TESTS_WITH_QUICHE' in os.environ, "SNI tests with Quiche are disabled")
    def testServerNameIndicationWithQuiche(self):
        name = 'simple.sni.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        for method in ["sendDOQQueryWrapper", "sendDOH3QueryWrapper"]:
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response, timeout=1)
            self.assertTrue(receivedQuery)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertTrue(receivedResponse)
            if method == 'sendDOQQueryWrapper':
                # dnspython sets the ID to 0
                receivedResponse.id = response.id
            self.assertEqual(response, receivedResponse)

    def testServerNameIndication(self):
        name = 'simple.sni.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        for method in ["sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper"]:
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response, timeout=1)
            self.assertTrue(receivedQuery)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(response, receivedResponse)
