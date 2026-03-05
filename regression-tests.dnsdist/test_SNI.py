#!/usr/bin/env python
import dns
import os
import unittest
import ssl

from dnsdisttests import DNSDistTest, pickAvailablePort


class TestSNI(DNSDistTest):
    _serverKey = "server.key"
    _serverCert = "server.chain"
    _serverKeyEC = "server-ec.key"
    _serverCertEC = "server-ec.chain"
    _serverKey2 = "server2.key"
    _serverCert2 = "server2.chain"
    _serverName = "tls.tests.dnsdist.org"
    _serverName2 = "tls2.tests.dnsdist.org"
    _serverName3 = "unknown.tests.dnsdist.org"
    _caCert = "ca.pem"
    _tlsServerPort = pickAvailablePort()
    _dohWithNGHTTP2ServerPort = pickAvailablePort()
    _doqServerPort = pickAvailablePort()
    _doh3ServerPort = pickAvailablePort()
    _dohWithNGHTTP2BaseURL = "https://%s:%d/" % (_serverName, _dohWithNGHTTP2ServerPort)
    _dohBaseURL = "https://%s:%d/" % (_serverName, _doh3ServerPort)

    _config_template = """
    newServer{address="127.0.0.1:%d"}

    local certs = {"%s", "%s", "%s"}
    local keys = {"%s", "%s", "%s"}
    local single_cert = "%s"
    local single_key = "%s"
    addTLSLocal("127.0.0.1:%d", certs, keys, { provider="openssl" })
    addDOHLocal("127.0.0.1:%d", certs, keys, {"/"}, {library="nghttp2"})
    addDOQLocal("127.0.0.1:%d", single_cert, single_key)
    addDOH3Local("127.0.0.1:%d", single_cert, single_key)

    function checkSNI(dq)
      local sni = dq:getServerNameIndication()
      if tostring(dq.qname) == 'simple.sni.tests.powerdns.com.' and sni ~= '%s' then
        return DNSAction.Spoof, '1.2.3.4'
      end
      if tostring(dq.qname) == 'name2.sni.tests.powerdns.com.' and sni ~= '%s' then
        return DNSAction.Spoof, '2.3.4.5'
      end
      if tostring(dq.qname) == 'unknown.sni.tests.powerdns.com.' and sni ~= '%s' then
        return DNSAction.Spoof, '3.4.5.6'
      end
      if tostring(dq.qname) == 'ecdsa.sni.tests.powerdns.com.' and sni ~= '%s' then
        return DNSAction.Spoof, '4.5.6.7'
      end
      if tostring(dq.qname) == 'rsa.sni.tests.powerdns.com.' and sni ~= '%s' then
        return DNSAction.Spoof, '4.5.6.7'
      end
      return DNSAction.Allow
    end
    addAction(AllRule(), LuaAction(checkSNI))
    """
    _config_params = [
        "_testServerPort",
        "_serverCert",
        "_serverCertEC",
        "_serverCert2",
        "_serverKey",
        "_serverKeyEC",
        "_serverKey2",
        "_serverCert",
        "_serverKey",
        "_tlsServerPort",
        "_dohWithNGHTTP2ServerPort",
        "_doqServerPort",
        "_doh3ServerPort",
        "_serverName",
        "_serverName2",
        "_serverName3",
        "_serverName",
        "_serverName",
    ]

    @unittest.skipUnless("ENABLE_SNI_TESTS_WITH_QUICHE" in os.environ, "SNI tests with Quiche are disabled")
    def testServerNameIndicationWithQuiche(self):
        name = "simple.sni.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN", use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        response.answer.append(rrset)
        for method in ["sendDOQQueryWrapper", "sendDOH3QueryWrapper"]:
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response, timeout=1)
            self.assertTrue(receivedQuery)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertTrue(receivedResponse)
            if method == "sendDOQQueryWrapper":
                # dnspython sets the ID to 0
                receivedResponse.id = response.id
            self.assertEqual(response, receivedResponse)

    def testServerNameIndication(self):
        name = "simple.sni.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN", use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        response.answer.append(rrset)
        for method in ["sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper"]:
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response, timeout=1)
            self.assertTrue(receivedQuery)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(response, receivedResponse)

        # check second certificate
        name = "name2.sni.tests.powerdns.com."
        self._dohWithNGHTTP2BaseURL = "https://%s:%d/" % (self._serverName2, self._dohWithNGHTTP2ServerPort)
        query = dns.message.make_query(name, "A", "IN", use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        response.answer.append(rrset)
        for method in ["sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper"]:
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response, timeout=1, serverName=self._serverName2)
            self.assertTrue(receivedQuery)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(response, receivedResponse)

        # check SNI for an unknown name, we should get the first certificate
        name = "unknown.sni.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN", use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        response.answer.append(rrset)

        sslctx = ssl.create_default_context(cafile=self._caCert)
        sslctx.check_hostname = False
        if hasattr(sslctx, "set_alpn_protocols"):
            sslctx.set_alpn_protocols(self._serverName3)

        conn = self.openTLSConnection(self._tlsServerPort, self._serverName3, self._caCert, timeout=1, sslctx=sslctx)
        self.sendTCPQueryOverConnection(conn, query, response=response, timeout=1)
        (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True, timeout=1)
        receivedQuery.id = query.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)

        cert = conn.getpeercert()
        subject = cert["subject"]
        altNames = cert["subjectAltName"]
        self.assertEqual(dict(subject[0])["commonName"], "tls.tests.dnsdist.org")
        self.assertEqual(dict(subject[1])["organizationalUnitName"], "PowerDNS.com BV")
        names = []
        for entry in altNames:
            names.append(entry[1])
        self.assertEqual(names, ["tls.tests.dnsdist.org", "powerdns.com", "127.0.0.1"])

        # check that we provide the correct RSA/ECDSA certificate when requested
        for algo in ["rsa", "ecdsa"]:
            name = algo + ".sni.tests.powerdns.com."
            query = dns.message.make_query(name, "A", "IN", use_edns=False)
            response = dns.message.make_response(query)
            rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
            response.answer.append(rrset)

            sslctx = ssl.create_default_context(cafile=self._caCert)
            if hasattr(sslctx, "set_alpn_protocols"):
                sslctx.set_alpn_protocols(self._serverName)
            # disable TLS 1.3 because configuring the signature algorithm is not supported by Python yet
            sslctx.maximum_version = ssl.TLSVersion.TLSv1_2
            # explicitly request authentication via RSA or ECDSA
            sslctx.set_ciphers("a" + algo.upper())

            conn = self.openTLSConnection(self._tlsServerPort, self._serverName, self._caCert, timeout=1, sslctx=sslctx)
            self.sendTCPQueryOverConnection(conn, query, response=response, timeout=1)
            (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True, timeout=1)
            receivedQuery.id = query.id
            self.assertEqual(receivedQuery, query)
            self.assertEqual(receivedResponse, response)

            cert = conn.getpeercert()
            subject = cert["subject"]
            altNames = cert["subjectAltName"]
            self.assertEqual(dict(subject[0])["commonName"], "tls.tests.dnsdist.org")
            self.assertEqual(dict(subject[1])["organizationalUnitName"], "PowerDNS.com BV")
            names = []
            for entry in altNames:
                names.append(entry[1])
            self.assertEqual(names, ["tls.tests.dnsdist.org", "powerdns.com", "127.0.0.1"])
