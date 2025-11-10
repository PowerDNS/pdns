#!/usr/bin/env python

import base64
import dns
import os
import time
import subprocess
import unittest
import clientsubnetoption

from dnsdistdohtests import DNSDistDOHTest
from dnsdisttests import DNSDistTest, pickAvailablePort

import pycurl
from io import BytesIO

class DOHTests(object):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _customResponseHeader1 = 'access-control-allow-origin: *'
    _customResponseHeader2 = 'user-agent: derp'
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    newServer{address="127.0.0.1:%d"}

    addAction("drop.doh.tests.powerdns.com.", DropAction())
    addAction("refused.doh.tests.powerdns.com.", RCodeAction(DNSRCode.REFUSED))
    addAction("spoof.doh.tests.powerdns.com.", SpoofAction("1.2.3.4"))
    addAction(HTTPHeaderRule("X-PowerDNS", "^[a]{5}$"), SpoofAction("2.3.4.5"))
    addAction(HTTPPathRule("/PowerDNS"), SpoofAction("3.4.5.6"))
    addAction(HTTPPathRegexRule("^/PowerDNS-[0-9]"), SpoofAction("6.7.8.9"))
    addAction("http-status-action.doh.tests.powerdns.com.", HTTPStatusAction(200, "Plaintext answer", "text/plain"))
    addAction("http-status-action-redirect.doh.tests.powerdns.com.", HTTPStatusAction(307, "https://doh.powerdns.org"))
    addAction("no-backend.doh.tests.powerdns.com.", PoolAction('this-pool-has-no-backend'))

    function dohHandler(dq)
      if dq:getHTTPScheme() == 'https' and dq:getHTTPHost() == '%s:%d' and dq:getHTTPPath() == '/' and dq:getHTTPQueryString() == '' then
        local foundct = false
        for key,value in pairs(dq:getHTTPHeaders()) do
          if key == 'content-type' and value == 'application/dns-message' then
            foundct = true
            break
          end
        end
        if foundct then
          dq:setHTTPResponse(200, 'It works!', 'text/plain')
          dq.dh:setQR(true)
          return DNSAction.HeaderModify
        end
      end
      return DNSAction.None
    end
    addAction("http-lua.doh.tests.powerdns.com.", LuaAction(dohHandler))

    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/", "/coffee", "/PowerDNS", "/PowerDNS2", "/PowerDNS-999" }, {customResponseHeaders={["access-control-allow-origin"]="*",["user-agent"]="derp",["UPPERCASE"]="VaLuE"}, keepIncomingHeaders=true, library='%s'})
    dohFE = getDOHFrontend(0)
    dohFE:setResponsesMap({newDOHResponseMapEntry('^/coffee$', 418, 'C0FFEE', {['FoO']='bar'})})
    """
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort', '_serverName', '_dohServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_dohLibrary']
    _verboseMode = True

    def testDOHSimple(self):
        """
        DOH: Simple query
        """
        name = 'simple.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.assertTrue((self._customResponseHeader1) in self._response_headers.decode())
        self.assertTrue((self._customResponseHeader2) in self._response_headers.decode())
        self.assertFalse(('UPPERCASE: VaLuE' in self._response_headers.decode()))
        self.assertTrue(('uppercase: VaLuE' in self._response_headers.decode()))
        self.assertTrue(('cache-control: max-age=3600' in self._response_headers.decode()))
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.checkHasHeader('cache-control', 'max-age=3600')

    def testDOHTransactionID(self):
        """
        DOH: Simple query with ID != 0
        """
        name = 'simple-with-non-zero-id.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 42
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)
        # just to be sure the ID _is_ checked
        self.assertEqual(response.id, receivedResponse.id)

    def testDOHSimplePOST(self):
        """
        DOH: Simple POST query
        """
        name = 'simple-post.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendDOHPostQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)

    def testDOHExistingEDNS(self):
        """
        DOH: Existing EDNS
        """
        name = 'existing-edns.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=8192)
        query.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.checkQueryEDNSWithoutECS(query, receivedQuery)
        self.checkResponseEDNSWithoutECS(response, receivedResponse)

    def testDOHExistingECS(self):
        """
        DOH: Existing EDNS Client Subnet
        """
        name = 'existing-ecs.doh.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('1.2.3.4')
        rewrittenEcso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=512, options=[ecso], want_dnssec=True)
        query.id = 0
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=4096, options=[rewrittenEcso])
        response.want_dnssec(True)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.checkQueryEDNSWithECS(query, receivedQuery)
        self.checkResponseEDNSWithECS(response, receivedResponse)

    def testDropped(self):
        """
        DOH: Dropped query
        """
        name = 'drop.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, caFile=self._caCert, query=query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)

    def testRefused(self):
        """
        DOH: Refused
        """
        name = 'refused.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.id = 0
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, caFile=self._caCert, query=query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)

    def testSpoof(self):
        """
        DOH: Spoofed
        """
        name = 'spoof.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.id = 0
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '1.2.3.4')
        expectedResponse.answer.append(rrset)

        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, caFile=self._caCert, query=query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)

    def testDOHWithoutQuery(self):
        """
        DOH: Empty GET query
        """
        url = self._dohBaseURL
        conn = self.openDOHConnection(self._dohServerPort, self._caCert, timeout=2.0)
        conn.setopt(pycurl.URL, url)
        conn.setopt(pycurl.RESOLVE, ["%s:%d:127.0.0.1" % (self._serverName, self._dohServerPort)])
        conn.setopt(pycurl.SSL_VERIFYPEER, 1)
        conn.setopt(pycurl.SSL_VERIFYHOST, 2)
        conn.setopt(pycurl.CAINFO, self._caCert)
        conn.perform_rb()
        rcode = conn.getinfo(pycurl.RESPONSE_CODE)
        self.assertEqual(rcode, 400)

    def testDOHZeroQDCount(self):
        """
        DOH: qdcount == 0
        """
        if self._dohLibrary == 'h2o':
            raise unittest.SkipTest('h2o tries to parse the qname early, so this check will fail')
        query = dns.message.Message()
        query.id = 0
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.NOTIMP)

        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, caFile=self._caCert, query=query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)

    def testDOHShortPath(self):
        """
        DOH: Short path in GET query
        """
        url = self._dohBaseURL + '/AA'
        conn = self.openDOHConnection(self._dohServerPort, self._caCert, timeout=2.0)
        conn.setopt(pycurl.URL, url)
        conn.setopt(pycurl.RESOLVE, ["%s:%d:127.0.0.1" % (self._serverName, self._dohServerPort)])
        conn.setopt(pycurl.SSL_VERIFYPEER, 1)
        conn.setopt(pycurl.SSL_VERIFYHOST, 2)
        conn.setopt(pycurl.CAINFO, self._caCert)
        conn.perform_rb()
        rcode = conn.getinfo(pycurl.RESPONSE_CODE)
        self.assertEqual(rcode, 404)

    def testDOHQueryNoParameter(self):
        """
        DOH: No parameter GET query
        """
        name = 'no-parameter-get.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        wire = query.to_wire()
        b64 = base64.urlsafe_b64encode(wire).decode('UTF8').rstrip('=')
        url = self._dohBaseURL + '?not-dns=' + b64
        conn = self.openDOHConnection(self._dohServerPort, self._caCert, timeout=2.0)
        conn.setopt(pycurl.URL, url)
        conn.setopt(pycurl.RESOLVE, ["%s:%d:127.0.0.1" % (self._serverName, self._dohServerPort)])
        conn.setopt(pycurl.SSL_VERIFYPEER, 1)
        conn.setopt(pycurl.SSL_VERIFYHOST, 2)
        conn.setopt(pycurl.CAINFO, self._caCert)
        conn.perform_rb()
        rcode = conn.getinfo(pycurl.RESPONSE_CODE)
        self.assertEqual(rcode, 400)

    def testDOHQueryInvalidBase64(self):
        """
        DOH: Invalid Base64 GET query
        """
        name = 'invalid-b64-get.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        url = self._dohBaseURL + '?dns=' + '_-~~~~-_'
        conn = self.openDOHConnection(self._dohServerPort, self._caCert, timeout=2.0)
        conn.setopt(pycurl.URL, url)
        conn.setopt(pycurl.RESOLVE, ["%s:%d:127.0.0.1" % (self._serverName, self._dohServerPort)])
        conn.setopt(pycurl.SSL_VERIFYPEER, 1)
        conn.setopt(pycurl.SSL_VERIFYHOST, 2)
        conn.setopt(pycurl.CAINFO, self._caCert)
        conn.perform_rb()
        rcode = conn.getinfo(pycurl.RESPONSE_CODE)
        self.assertEqual(rcode, 400)

    def testDOHInvalidDNSHeaders(self):
        """
        DOH: Invalid DNS headers
        """
        name = 'invalid-dns-headers.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.flags |= dns.flags.QR
        wire = query.to_wire()
        b64 = base64.urlsafe_b64encode(wire).decode('UTF8').rstrip('=')
        url = self._dohBaseURL + '?dns=' + b64
        conn = self.openDOHConnection(self._dohServerPort, self._caCert, timeout=2.0)
        conn.setopt(pycurl.URL, url)
        conn.setopt(pycurl.RESOLVE, ["%s:%d:127.0.0.1" % (self._serverName, self._dohServerPort)])
        conn.setopt(pycurl.SSL_VERIFYPEER, 1)
        conn.setopt(pycurl.SSL_VERIFYHOST, 2)
        conn.setopt(pycurl.CAINFO, self._caCert)
        conn.perform_rb()
        rcode = conn.getinfo(pycurl.RESPONSE_CODE)
        self.assertEqual(rcode, 400)

    def testDOHQueryInvalidMethod(self):
        """
        DOH: Invalid method
        """
        if self._dohLibrary == 'h2o':
            raise unittest.SkipTest('h2o does not check the HTTP method')
        name = 'invalid-method.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        wire = query.to_wire()
        b64 = base64.urlsafe_b64encode(wire).decode('UTF8').rstrip('=')
        url = self._dohBaseURL + '?dns=' + b64
        conn = self.openDOHConnection(self._dohServerPort, self._caCert, timeout=2)
        conn.setopt(pycurl.URL, url)
        conn.setopt(pycurl.RESOLVE, ["%s:%d:127.0.0.1" % (self._serverName, self._dohServerPort)])
        conn.setopt(pycurl.SSL_VERIFYPEER, 1)
        conn.setopt(pycurl.SSL_VERIFYHOST, 2)
        conn.setopt(pycurl.CAINFO, self._caCert)
        conn.setopt(pycurl.CUSTOMREQUEST, 'PATCH')
        conn.perform_rb()
        rcode = conn.getinfo(pycurl.RESPONSE_CODE)
        self.assertEqual(rcode, 400)

    def testDOHQueryInvalidALPN(self):
        """
        DOH: Invalid ALPN
        """
        alpn = ['bogus-alpn']
        conn = self.openTLSConnection(self._dohServerPort, self._serverName, self._caCert, alpn=alpn)
        try:
            conn.send('AAAA')
            response = conn.recv(65535)
            self.assertFalse(response)
        except:
            pass

    metricMap = {
        'connects': 2,
        'http/1.1': 3,
        'http/2': 4,
    }

    def getHTTPCounter(self, name):
        lines = self.sendConsoleCommand("showDOHFrontends()").splitlines()
        self.assertEqual(len(lines), 2)
        metrics = lines[1].split()
        self.assertEqual(len(metrics), 15)
        return int(metrics[self.metricMap[name]])

    def testDOHHTTP1(self):
        """
        DOH: HTTP/1.1
        """
        if self._dohLibrary == 'h2o':
            raise unittest.SkipTest('h2o supports HTTP/1.1, this test is only relevant for nghttp2')
        httpConnections = self.getHTTPCounter('connects')
        http1 = self.getHTTPCounter('http/1.1')
        http2 = self.getHTTPCounter('http/2')
        name = 'http11.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        wire = query.to_wire()
        b64 = base64.urlsafe_b64encode(wire).decode('UTF8').rstrip('=')
        url = self._dohBaseURL + '?dns=' + b64
        responseHeaders = BytesIO()
        conn = pycurl.Curl()
        conn.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_1_1)
        conn.setopt(pycurl.HTTPHEADER, ["Content-type: application/dns-message",
                                         "Accept: application/dns-message"])
        conn.setopt(pycurl.URL, url)
        conn.setopt(pycurl.RESOLVE, ["%s:%d:127.0.0.1" % (self._serverName, self._dohServerPort)])
        conn.setopt(pycurl.SSL_VERIFYPEER, 1)
        conn.setopt(pycurl.SSL_VERIFYHOST, 2)
        conn.setopt(pycurl.CAINFO, self._caCert)
        conn.setopt(pycurl.HEADERFUNCTION, responseHeaders.write)
        data = conn.perform_rb()
        rcode = conn.getinfo(pycurl.RESPONSE_CODE)
        responseHeaders = responseHeaders.getvalue()
        self.assertEqual(rcode, 400)
        self.assertEqual(data, b'<html><body>This server implements RFC 8484 - DNS Queries over HTTP, and requires HTTP/2 in accordance with section 5.2 of the RFC.</body></html>\r\n')
        self.assertEqual(self.getHTTPCounter('connects'), httpConnections + 1)
        self.assertEqual(self.getHTTPCounter('http/1.1'), http1 + 1)
        self.assertEqual(self.getHTTPCounter('http/2'), http2)

        dateFound = False
        for header in responseHeaders.decode().splitlines(False):
            values = header.split(':')
            key = values[0]
            if key.lower() == 'date':
                dateFound = True
                break
        self.assertTrue(dateFound)

    def testDOHHTTP1NotSelectedOverH2(self):
        """
        DOH: Check that HTTP/1.1 is not selected over H2 when offered in the wrong order by the client
        """
        if self._dohLibrary == 'h2o':
            raise unittest.SkipTest('h2o supports HTTP/1.1, this test is only relevant for nghttp2')
        alpn = ['http/1.1', 'h2']
        conn = self.openTLSConnection(self._dohServerPort, self._serverName, self._caCert, alpn=alpn)
        if not hasattr(conn, 'selected_alpn_protocol'):
            raise unittest.SkipTest('Unable to check the selected ALPN, Python version is too old to support selected_alpn_protocol')
        self.assertEqual(conn.selected_alpn_protocol(), 'h2')

    def testDOHInvalid(self):
        """
        DOH: Invalid DNS query
        """
        name = 'invalid.doh.tests.powerdns.com.'
        invalidQuery = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        invalidQuery.id = 0
        # first an invalid query
        invalidQuery = invalidQuery.to_wire()
        invalidQuery = invalidQuery[:-5]
        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, caFile=self._caCert, query=invalidQuery, response=None, useQueue=False, rawQuery=True)
        self.assertEqual(receivedResponse, None)

        # and now a valid one
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)

    def testDOHInvalidHeaderName(self):
        """
        DOH: Invalid HTTP header name query
        """
        name = 'invalid-header-name.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        # this header is invalid, see rfc9113 section 8.2.1. Field Validity
        customHeaders = ['{}: test']
        try:
            (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert, customHeaders=customHeaders)
            self.assertFalse(receivedQuery)
            self.assertFalse(receivedResponse)
        except pycurl.error:
            pass

    def testDOHNoBackend(self):
        """
        DOH: No backend
        """
        if self._dohLibrary == 'h2o':
            raise unittest.SkipTest('h2o does not check the HTTP method')
        name = 'no-backend.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        wire = query.to_wire()
        b64 = base64.urlsafe_b64encode(wire).decode('UTF8').rstrip('=')
        url = self._dohBaseURL + '?dns=' + b64
        conn = self.openDOHConnection(self._dohServerPort, self._caCert, timeout=2)
        conn.setopt(pycurl.URL, url)
        conn.setopt(pycurl.RESOLVE, ["%s:%d:127.0.0.1" % (self._serverName, self._dohServerPort)])
        conn.setopt(pycurl.SSL_VERIFYPEER, 1)
        conn.setopt(pycurl.SSL_VERIFYHOST, 2)
        conn.setopt(pycurl.CAINFO, self._caCert)
        conn.perform_rb()
        rcode = conn.getinfo(pycurl.RESPONSE_CODE)
        self.assertEqual(rcode, 403)

    def testDOHEmptyPOST(self):
        """
        DOH: Empty POST query
        """
        name = 'empty-post.doh.tests.powerdns.com.'

        (_, receivedResponse) = self.sendDOHPostQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query="", rawQuery=True, response=None, caFile=self._caCert)
        self.assertEqual(receivedResponse, None)

        # and now a valid one
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        (receivedQuery, receivedResponse) = self.sendDOHPostQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)

    def testHeaderRule(self):
        """
        DOH: HeaderRule
        """
        name = 'header-rule.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.id = 0
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '2.3.4.5')
        expectedResponse.answer.append(rrset)

        # this header should match
        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, caFile=self._caCert, query=query, response=None, useQueue=False, customHeaders=['x-powerdnS: aaaaa'])
        self.assertEqual(receivedResponse, expectedResponse)

        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.flags &= ~dns.flags.RD
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        # this content of the header should NOT match
        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert, customHeaders=['x-powerdnS: bbbbb'])
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)

    def testHTTPPath(self):
        """
        DOH: HTTPPath
        """
        name = 'http-path.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.id = 0
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '3.4.5.6')
        expectedResponse.answer.append(rrset)

        # this path should match
        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL + 'PowerDNS', caFile=self._caCert, query=query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)

        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        expectedQuery.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        # this path should NOT match
        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL + "PowerDNS2", query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # this path is not in the URLs map and should lead to a 404
        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL + "PowerDNS/something", query, caFile=self._caCert, useQueue=False, rawResponse=True)
        self.assertTrue(receivedResponse)
        self.assertEqual(receivedResponse, b'there is no endpoint configured for this path')
        self.assertEqual(self._rcode, 404)

    def testHTTPPathRegex(self):
        """
        DOH: HTTPPathRegex
        """
        name = 'http-path-regex.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.id = 0
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '6.7.8.9')
        expectedResponse.answer.append(rrset)

        # this path should match
        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL + 'PowerDNS-999', caFile=self._caCert, query=query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)

        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        expectedQuery.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        # this path should NOT match
        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL + "PowerDNS2", query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)

    def testHTTPStatusAction200(self):
        """
        DOH: HTTPStatusAction 200 OK
        """
        name = 'http-status-action.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0

        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, useQueue=False, rawResponse=True)
        self.assertTrue(receivedResponse)
        self.assertEqual(receivedResponse, b'Plaintext answer')
        self.assertEqual(self._rcode, 200)
        self.assertTrue('content-type: text/plain' in self._response_headers.decode())

    def testHTTPStatusAction307(self):
        """
        DOH: HTTPStatusAction 307
        """
        name = 'http-status-action-redirect.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0

        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, useQueue=False, rawResponse=True)
        self.assertTrue(receivedResponse)
        self.assertEqual(self._rcode, 307)
        self.assertTrue('location: https://doh.powerdns.org' in self._response_headers.decode())

    def testHTTPLuaResponse(self):
        """
        DOH: Lua HTTP Response
        """
        name = 'http-lua.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0

        (_, receivedResponse) = self.sendDOHPostQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, useQueue=False, rawResponse=True)
        self.assertTrue(receivedResponse)
        self.assertEqual(receivedResponse, b'It works!')
        self.assertEqual(self._rcode, 200)
        self.assertTrue('content-type: text/plain' in self._response_headers.decode())

    def testHTTPEarlyResponse(self):
        """
        DOH: HTTP Early Response
        """
        response_headers = BytesIO()
        url = self._dohBaseURL + 'coffee'
        conn = self.openDOHConnection(self._dohServerPort, caFile=self._caCert, timeout=2.0)
        conn.setopt(pycurl.URL, url)
        conn.setopt(pycurl.RESOLVE, ["%s:%d:127.0.0.1" % (self._serverName, self._dohServerPort)])
        conn.setopt(pycurl.SSL_VERIFYPEER, 1)
        conn.setopt(pycurl.SSL_VERIFYHOST, 2)
        conn.setopt(pycurl.CAINFO, self._caCert)
        conn.setopt(pycurl.HEADERFUNCTION, response_headers.write)
        data = conn.perform_rb()
        rcode = conn.getinfo(pycurl.RESPONSE_CODE)
        headers = response_headers.getvalue().decode()

        self.assertEqual(rcode, 418)
        self.assertEqual(data, b'C0FFEE')
        self.assertIn('foo: bar', headers)
        self.assertNotIn(self._customResponseHeader2, headers)

        response_headers = BytesIO()
        conn = self.openDOHConnection(self._dohServerPort, caFile=self._caCert, timeout=2.0)
        conn.setopt(pycurl.URL, url)
        conn.setopt(pycurl.RESOLVE, ["%s:%d:127.0.0.1" % (self._serverName, self._dohServerPort)])
        conn.setopt(pycurl.SSL_VERIFYPEER, 1)
        conn.setopt(pycurl.SSL_VERIFYHOST, 2)
        conn.setopt(pycurl.CAINFO, self._caCert)
        conn.setopt(pycurl.HEADERFUNCTION, response_headers.write)
        conn.setopt(pycurl.POST, True)
        data = ''
        conn.setopt(pycurl.POSTFIELDS, data)

        data = conn.perform_rb()
        rcode = conn.getinfo(pycurl.RESPONSE_CODE)
        headers = response_headers.getvalue().decode()
        self.assertEqual(rcode, 418)
        self.assertEqual(data, b'C0FFEE')
        self.assertIn('foo: bar', headers)
        self.assertNotIn(self._customResponseHeader2, headers)

    def testFrontendAccessViaBuiltInClient(self):
        """
        DOH: Built-in client
        """
        if self._yaml_config_template:
            return

        output = None
        try:
            confFile = os.path.join('configs', 'dnsdist_%s.conf' % (self.__class__.__name__))
            testcmd = [os.environ['DNSDISTBIN'], '--client', '-C', confFile ]
            process = subprocess.Popen(testcmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
            output = process.communicate(input=b'showVersion()\n')
        except subprocess.CalledProcessError as exc:
            raise AssertionError('%s failed (%d): %s' % (testcmd, process.returncode, process.output))

        if process.returncode != 0:
          raise AssertionError('%s failed (%d): %s' % (testcmd, process.returncode, output))

        self.assertTrue(output[0].startswith(b'dnsdist '))

class TestDoHNGHTTP2(DOHTests, DNSDistDOHTest):
    _dohLibrary = 'nghttp2'

class TestDoHH2O(DOHTests, DNSDistDOHTest):
    _dohLibrary = 'h2o'

class TestDoHNGHTTP2Yaml(DOHTests, DNSDistDOHTest):
    _dohLibrary = 'nghttp2'
    _yaml_config_template = """---
console:
  key: "%s"
  listen_address: "127.0.0.1:%d"
  acl:
    - 127.0.0.0/8
backends:
  - address: "127.0.0.1:%d"
    protocol: "Do53"
binds:
  - listen_address: "127.0.0.1:%d"
    reuseport: true
    protocol: "DoH"
    tls:
      certificates:
        - certificate: "%s"
          key: "%s"
    doh:
      provider: "%s"
      paths:
        - "/"
        - "/coffee"
        - "/PowerDNS"
        - "/PowerDNS2"
        - "/PowerDNS-999"
      custom_response_headers:
        - key: "access-control-allow-origin"
          value: "*"
        - key: "user-agent"
          value: "derp"
        - key: "UPPERCASE"
          value: "VaLuE"
      keep_incoming_headers: true
      responses_map:
        - expression: "^/coffee$"
          status: 418
          content: 'C0FFEE'
          headers:
           - key: "FoO"
             value: "bar"
query_rules:
  - name: "Drop"
    selector:
      type: "QName"
      qname: "drop.doh.tests.powerdns.com."
    action:
      type: "Drop"
  - name: "Refused"
    selector:
      type: "QName"
      qname: "refused.doh.tests.powerdns.com."
    action:
      type: "RCode"
      rcode: "Refused"
  - name: "Spoof"
    selector:
      type: "QName"
      qname: "spoof.doh.tests.powerdns.com."
    action:
      type: "Spoof"
      ips:
        - "1.2.3.4"
  - name: "HTTP header"
    selector:
      type: "HTTPHeader"
      header: "X-PowerDNS"
      expression: "^[a]{5}$"
    action:
      type: "Spoof"
      ips:
        - "2.3.4.5"
  - name: "HTTP path"
    selector:
      type: "HTTPPath"
      path: "/PowerDNS"
    action:
      type: "Spoof"
      ips:
        - "3.4.5.6"
  - name: "HTTP regex"
    selector:
      type: "HTTPPathRegex"
      expression: "^/PowerDNS-[0-9]"
    action:
      type: "Spoof"
      ips:
        - "6.7.8.9"
  - name: "HTTP status"
    selector:
      type: "QName"
      qname: "http-status-action.doh.tests.powerdns.com."
    action:
      type: "HTTPStatus"
      status: 200
      body: "Plaintext answer"
      content_type: "text/plain"
  - name: "HTTP status redirect"
    selector:
      type: "QName"
      qname: "http-status-action-redirect.doh.tests.powerdns.com."
    action:
      type: "HTTPStatus"
      status: 307
      body: "https://doh.powerdns.org"
  - name: "No backend"
    selector:
      type: "QName"
      qname: "no-backend.doh.tests.powerdns.com."
    action:
      type: "Pool"
      pool_name: "this-pool-has-no-backend"
  - name: "HTTP Lua"
    selector:
      type: "QName"
      qname: "http-lua.doh.tests.powerdns.com."
    action:
      type: "Lua"
      function_name: "dohHandler"
"""
    _yaml_config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_dohLibrary']
    _config_template = """
    function dohHandler(dq)
      if dq:getHTTPScheme() == 'https' and dq:getHTTPHost() == '%s:%d' and dq:getHTTPPath() == '/' and dq:getHTTPQueryString() == '' then
        local foundct = false
        for key,value in pairs(dq:getHTTPHeaders()) do
          if key == 'content-type' and value == 'application/dns-message' then
            foundct = true
            break
          end
        end
        if foundct then
          dq:setHTTPResponse(200, 'It works!', 'text/plain')
          dq.dh:setQR(true)
          return DNSAction.HeaderModify
        end
      end
      return DNSAction.None
    end
    """
    _config_params = ['_serverName', '_dohServerPort']

class DOHSubPathsTests(object):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    addAction(AllRule(), SpoofAction("3.4.5.6"))

    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/PowerDNS" }, {exactPathMatching=false, library='%s'})
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_dohLibrary']

    def testSubPath(self):
        """
        DOH: sub-path
        """
        name = 'sub-path.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.id = 0
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '3.4.5.6')
        expectedResponse.answer.append(rrset)

        # this path should match
        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL + 'PowerDNS', caFile=self._caCert, query=query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)

        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        expectedQuery.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        # this path is not in the URLs map and should lead to a 404
        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL + "NotPowerDNS", query, caFile=self._caCert, useQueue=False, rawResponse=True)
        self.assertTrue(receivedResponse)
        self.assertIn(receivedResponse, [b'there is no endpoint configured for this path', b'not found'])
        self.assertEqual(self._rcode, 404)

        # this path is below one in the URLs map and exactPathMatching is false, so we should be good
        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL + 'PowerDNS/something', caFile=self._caCert, query=query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)

class TestDoHSubPathsNGHTTP2(DOHSubPathsTests, DNSDistDOHTest):
    _dohLibrary = 'nghttp2'

class TestDoHSubPathsH2O(DOHSubPathsTests, DNSDistDOHTest):
    _dohLibrary = 'h2o'

class DOHAddingECSTests(object):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%d", useClientSubnet=true}
    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, {library='%s'})
    setECSOverride(true)
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_dohLibrary']

    def testDOHSimple(self):
        """
        DOH with ECS: Simple query
        """
        name = 'simple.doh-ecs.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        rewrittenEcso = clientsubnetoption.ClientSubnetOption('127.0.0.0', 24)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[rewrittenEcso])
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        expectedQuery.id = receivedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.checkResponseNoEDNS(response, receivedResponse)

    def testDOHExistingEDNS(self):
        """
        DOH with ECS: Existing EDNS
        """
        name = 'existing-edns.doh-ecs.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=8192)
        query.id = 0
        rewrittenEcso = clientsubnetoption.ClientSubnetOption('127.0.0.0', 24)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=8192, options=[rewrittenEcso])
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
        self.checkResponseEDNSWithoutECS(response, receivedResponse)

    def testDOHExistingECS(self):
        """
        DOH with ECS: Existing EDNS Client Subnet
        """
        name = 'existing-ecs.doh-ecs.tests.powerdns.com.'
        ecso = clientsubnetoption.ClientSubnetOption('1.2.3.4')
        rewrittenEcso = clientsubnetoption.ClientSubnetOption('127.0.0.0', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=512, options=[ecso], want_dnssec=True)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=512, options=[rewrittenEcso], want_dnssec=True)
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=4096, options=[rewrittenEcso])
        response.want_dnssec(True)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
        self.checkResponseEDNSWithECS(response, receivedResponse)

class TestDoHAddingECSNGHTTP2(DOHAddingECSTests, DNSDistDOHTest):
    _dohLibrary = 'nghttp2'

class TestDoHAddingECSH2O(DOHAddingECSTests, DNSDistDOHTest):
    _dohLibrary = 'h2o'

class DOHOverHTTP(object):
    _dohServerPort = pickAvailablePort()
    _serverName = 'tls.tests.dnsdist.org'
    _dohBaseURL = ("http://%s:%d/dns-query" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    addDOHLocal("127.0.0.1:%d", nil, nil, '/dns-query', {library='%s'})
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_dohLibrary']

    def testDOHSimple(self):
        """
        DOH over HTTP: Simple query
        """
        name = 'simple.doh-over-http.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, useHTTPS=False)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        expectedQuery.id = receivedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.checkResponseNoEDNS(response, receivedResponse)

    def testDOHSimplePOST(self):
        """
        DOH over HTTP: Simple POST query
        """
        name = 'simple-post.doh-over-http.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendDOHPostQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, useHTTPS=False)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.checkResponseNoEDNS(response, receivedResponse)

class TestDOHOverHTTPNGHTTP2(DOHOverHTTP, DNSDistDOHTest):
    _dohLibrary = 'nghttp2'
    _checkConfigExpectedOutput = b"""No certificate provided for DoH endpoint 127.0.0.1:%d, running in DNS over HTTP mode instead of DNS over HTTPS
Configuration 'configs/dnsdist_TestDOHOverHTTPNGHTTP2.conf' OK!
""" % (DOHOverHTTP._dohServerPort)

class TestDOHOverHTTPH2O(DOHOverHTTP, DNSDistDOHTest):
    _dohLibrary = 'h2o'
    _checkConfigExpectedOutput = b"""No certificate provided for DoH endpoint 127.0.0.1:%d, running in DNS over HTTP mode instead of DNS over HTTPS
Configuration 'configs/dnsdist_TestDOHOverHTTPH2O.conf' OK!
""" % (DOHOverHTTP._dohServerPort)

class DOHWithCache(object):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/dns-query" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    addDOHLocal("127.0.0.1:%d", "%s", "%s", '/dns-query', {library='%s'})

    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_dohLibrary']

    def testDOHCacheLargeAnswer(self):
        """
        DOH with cache: Check that we can cache (and retrieve) large answers
        """
        numberOfQueries = 10
        name = 'large.doh-with-cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        # we prepare a large answer
        content = ""
        for i in range(44):
            if len(content) > 0:
                content = content + ', '
            content = content + (str(i)*50)
        # pad up to 4096
        content = content + 'A'*40

        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    content)
        response.answer.append(rrset)
        self.assertEqual(len(response.to_wire()), 4096)

        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.checkHasHeader('cache-control', 'max-age=3600')

        for _ in range(numberOfQueries):
            (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, useQueue=False)
            self.assertEqual(receivedResponse, response)
            self.checkHasHeader('cache-control', 'max-age=' + str(receivedResponse.answer[0].ttl))

        time.sleep(1)

        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, useQueue=False)
        self.assertEqual(receivedResponse, response)
        self.checkHasHeader('cache-control', 'max-age=' + str(receivedResponse.answer[0].ttl))

    def testDOHGetFromUDPCache(self):
        """
        DOH with cache: Check that we can retrieve an answer received for a UDP query
        """
        name = 'doh-query-insert-udp.doh-with-cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.84')
        response.answer.append(rrset)

        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # now we send the exact same query over DoH, we should get a cache hit
        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEqual(response, receivedResponse)

    def testDOHInsertIntoUDPCache(self):
        """
        DOH with cache: Check that we can retrieve an answer received for a DoH query from UDP
        """
        name = 'udp-query-get-doh.doh-with-cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.84')
        response.answer.append(rrset)

        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)

        # now we send the exact same query over DoH, we should get a cache hit
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEqual(response, receivedResponse)

    def testTruncation(self):
        """
        DOH: Truncation over UDP (with cache)
        """
        # the query is first forwarded over UDP, leading to a TC=1 answer from the
        # backend, then over TCP
        name = 'truncated-udp.doh-with-cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.id = 42
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 42
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        # first response is a TC=1
        tcResponse = dns.message.make_response(query)
        tcResponse.flags |= dns.flags.TC
        self._toResponderQueue.put(tcResponse, True, 2.0)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, response=response)
        # first query, received by the responder over UDP
        self.assertTrue(receivedQuery)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)

        # check the response
        self.assertTrue(receivedResponse)
        self.assertEqual(response, receivedResponse)

        # check the second query, received by the responder over TCP
        receivedQuery = self._fromResponderQueue.get(True, 2.0)
        self.assertTrue(receivedQuery)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)

        # now check the cache for a DoH query
        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, useQueue=False)
        self.assertEqual(response, receivedResponse)

        # The TC=1 answer received over UDP will not be cached, because we currently do not cache answers with no records (no TTL)
        # The TCP one should, however
        (_, receivedResponse) = self.sendTCPQuery(expectedQuery, response=None, useQueue=False)
        self.assertEqual(response, receivedResponse)

    def testResponsesReceivedOverUDP(self):
        """
        DOH: Check that responses received over UDP are cached (with cache)
        """
        name = 'cached-udp.doh-with-cache.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, response=response)
        self.assertTrue(receivedQuery)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertTrue(receivedResponse)
        self.assertEqual(response, receivedResponse)

        # now check the cache for a DoH query
        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, useQueue=False)
        self.assertEqual(response, receivedResponse)

        # Check that the answer is usable for UDP queries as well
        (_, receivedResponse) = self.sendUDPQuery(expectedQuery, response=None, useQueue=False)
        self.assertEqual(response, receivedResponse)

class TestDOHWithCacheNGHTTP2(DOHWithCache, DNSDistDOHTest):
    _dohLibrary = 'nghttp2'
    _verboseMode = True

class TestDOHWithCacheH2O(DOHWithCache, DNSDistDOHTest):
    _dohLibrary = 'h2o'

class DOHWithoutCacheControl(object):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, {sendCacheControlHeaders=false, library='%s'})
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_dohLibrary']

    def testDOHSimple(self):
        """
        DOH without cache-control
        """
        name = 'simple.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkNoHeader('cache-control')
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)

class TestDOHWithoutCacheControlNGHTTP2(DOHWithoutCacheControl, DNSDistDOHTest):
    _dohLibrary = 'nghttp2'

class TestDOHWithoutCacheControlH2O(DOHWithoutCacheControl, DNSDistDOHTest):
    _dohLibrary = 'h2o'

class DOHFFI(object):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _customResponseHeader1 = 'access-control-allow-origin: *'
    _customResponseHeader2 = 'user-agent: derp'
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, {customResponseHeaders={["access-control-allow-origin"]="*",["user-agent"]="derp",["UPPERCASE"]="VaLuE"}, keepIncomingHeaders=true, library='%s'})

    local ffi = require("ffi")

    function dohHandler(dq)
      local scheme = ffi.string(ffi.C.dnsdist_ffi_dnsquestion_get_http_scheme(dq))
      local host = ffi.string(ffi.C.dnsdist_ffi_dnsquestion_get_http_host(dq))
      local path = ffi.string(ffi.C.dnsdist_ffi_dnsquestion_get_http_path(dq))
      local query_string = ffi.string(ffi.C.dnsdist_ffi_dnsquestion_get_http_query_string(dq))
      if scheme == 'https' and host == '%s:%d' and path == '/' and query_string == '' then
        local foundct = false
        local headers_ptr = ffi.new("const dnsdist_ffi_http_header_t *[1]")
        local headers_ptr_param = ffi.cast("const dnsdist_ffi_http_header_t **", headers_ptr)

        local headers_count = tonumber(ffi.C.dnsdist_ffi_dnsquestion_get_http_headers(dq, headers_ptr_param))
        if headers_count > 0 then
          for idx = 0, headers_count-1 do
            if ffi.string(headers_ptr[0][idx].name) == 'content-type' and ffi.string(headers_ptr[0][idx].value) == 'application/dns-message' then
              foundct = true
              break
            end
          end
        end
        if foundct then
          local response = 'It works!'
          ffi.C.dnsdist_ffi_dnsquestion_set_http_response(dq, 200, response, #response, 'text/plain')
          return DNSAction.HeaderModify
        end
      end
      return DNSAction.None
    end
    addAction("http-lua-ffi.doh.tests.powerdns.com.", LuaFFIAction(dohHandler))
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_dohLibrary', '_serverName', '_dohServerPort']

    def testHTTPLuaFFIResponse(self):
        """
        DOH: Lua FFI HTTP Response
        """
        name = 'http-lua-ffi.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0

        (_, receivedResponse) = self.sendDOHPostQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, useQueue=False, rawResponse=True)
        self.assertTrue(receivedResponse)
        self.assertEqual(receivedResponse, b'It works!')
        self.assertEqual(self._rcode, 200)
        self.assertTrue('content-type: text/plain' in self._response_headers.decode())

class TestDOHFFINGHTTP2(DOHFFI, DNSDistDOHTest):
    _dohLibrary = 'nghttp2'

class TestDOHFFIH2O(DOHFFI, DNSDistDOHTest):
    _dohLibrary = 'h2o'

class DOHForwardedFor(object):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    setACL('192.0.2.1/32')
    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, {trustForwardedForHeader=true, library='%s'})
    -- Set a maximum number of TCP connections per client, to exercise
    -- that code along with X-Forwarded-For support
    setMaxTCPConnectionsPerClient(2)
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_dohLibrary']

    def testDOHAllowedForwarded(self):
        """
        DOH with X-Forwarded-For allowed
        """
        name = 'allowed.forwarded.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert, customHeaders=['x-forwarded-for: 127.0.0.1:42, 127.0.0.1, 192.0.2.1:4200'])
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)

    def testDOHDeniedForwarded(self):
        """
        DOH with X-Forwarded-For not allowed
        """
        name = 'not-allowed.forwarded.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert, useQueue=False, rawResponse=True, customHeaders=['x-forwarded-for: 127.0.0.1:42, 127.0.0.1'])

        self.assertEqual(self._rcode, 403)
        self.assertEqual(receivedResponse, b'DoH query not allowed because of ACL')

class TestDOHForwardedForNGHTTP2(DOHForwardedFor, DNSDistDOHTest):
    _dohLibrary = 'nghttp2'

class TestDOHForwardedForH2O(DOHForwardedFor, DNSDistDOHTest):
    _dohLibrary = 'h2o'

class DOHForwardedForNoTrusted(object):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    setACL('192.0.2.1/32')
    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, {earlyACLDrop=true, library='%s'})
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_dohLibrary']

    def testDOHForwardedUntrusted(self):
        """
        DOH with X-Forwarded-For not trusted
        """
        name = 'not-trusted.forwarded.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        dropped = False
        try:
            (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert, useQueue=False, rawResponse=True, customHeaders=['x-forwarded-for: 192.0.2.1:4200'])
            self.assertEqual(self._rcode, 403)
            self.assertEqual(receivedResponse, b'DoH query not allowed because of ACL')
        except pycurl.error as e:
            dropped = True

        self.assertTrue(dropped)

class TestDOHForwardedForNoTrustedNGHTTP2(DOHForwardedForNoTrusted, DNSDistDOHTest):
    _dohLibrary = 'nghttp2'

class TestDOHForwardedForNoTrustedH2O(DOHForwardedForNoTrusted, DNSDistDOHTest):
    _dohLibrary = 'h2o'

class DOHFrontendLimits(object):

    # this test suite uses a different responder port
    # because it uses a different health check configuration
    _testServerPort = pickAvailablePort()
    _answerUnexpected = True

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _skipListeningOnCL = True
    _maxTCPConnsPerDOHFrontend = 5
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, { maxConcurrentTCPConnections=%d, library='%s' })
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_maxTCPConnsPerDOHFrontend', '_dohLibrary']
    _alternateListeningAddr = '127.0.0.1'
    _alternateListeningPort = _dohServerPort

    def testTCPConnsPerDOHFrontend(self):
        """
        DoH Frontend Limits: Maximum number of conns per DoH frontend
        """
        query = b"GET / HTTP/1.0\r\n\r\n"
        conns = []

        for idx in range(self._maxTCPConnsPerDOHFrontend + 1):
            try:
                alpn = []
                if self._dohLibrary != 'h2o':
                    alpn.append('h2')
                conns.append(self.openTLSConnection(self._dohServerPort, self._serverName, self._caCert, alpn=alpn))
            except:
                conns.append(None)

        count = 0
        failed = 0
        for conn in conns:
            if not conn:
                failed = failed + 1
                continue

            try:
                conn.send(query)
                response = conn.recv(65535)
                if response:
                    count = count + 1
                else:
                    failed = failed + 1
            except:
                failed = failed + 1

        for conn in conns:
            if conn:
                conn.close()

        # wait a bit to be sure that dnsdist closed the connections
        # and decremented the counters on its side, otherwise subsequent
        # connections will be dropped
        time.sleep(1)

        self.assertEqual(count, self._maxTCPConnsPerDOHFrontend)
        self.assertEqual(failed, 1)

class TestDOHFrontendLimitsNGHTTP2(DOHFrontendLimits, DNSDistDOHTest):
    _dohLibrary = 'nghttp2'

class TestDOHFrontendLimitsH2O(DOHFrontendLimits, DNSDistDOHTest):
    _dohLibrary = 'h2o'

class Protocols(object):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _customResponseHeader1 = 'access-control-allow-origin: *'
    _customResponseHeader2 = 'user-agent: derp'
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    function checkDOH(dq)
      if dq:getProtocol() ~= "DNS over HTTPS" then
        return DNSAction.Spoof, '1.2.3.4'
      end
      return DNSAction.None
    end

    addAction("protocols.doh.tests.powerdns.com.", LuaAction(checkDOH))
    newServer{address="127.0.0.1:%d"}
    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, {library='%s'})
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_dohLibrary']

    def testProtocolDOH(self):
        """
        DoH: Test DNSQuestion.Protocol
        """
        name = 'protocols.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEqual(response, receivedResponse)

class TestProtocolsNGHTTP2(Protocols, DNSDistDOHTest):
    _dohLibrary = 'nghttp2'

class TestProtocolsH2O(Protocols, DNSDistDOHTest):
    _dohLibrary = 'h2o'

class DOHWithPKCS12Cert(object):
    _serverCert = 'server.p12'
    _pkcs12Password = 'passw0rd'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    cert=newTLSCertificate("%s", {password="%s"})
    addDOHLocal("127.0.0.1:%d", cert, "", { "/" }, {library='%s'})
    """
    _config_params = ['_testServerPort', '_serverCert', '_pkcs12Password', '_dohServerPort', '_dohLibrary']

    def testPKCS12DOH(self):
        """
        DoH: Test Simple DOH Query with a password protected PKCS12 file configured
        """
        name = 'simple.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096)
        expectedQuery.id = 0
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEqual(expectedQuery, receivedQuery)

class TestDOHWithPKCS12CertNGHTTP2(DOHWithPKCS12Cert, DNSDistDOHTest):
    _dohLibrary = 'nghttp2'

class TestDOHWithPKCS12CertH2O(DOHWithPKCS12Cert, DNSDistDOHTest):
    _dohLibrary = 'h2o'

class DOHForwardedToTCPOnly(object):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%d", tcpOnly=true}
    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, {library='%s'})
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_dohLibrary']

    def testDOHTCPOnly(self):
        """
        DoH: Test a DoH query forwarded to a TCP-only server
        """
        name = 'tcponly.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.id = 42
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)

class TestDOHForwardedToTCPOnlyNGHTTP2(DOHForwardedToTCPOnly, DNSDistDOHTest):
    _dohLibrary = 'nghttp2'

class TestDOHForwardedToTCPOnlyH2O(DOHForwardedToTCPOnly, DNSDistDOHTest):
    _dohLibrary = 'h2o'

class DOHLimits(object):
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _maxTCPConnsPerClient = 3
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, {library='%s'})
    setMaxTCPConnectionsPerClient(%d)
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_dohLibrary', '_maxTCPConnsPerClient']

    def testConnsPerClient(self):
        """
        DoH Limits: Maximum number of conns per client
        """
        name = 'maxconnsperclient.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        url = self.getDOHGetURL(self._dohBaseURL, query)
        conns = []

        for idx in range(self._maxTCPConnsPerClient + 1):
            conn = self.openDOHConnection(self._dohServerPort, self._caCert, timeout=2.0)
            conn.setopt(pycurl.URL, url)
            conn.setopt(pycurl.RESOLVE, ["%s:%d:127.0.0.1" % (self._serverName, self._dohServerPort)])
            conn.setopt(pycurl.SSL_VERIFYPEER, 1)
            conn.setopt(pycurl.SSL_VERIFYHOST, 2)
            conn.setopt(pycurl.CAINFO, self._caCert)
            conns.append(conn)

        count = 0
        failed = 0
        for conn in conns:
            try:
                conn.perform_rb()
                conn.getinfo(pycurl.RESPONSE_CODE)
                count = count + 1
            except:
                failed = failed + 1

        for conn in conns:
            conn.close()

        # wait a bit to be sure that dnsdist closed the connections
        # and decremented the counters on its side, otherwise subsequent
        # connections will be dropped
        time.sleep(1)

        self.assertEqual(count, self._maxTCPConnsPerClient)
        self.assertEqual(failed, 1)

class TestDOHLimitsNGHTTP2(DOHLimits, DNSDistDOHTest):
    _dohLibrary = 'nghttp2'

class TestDOHLimitsH2O(DOHLimits, DNSDistDOHTest):
    _dohLibrary = 'h2o'

class DOHXFR(object):
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _maxTCPConnsPerClient = 3
    _config_template = """
    newServer{address="127.0.0.1:%d", tcpOnly=true}
    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, {library='%s'})
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_dohLibrary']

    def testXFR(self):
        """
        DoH XFR: Check that XFR requests over DoH are refused with NotImp
        """
        name = 'xfr.doh.tests.powerdns.com.'
        for xfrType in [dns.rdatatype.AXFR, dns.rdatatype.IXFR]:
            query = dns.message.make_query(name, xfrType, 'IN')

            expectedResponse = dns.message.make_response(query)
            expectedResponse.set_rcode(dns.rcode.NOTIMP)

            (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, useQueue=False)

            self.assertEqual(receivedResponse, expectedResponse)

class TestDOHXFRNGHTTP2(DOHXFR, DNSDistDOHTest):
    _dohLibrary = 'nghttp2'

class TestDOHXFRH2O(DOHXFR, DNSDistDOHTest):
    _dohLibrary = 'h2o'
