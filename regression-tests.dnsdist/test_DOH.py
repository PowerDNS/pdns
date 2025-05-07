#!/usr/bin/env python

import dns
import os
import time
import unittest
import clientsubnetoption

from dnsdistdohtests import DNSDistDOHTest
from dnsdisttests import pickAvailablePort

import pycurl
from io import BytesIO

class TestDOH(DNSDistDOHTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _customResponseHeader1 = 'access-control-allow-origin: *'
    _customResponseHeader2 = 'user-agent: derp'
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%s"}

    addDOHLocal("127.0.0.1:%s", "%s", "%s", { "/", "/coffee", "/PowerDNS", "/PowerDNS2", "/PowerDNS-999" }, {customResponseHeaders={["access-control-allow-origin"]="*",["user-agent"]="derp",["UPPERCASE"]="VaLuE"}, keepIncomingHeaders=true})
    dohFE = getDOHFrontend(0)
    dohFE:setResponsesMap({newDOHResponseMapEntry('^/coffee$', 418, 'C0FFEE', {['FoO']='bar'})})

    addAction("drop.doh.tests.powerdns.com.", DropAction())
    addAction("refused.doh.tests.powerdns.com.", RCodeAction(DNSRCode.REFUSED))
    addAction("spoof.doh.tests.powerdns.com.", SpoofAction("1.2.3.4"))
    addAction(HTTPHeaderRule("X-PowerDNS", "^[a]{5}$"), SpoofAction("2.3.4.5"))
    addAction(HTTPPathRule("/PowerDNS"), SpoofAction("3.4.5.6"))
    addAction(HTTPPathRegexRule("^/PowerDNS-[0-9]"), SpoofAction("6.7.8.9"))
    addAction("http-status-action.doh.tests.powerdns.com.", HTTPStatusAction(200, "Plaintext answer", "text/plain"))
    addAction("http-status-action-redirect.doh.tests.powerdns.com.", HTTPStatusAction(307, "https://doh.powerdns.org"))

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
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_serverName', '_dohServerPort']

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

    def testDOHInvalid(self):
        """
        DOH: Invalid query
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

    def testDOHWithoutQuery(self):
        """
        DOH: Empty GET query
        """
        name = 'empty-get.doh.tests.powerdns.com.'
        url = self._dohBaseURL
        conn = self.openDOHConnection(self._dohServerPort, self._caCert, timeout=2.0)
        conn.setopt(pycurl.URL, url)
        conn.setopt(pycurl.RESOLVE, ["%s:%d:127.0.0.1" % (self._serverName, self._dohServerPort)])
        conn.setopt(pycurl.SSL_VERIFYPEER, 1)
        conn.setopt(pycurl.SSL_VERIFYHOST, 2)
        conn.setopt(pycurl.CAINFO, self._caCert)
        data = conn.perform_rb()
        rcode = conn.getinfo(pycurl.RESPONSE_CODE)
        self.assertEqual(rcode, 400)

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

class TestDOHSubPaths(DNSDistDOHTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%s"}

    addAction(AllRule(), SpoofAction("3.4.5.6"))

    addDOHLocal("127.0.0.1:%s", "%s", "%s", { "/PowerDNS" }, {exactPathMatching=false})
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey']

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
        self.assertEqual(receivedResponse, b'not found')
        self.assertEqual(self._rcode, 404)

        # this path is below one in the URLs map and exactPathMatching is false, so we should be good
        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL + 'PowerDNS/something', caFile=self._caCert, query=query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)

class TestDOHAddingECS(DNSDistDOHTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%s", useClientSubnet=true}
    addDOHLocal("127.0.0.1:%s", "%s", "%s", { "/" })
    setECSOverride(true)
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey']

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
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=512, options=[rewrittenEcso])
        response = dns.message.make_response(query)
        response.use_edns(edns=True, payload=4096, options=[rewrittenEcso])
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

class TestDOHOverHTTP(DNSDistDOHTest):

    _dohServerPort = pickAvailablePort()
    _serverName = 'tls.tests.dnsdist.org'
    _dohBaseURL = ("http://%s:%d/dns-query" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    addDOHLocal("127.0.0.1:%s")
    """
    _config_params = ['_testServerPort', '_dohServerPort']
    _checkConfigExpectedOutput = b"""No certificate provided for DoH endpoint 127.0.0.1:%d, running in DNS over HTTP mode instead of DNS over HTTPS
Configuration 'configs/dnsdist_TestDOHOverHTTP.conf' OK!
""" % (_dohServerPort)

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

class TestDOHWithCache(DNSDistDOHTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/dns-query" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%s"}

    addDOHLocal("127.0.0.1:%s", "%s", "%s")

    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey']

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

class TestDOHWithoutCacheControl(DNSDistDOHTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%s"}

    addDOHLocal("127.0.0.1:%s", "%s", "%s", { "/" }, {sendCacheControlHeaders=false})
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey']

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

class TestDOHFFI(DNSDistDOHTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _customResponseHeader1 = 'access-control-allow-origin: *'
    _customResponseHeader2 = 'user-agent: derp'
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%s"}

    addDOHLocal("127.0.0.1:%s", "%s", "%s", { "/" }, {customResponseHeaders={["access-control-allow-origin"]="*",["user-agent"]="derp",["UPPERCASE"]="VaLuE"}, keepIncomingHeaders=true})

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
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_serverName', '_dohServerPort']

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

class TestDOHForwardedFor(DNSDistDOHTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%s"}

    setACL('192.0.2.1/32')
    addDOHLocal("127.0.0.1:%s", "%s", "%s", { "/" }, {trustForwardedForHeader=true})
    -- Set a maximum number of TCP connections per client, to exercise
    -- that code along with X-Forwarded-For support
    setMaxTCPConnectionsPerClient(2)
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey']

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
        self.assertEqual(receivedResponse, b'dns query not allowed because of ACL')

class TestDOHForwardedForNoTrusted(DNSDistDOHTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%s"}

    setACL('192.0.2.1/32')
    addDOHLocal("127.0.0.1:%s", "%s", "%s", { "/" })
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey']

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

        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert, useQueue=False, rawResponse=True, customHeaders=['x-forwarded-for: 192.0.2.1:4200'])

        self.assertEqual(self._rcode, 403)
        self.assertEqual(receivedResponse, b'dns query not allowed because of ACL')

class TestDOHFrontendLimits(DNSDistDOHTest):

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
    newServer{address="127.0.0.1:%s"}
    addDOHLocal("127.0.0.1:%s", "%s", "%s", { "/" }, { maxConcurrentTCPConnections=%d })
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_maxTCPConnsPerDOHFrontend']
    _alternateListeningAddr = '127.0.0.1'
    _alternateListeningPort = _dohServerPort

    def testTCPConnsPerDOHFrontend(self):
        """
        DoH Frontend Limits: Maximum number of conns per DoH frontend
        """
        name = 'maxconnsperfrontend.doh.tests.powerdns.com.'
        query = b"GET / HTTP/1.0\r\n\r\n"
        conns = []

        for idx in range(self._maxTCPConnsPerDOHFrontend + 1):
            try:
                conns.append(self.openTLSConnection(self._dohServerPort, self._serverName, self._caCert))
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

class TestProtocols(DNSDistDOHTest):
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
    newServer{address="127.0.0.1:%s"}
    addDOHLocal("127.0.0.1:%s", "%s", "%s", { "/" })
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey']

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

class TestDOHWithPCKS12Cert(DNSDistDOHTest):
    _serverCert = 'server.p12'
    _pkcs12Password = 'passw0rd'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    cert=newTLSCertificate("%s", {password="%s"})
    addDOHLocal("127.0.0.1:%s", cert, "", { "/" })
    """
    _config_params = ['_testServerPort', '_serverCert', '_pkcs12Password', '_dohServerPort']

    def testProtocolDOH(self):
        """
        DoH: Test Simple DOH Query with a password protected PCKS12 file configured
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

class TestDOHForwardedToTCPOnly(DNSDistDOHTest):
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%s", tcpOnly=true}
    addDOHLocal("127.0.0.1:%s", "%s", "%s", { "/" })
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey']

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

class TestDOHLimits(DNSDistDOHTest):
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = pickAvailablePort()
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _maxTCPConnsPerClient = 3
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    addDOHLocal("127.0.0.1:%s", "%s", "%s", { "/" })
    setMaxTCPConnectionsPerClient(%s)
    """
    _config_params = ['_testServerPort', '_dohServerPort', '_serverCert', '_serverKey', '_maxTCPConnsPerClient']

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
                data = conn.perform_rb()
                rcode = conn.getinfo(pycurl.RESPONSE_CODE)
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
