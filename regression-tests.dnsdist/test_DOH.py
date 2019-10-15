#!/usr/bin/env python
import base64
import dns
import clientsubnetoption
from dnsdisttests import DNSDistTest

import pycurl
from io import BytesIO
#from hyper import HTTP20Connection
#from hyper.ssl_compat import SSLContext, PROTOCOL_TLSv1_2

class DNSDistDOHTest(DNSDistTest):

    @classmethod
    def getDOHGetURL(cls, baseurl, query, rawQuery=False):
        if rawQuery:
            wire = query
        else:
            wire = query.to_wire()
        param = base64.urlsafe_b64encode(wire).decode('UTF8').rstrip('=')
        return baseurl + "?dns=" + param

    @classmethod
    def openDOHConnection(cls, port, caFile, timeout=2.0):
        conn = pycurl.Curl()
        conn.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2)

        conn.setopt(pycurl.HTTPHEADER, ["Content-type: application/dns-message",
                                         "Accept: application/dns-message"])
        return conn

    @classmethod
    def sendDOHQuery(cls, port, servername, baseurl, query, response=None, timeout=2.0, caFile=None, useQueue=True, rawQuery=False, rawResponse=False, customHeaders=[], useHTTPS=True):
        url = cls.getDOHGetURL(baseurl, query, rawQuery)
        conn = cls.openDOHConnection(port, caFile=caFile, timeout=timeout)
        response_headers = BytesIO()
        #conn.setopt(pycurl.VERBOSE, True)
        conn.setopt(pycurl.URL, url)
        conn.setopt(pycurl.RESOLVE, ["%s:%d:127.0.0.1" % (servername, port)])
        if useHTTPS:
            conn.setopt(pycurl.SSL_VERIFYPEER, 1)
            conn.setopt(pycurl.SSL_VERIFYHOST, 2)
            if caFile:
                conn.setopt(pycurl.CAINFO, caFile)

        conn.setopt(pycurl.HTTPHEADER, customHeaders)
        conn.setopt(pycurl.HEADERFUNCTION, response_headers.write)

        if response:
            cls._toResponderQueue.put(response, True, timeout)

        receivedQuery = None
        message = None
        cls._response_headers = ''
        data = conn.perform_rb()
        cls._rcode = conn.getinfo(pycurl.RESPONSE_CODE)
        if cls._rcode == 200 and not rawResponse:
            message = dns.message.from_wire(data)
        elif rawResponse:
            message = data

        if useQueue and not cls._fromResponderQueue.empty():
            receivedQuery = cls._fromResponderQueue.get(True, timeout)

        cls._response_headers = response_headers.getvalue()
        return (receivedQuery, message)

    @classmethod
    def sendDOHPostQuery(cls, port, servername, baseurl, query, response=None, timeout=2.0, caFile=None, useQueue=True, rawQuery=False, rawResponse=False, customHeaders=[], useHTTPS=True):
        url = baseurl
        conn = cls.openDOHConnection(port, caFile=caFile, timeout=timeout)
        response_headers = BytesIO()
        #conn.setopt(pycurl.VERBOSE, True)
        conn.setopt(pycurl.URL, url)
        conn.setopt(pycurl.RESOLVE, ["%s:%d:127.0.0.1" % (servername, port)])
        if useHTTPS:
            conn.setopt(pycurl.SSL_VERIFYPEER, 1)
            conn.setopt(pycurl.SSL_VERIFYHOST, 2)
            if caFile:
                conn.setopt(pycurl.CAINFO, caFile)

        conn.setopt(pycurl.HTTPHEADER, customHeaders)
        conn.setopt(pycurl.HEADERFUNCTION, response_headers.write)
        conn.setopt(pycurl.POST, True)
        data = query
        if not rawQuery:
            data = data.to_wire()

        conn.setopt(pycurl.POSTFIELDS, data)

        if response:
            cls._toResponderQueue.put(response, True, timeout)

        receivedQuery = None
        message = None
        cls._response_headers = ''
        data = conn.perform_rb()
        cls._rcode = conn.getinfo(pycurl.RESPONSE_CODE)
        if cls._rcode == 200 and not rawResponse:
            message = dns.message.from_wire(data)
        elif rawResponse:
            message = data

        if useQueue and not cls._fromResponderQueue.empty():
            receivedQuery = cls._fromResponderQueue.get(True, timeout)

        cls._response_headers = response_headers.getvalue()
        return (receivedQuery, message)

#     @classmethod
#     def openDOHConnection(cls, port, caFile, timeout=2.0):
#         sslctx = SSLContext(PROTOCOL_TLSv1_2)
#         sslctx.load_verify_locations(caFile)
#         return HTTP20Connection('127.0.0.1', port=port, secure=True, timeout=timeout, ssl_context=sslctx, force_proto='h2')

#     @classmethod
#     def sendDOHQueryOverConnection(cls, conn, baseurl, query, response=None, timeout=2.0):
#         url = cls.getDOHGetURL(baseurl, query)

#         if response:
#             cls._toResponderQueue.put(response, True, timeout)

#         conn.request('GET', url)

#     @classmethod
#     def recvDOHResponseOverConnection(cls, conn, useQueue=False, timeout=2.0):
#         message = None
#         data = conn.get_response()
#         if data:
#             data = data.read()
#             if data:
#                 message = dns.message.from_wire(data)

#         if useQueue and not cls._fromResponderQueue.empty():
#             receivedQuery = cls._fromResponderQueue.get(True, timeout)
#             return (receivedQuery, message)
#         else:
#             return message

class TestDOH(DNSDistDOHTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = 8443
    _customResponseHeader1 = 'access-control-allow-origin: *'
    _customResponseHeader2 = 'user-agent: derp'
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%s"}

    addDOHLocal("127.0.0.1:%s", "%s", "%s", { "/" }, {customResponseHeaders={["access-control-allow-origin"]="*",["user-agent"]="derp",["UPPERCASE"]="VaLuE"}})
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
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertTrue((self._customResponseHeader1) in self._response_headers.decode())
        self.assertTrue((self._customResponseHeader2) in self._response_headers.decode())
        self.assertFalse(('UPPERCASE: VaLuE' in self._response_headers.decode()))
        self.assertTrue(('uppercase: VaLuE' in self._response_headers.decode()))
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

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
        self.assertEquals(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

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
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
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
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        self.checkQueryEDNSWithECS(query, receivedQuery)
        self.checkResponseEDNSWithECS(response, receivedResponse)

    def testDropped(self):
        """
        DOH: Dropped query
        """
        name = 'drop.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, caFile=self._caCert, query=query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, None)

    def testRefused(self):
        """
        DOH: Refused
        """
        name = 'refused.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.id = 0
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, caFile=self._caCert, query=query, response=None, useQueue=False)
        self.assertEquals(receivedResponse, expectedResponse)

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
        self.assertEquals(receivedResponse, expectedResponse)

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
        self.assertEquals(receivedResponse, None)

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
        self.assertEquals(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

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
        self.assertEquals(rcode, 400)

    def testDOHEmptyPOST(self):
        """
        DOH: Empty POST query
        """
        name = 'empty-post.doh.tests.powerdns.com.'

        (_, receivedResponse) = self.sendDOHPostQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query="", rawQuery=True, response=None, caFile=self._caCert)
        self.assertEquals(receivedResponse, None)

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
        self.assertEquals(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

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
        self.assertEquals(receivedResponse, expectedResponse)

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
        self.assertEquals(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

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
        self.assertEquals(receivedResponse, expectedResponse)

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
        self.assertEquals(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

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
        self.assertEquals(receivedResponse, expectedResponse)

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
        self.assertEquals(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testHTTPStatusAction200(self):
        """
        DOH: HTTPStatusAction 200 OK
        """
        name = 'http-status-action.doh.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.id = 0

        (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, useQueue=False, rawResponse=True)
        self.assertTrue(receivedResponse)
        self.assertEquals(receivedResponse, b'Plaintext answer')
        self.assertEquals(self._rcode, 200)
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
        self.assertEquals(self._rcode, 307)
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
        self.assertEquals(receivedResponse, b'It works!')
        self.assertEquals(self._rcode, 200)
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

        self.assertEquals(rcode, 418)
        self.assertEquals(data, b'C0FFEE')
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
        self.assertEquals(rcode, 418)
        self.assertEquals(data, b'C0FFEE')
        self.assertIn('foo: bar', headers)
        self.assertNotIn(self._customResponseHeader2, headers)

class TestDOHAddingECS(DNSDistDOHTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = 8443
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
        self.assertEquals(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)
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
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)
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
        self.assertEquals(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)
        self.checkQueryEDNSWithECS(expectedQuery, receivedQuery)
        self.checkResponseEDNSWithECS(response, receivedResponse)

class TestDOHOverHTTP(DNSDistDOHTest):

    _dohServerPort = 8480
    _serverName = 'tls.tests.dnsdist.org'
    _dohBaseURL = ("http://%s:%d/" % (_serverName, _dohServerPort))
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    addDOHLocal("127.0.0.1:%s")
    """
    _config_params = ['_testServerPort', '_dohServerPort']

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
        self.assertEquals(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)
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
        self.assertEquals(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)
        self.checkResponseNoEDNS(response, receivedResponse)

class TestDOHWithCache(DNSDistDOHTest):

    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohServerPort = 8443
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
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
        self.assertEquals(len(response.to_wire()), 4096)

        # first query to fill the cache
        (receivedQuery, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        self.assertEquals(expectedQuery, receivedQuery)
        self.checkQueryEDNSWithoutECS(expectedQuery, receivedQuery)
        self.assertEquals(response, receivedResponse)

        for _ in range(numberOfQueries):
            (_, receivedResponse) = self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, caFile=self._caCert, useQueue=False)
            self.assertEquals(receivedResponse, response)
