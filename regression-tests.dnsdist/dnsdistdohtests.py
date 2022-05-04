#!/usr/bin/env python
import base64
import dns
import os
import unittest

from dnsdisttests import DNSDistTest

import pycurl
from io import BytesIO

@unittest.skipIf('SKIP_DOH_TESTS' in os.environ, 'DNS over HTTPS tests are disabled')
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
    def sendDOHQuery(cls, port, servername, baseurl, query, response=None, timeout=2.0, caFile=None, useQueue=True, rawQuery=False, rawResponse=False, customHeaders=[], useHTTPS=True, fromQueue=None, toQueue=None):
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
            if toQueue:
                toQueue.put(response, True, timeout)
            else:
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

        if useQueue:
            if fromQueue:
                if not fromQueue.empty():
                    receivedQuery = fromQueue.get(True, timeout)
            else:
                if not cls._fromResponderQueue.empty():
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

    def getHeaderValue(self, name):
        for header in self._response_headers.decode().splitlines(False):
            values = header.split(':')
            key = values[0]
            if key.lower() == name.lower():
                return values[1].strip()
        return None

    def checkHasHeader(self, name, value):
        got = self.getHeaderValue(name)
        self.assertEqual(got, value)

    def checkNoHeader(self, name):
        self.checkHasHeader(name, None)

    @classmethod
    def setUpClass(cls):

        # for some reason, @unittest.skipIf() is not applied to derived classes with some versions of Python
        if 'SKIP_DOH_TESTS' in os.environ:
            raise unittest.SkipTest('DNS over HTTPS tests are disabled')

        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

        print("Launching tests..")
