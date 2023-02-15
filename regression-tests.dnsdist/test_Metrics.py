#!/usr/bin/env python

import os
import requests
import socket
import threading
import unittest
import dns
from dnsdisttests import DNSDistTest

class TestRuleMetrics(DNSDistTest):

    _config_template = """
    addTLSLocal("127.0.0.1:%s", "%s", "%s", { provider="openssl" })
    addDOHLocal("127.0.0.1:%s", "%s", "%s", { "/"})

    newServer{address="127.0.0.1:%s", pool={'', 'cache'}}
    webserver("127.0.0.1:%s")
    setWebserverConfig({apiKey="%s"})

    addAction('rcode-nxdomain.metrics.tests.powerdns.com', RCodeAction(DNSRCode.NXDOMAIN))
    addAction('rcode-refused.metrics.tests.powerdns.com', RCodeAction(DNSRCode.REFUSED))
    addAction('rcode-servfail.metrics.tests.powerdns.com', RCodeAction(DNSRCode.SERVFAIL))

    pc = newPacketCache(100)
    getPool('cache'):setCache(pc)
    addAction('cache.metrics.tests.powerdns.com', PoolAction('cache'))
    """
    _webTimeout = 2.0
    _webServerPort = 8083
    _webServerAPIKey = 'apisecret'
    _webServerAPIKeyHashed = '$scrypt$ln=10,p=1,r=8$9v8JxDfzQVyTpBkTbkUqYg==$bDQzAOHeK1G9UvTPypNhrX48w974ZXbFPtRKS34+aso='
    _serverKey = 'server.key'
    _serverCert = 'server.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _tlsServerPort = 8453
    _dohServerPort = 8443
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _dohServerPort))
    _config_params = ['_tlsServerPort', '_serverCert', '_serverKey', '_dohServerPort', '_serverCert', '_serverKey', '_testServerPort', '_webServerPort', '_webServerAPIKeyHashed']

    def getMetric(self, name):
        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/api/v1/servers/localhost'
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        stats = content['statistics']
        self.assertIn(name, stats)
        return int(stats[name])

    def testRCodeIncreaseMetrics(self):
        """
        Metrics: Check that metrics are correctly updated for RCodeAction
        """
        rcodes = [
            ( 'nxdomain', dns.rcode.NXDOMAIN ),
            ( 'refused', dns.rcode.REFUSED ),
            ( 'servfail', dns.rcode.SERVFAIL )
        ]
        for (name, rcode) in rcodes:
            qname = 'rcode-' + name + '.metrics.tests.powerdns.com.'
            query = dns.message.make_query(qname, 'A', 'IN')
            # dnsdist set RA = RD for spoofed responses
            query.flags &= ~dns.flags.RD
            expectedResponse = dns.message.make_response(query)
            expectedResponse.set_rcode(rcode)

            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                (_, receivedResponse) = sender(query, response=None, useQueue=False)
                self.assertEqual(receivedResponse, expectedResponse)

            self.assertEquals(self.getMetric('rule-' + name), 2)

    def sendDOHQueryWrapper(self, query, response, useQueue=True):
        return self.sendDOHQuery(self._dohServerPort, self._serverName, self._dohBaseURL, query, response=response, caFile=self._caCert, useQueue=useQueue)

    def sendDOTQueryWrapper(self, query, response, useQueue=True):
        return self.sendDOTQuery(self._tlsServerPort, self._serverName, query, response, self._caCert, useQueue=useQueue)

    def testCacheMetrics(self):
        """
        Metrics: Check that metrics are correctly updated for cache misses and hits
        """

        for method in ("sendUDPQuery", "sendTCPQuery", "sendDOTQueryWrapper", "sendDOHQueryWrapper"):
            qname = method + '.cache.metrics.tests.powerdns.com.'
            query = dns.message.make_query(qname, 'A', 'IN')
            # dnsdist set RA = RD for spoofed responses
            query.flags &= ~dns.flags.RD
            response = dns.message.make_response(query)
            rrset = dns.rrset.from_text(qname,
                                        3600,
                                        dns.rdataclass.IN,
                                        dns.rdatatype.A,
                                        '127.0.0.1')
            response.answer.append(rrset)

            responsesBefore = self.getMetric('responses')
            cacheHitsBefore = self.getMetric('cache-hits')
            cacheMissesBefore = self.getMetric('cache-misses')

            sender = getattr(self, method)
            # first time, cache miss
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)
            # second time, hit
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, response)

            self.assertEqual(self.getMetric('responses'), responsesBefore + 2)
            self.assertEqual(self.getMetric('cache-hits'), cacheHitsBefore + 1)
            self.assertEqual(self.getMetric('cache-misses'), cacheMissesBefore + 1)
