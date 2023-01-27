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
    newServer{address="127.0.0.1:%s"}
    webserver("127.0.0.1:%s")
    setWebserverConfig({apiKey="%s"})

    addAction('rcode-nxdomain.metrics.tests.powerdns.com', RCodeAction(DNSRCode.NXDOMAIN))
    addAction('rcode-refused.metrics.tests.powerdns.com', RCodeAction(DNSRCode.REFUSED))
    addAction('rcode-servfail.metrics.tests.powerdns.com', RCodeAction(DNSRCode.SERVFAIL))
    """
    _webTimeout = 2.0
    _webServerPort = 8083
    _webServerAPIKey = 'apisecret'
    _webServerAPIKeyHashed = '$scrypt$ln=10,p=1,r=8$9v8JxDfzQVyTpBkTbkUqYg==$bDQzAOHeK1G9UvTPypNhrX48w974ZXbFPtRKS34+aso='
    _config_params = ['_testServerPort', '_webServerPort', '_webServerAPIKeyHashed']

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
