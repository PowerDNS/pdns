#!/usr/bin/env python
import dns
import dns.message
import os
import socket
import subprocess
import time
import unittest
from dnsdisttests import DNSDistTest
import dnscrypt

class TestDNSCrypt(DNSDistTest):
    """
    dnsdist is configured to accept DNSCrypt queries on 127.0.0.1:_dnsDistPortDNSCrypt.
    The provider's keys have been generated with:
    generateDNSCryptProviderKeys("DNSCryptProviderPublic.key", "DNSCryptProviderPrivate.key")
    Be careful to change the _providerFingerprint below if you want to regenerate the keys.
    """

    _dnsDistPort = 5340
    _dnsDistPortDNSCrypt = 8443
    _config_template = """
    generateDNSCryptCertificate("DNSCryptProviderPrivate.key", "DNSCryptResolver.cert", "DNSCryptResolver.key", %d, %d, %d)
    addDNSCryptBind("127.0.0.1:%d", "%s", "DNSCryptResolver.cert", "DNSCryptResolver.key")
    newServer{address="127.0.0.1:%s"}
    """

    _providerFingerprint = 'E1D7:2108:9A59:BF8D:F101:16FA:ED5E:EA6A:9F6C:C78F:7F91:AF6B:027E:62F4:69C3:B1AA'
    _providerName = "2.provider.name"
    _resolverCertificateSerial = 42
    # valid from 60s ago until 2h from now
    _resolverCertificateValidFrom = time.time() - 60
    _resolverCertificateValidUntil = time.time() + 7200
    _config_params = ['_resolverCertificateSerial', '_resolverCertificateValidFrom', '_resolverCertificateValidUntil', '_dnsDistPortDNSCrypt', '_providerName', '_testServerPort']
    _dnsdistStartupDelay = 10

    def testSimpleA(self):
        """
        DNSCrypt: encrypted A query
        """
        client = dnscrypt.DNSCryptClient(self._providerName, self._providerFingerprint, "127.0.0.1", 8443)
        name = 'a.dnscrypt.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        self._toResponderQueue.put(response)
        data = client.query(query.to_wire())
        receivedResponse = dns.message.from_wire(data)
        receivedQuery = None
        if not self._fromResponderQueue.empty():
            receivedQuery = self._fromResponderQueue.get(query)

        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testResponseLargerThanPaddedQuery(self):
        """
        DNSCrypt: response larger than query

        Send a small encrypted query (don't forget to take
        the padding into account) and check that the response
        is truncated.
        """
        client = dnscrypt.DNSCryptClient(self._providerName, self._providerFingerprint, "127.0.0.1", 8443)
        name = 'smallquerylargeresponse.dnscrypt.tests.powerdns.com.'
        query = dns.message.make_query(name, 'TXT', 'IN', use_edns=True, payload=4096)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    'A'*255)
        response.answer.append(rrset)

        self._toResponderQueue.put(response)
        data = client.query(query.to_wire())
        receivedQuery = None
        if not self._fromResponderQueue.empty():
            receivedQuery = self._fromResponderQueue.get(query)

        receivedResponse = dns.message.from_wire(data)

        self.assertTrue(receivedQuery)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse.question, response.question)
        self.assertTrue(receivedResponse.flags & ~dns.flags.TC)
        self.assertTrue(len(receivedResponse.answer) == 0)
        self.assertTrue(len(receivedResponse.authority) == 0)
        self.assertTrue(len(receivedResponse.additional) == 0)

if __name__ == '__main__':
    unittest.main()
    exit(0)
