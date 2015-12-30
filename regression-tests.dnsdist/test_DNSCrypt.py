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
    generateDNSCryptCertificate("DNSCryptProviderPrivate.key", "DNSCryptResolver.cert", "DNSCryptResolver.key", 42, %d, %d)
    addDNSCryptBind("127.0.0.1:%d", "%s", "DNSCryptResolver.cert", "DNSCryptResolver.key")
    newServer{address="127.0.0.1:%s"}
    """

    _dnsdistcmd = (os.environ['DNSDISTBIN'] + " -C dnsdist_DNSCrypt.conf --acl 127.0.0.1/32 -l 127.0.0.1:" + str(_dnsDistPort)).split()
    _providerFingerprint = 'E1D7:2108:9A59:BF8D:F101:16FA:ED5E:EA6A:9F6C:C78F:7F91:AF6B:027E:62F4:69C3:B1AA'
    _providerName = "2.provider.name"

    @classmethod
    def startDNSDist(cls, shutUp=True):
        print("Launching dnsdist..")
        # valid from 60s ago until 2h from now
        validFrom = time.time() - 60
        validUntil = time.time() + 7200
        with open('dnsdist_DNSCrypt.conf', 'w') as conf:
            conf.write(cls._config_template % (validFrom, validUntil, cls._dnsDistPortDNSCrypt, cls._providerName, str(cls._testServerPort)))

        print(' '.join(cls._dnsdistcmd))
        if shutUp:
            with open(os.devnull, 'w') as fdDevNull:
                cls._dnsdist = subprocess.Popen(cls._dnsdistcmd, close_fds=True, stdout=fdDevNull, stderr=fdDevNull)
        else:
            cls._dnsdist = subprocess.Popen(cls._dnsdistcmd, close_fds=True)

        time.sleep(1)

        if cls._dnsdist.poll() is not None:
            cls._dnsdist.terminate()
            cls._dnsdist.wait()
            sys.exit(cls._dnsdist.returncode)


    def testSimpleA(self):
        """
        Send an encrypted A query.
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
        receivedResponse.id = response.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

if __name__ == '__main__':
    unittest.main()
    exit(0)
