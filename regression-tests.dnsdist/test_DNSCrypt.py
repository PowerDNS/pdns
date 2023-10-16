#!/usr/bin/env python
import base64
import socket
import time
import dns
import dns.message
from dnsdisttests import DNSDistTest, pickAvailablePort
import dnscrypt

class DNSCryptTest(DNSDistTest):
    """
    dnsdist is configured to accept DNSCrypt queries on 127.0.0.1:_dnsDistPortDNSCrypt.
    The provider's keys have been generated with:
    generateDNSCryptProviderKeys("DNSCryptProviderPublic.key", "DNSCryptProviderPrivate.key")
    Be careful to change the _providerFingerprint below if you want to regenerate the keys.
    """

    _dnsDistPortDNSCrypt = pickAvailablePort()

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')

    _providerFingerprint = 'E1D7:2108:9A59:BF8D:F101:16FA:ED5E:EA6A:9F6C:C78F:7F91:AF6B:027E:62F4:69C3:B1AA'
    _providerName = "2.provider.name"
    _resolverCertificateSerial = 42

    # valid from 60s ago until 2h from now
    _resolverCertificateValidFrom = int(time.time() - 60)
    _resolverCertificateValidUntil = int(time.time() + 7200)

    def doDNSCryptQuery(self, client, query, response, tcp):
        self._toResponderQueue.put(response)
        data = client.query(query.to_wire(), tcp=tcp)
        receivedResponse = dns.message.from_wire(data)
        receivedQuery = None
        if not self._fromResponderQueue.empty():
            receivedQuery = self._fromResponderQueue.get(query)

        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)


class TestDNSCrypt(DNSCryptTest):
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")
    generateDNSCryptCertificate("DNSCryptProviderPrivate.key", "DNSCryptResolver.cert", "DNSCryptResolver.key", %d, %d, %d)
    addDNSCryptBind("127.0.0.1:%d", "%s", "DNSCryptResolver.cert", "DNSCryptResolver.key")
    newServer{address="127.0.0.1:%s"}

    function checkDNSCryptUDP(dq)
      if dq:getProtocol() ~= "DNSCrypt UDP" then
        return DNSAction.Spoof, '1.2.3.4'
      end
      return DNSAction.None
    end

    function checkDNSCryptTCP(dq)
      if dq:getProtocol() ~= "DNSCrypt TCP" then
        return DNSAction.Spoof, '1.2.3.4'
      end
      return DNSAction.None
    end

    addAction("udp.protocols.dnscrypt.tests.powerdns.com.", LuaAction(checkDNSCryptUDP))
    addAction("tcp.protocols.dnscrypt.tests.powerdns.com.", LuaAction(checkDNSCryptTCP))
    """

    _config_params = ['_consoleKeyB64', '_consolePort', '_resolverCertificateSerial', '_resolverCertificateValidFrom', '_resolverCertificateValidUntil', '_dnsDistPortDNSCrypt', '_providerName', '_testServerPort']

    def testSimpleA(self):
        """
        DNSCrypt: encrypted A query
        """
        client = dnscrypt.DNSCryptClient(self._providerName, self._providerFingerprint, "127.0.0.1", self._dnsDistPortDNSCrypt)
        name = 'a.dnscrypt.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.2.0.1')
        response.answer.append(rrset)

        self.doDNSCryptQuery(client, query, response, False)
        self.doDNSCryptQuery(client, query, response, True)

    def testResponseLargerThanPaddedQuery(self):
        """
        DNSCrypt: response larger than query

        Send a small encrypted query (don't forget to take
        the padding into account) and check that the response
        is truncated.
        """
        client = dnscrypt.DNSCryptClient(self._providerName, self._providerFingerprint, "127.0.0.1", self._dnsDistPortDNSCrypt)
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
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse.question, response.question)
        self.assertTrue(receivedResponse.flags & ~dns.flags.TC)
        self.assertTrue(len(receivedResponse.answer) == 0)
        self.assertTrue(len(receivedResponse.authority) == 0)
        self.assertTrue(len(receivedResponse.additional) == 0)

    def testCertRotation(self):
        """
        DNSCrypt: certificate rotation
        """
        client = dnscrypt.DNSCryptClient(self._providerName, self._providerFingerprint, "127.0.0.1", self._dnsDistPortDNSCrypt)
        client.refreshResolverCertificates()

        cert = client.getResolverCertificate()
        self.assertTrue(cert)
        self.assertEqual(cert.serial, self._resolverCertificateSerial)

        name = 'rotation.dnscrypt.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.2.0.1')
        response.answer.append(rrset)

        self.doDNSCryptQuery(client, query, response, False)
        self.doDNSCryptQuery(client, query, response, True)

        # generate a new certificate
        self.sendConsoleCommand("generateDNSCryptCertificate('DNSCryptProviderPrivate.key', 'DNSCryptResolver.cert.2', 'DNSCryptResolver.key.2', {!s}, {:.0f}, {:.0f})".format(self._resolverCertificateSerial + 1, self._resolverCertificateValidFrom, self._resolverCertificateValidUntil))
        # add that new certificate
        self.sendConsoleCommand("getDNSCryptBind(0):loadNewCertificate('DNSCryptResolver.cert.2', 'DNSCryptResolver.key.2')")

        oldSerial = self.sendConsoleCommand("getDNSCryptBind(0):getCertificate(0):getSerial()")
        self.assertEqual(int(oldSerial), self._resolverCertificateSerial)
        effectiveSerial = self.sendConsoleCommand("getDNSCryptBind(0):getCertificate(1):getSerial()")
        self.assertEqual(int(effectiveSerial), self._resolverCertificateSerial + 1)
        tsStart = self.sendConsoleCommand("getDNSCryptBind(0):getCertificate(1):getTSStart()")
        self.assertEqual(int(tsStart), self._resolverCertificateValidFrom)
        tsEnd = self.sendConsoleCommand("getDNSCryptBind(0):getCertificate(1):getTSEnd()")
        self.assertEqual(int(tsEnd), self._resolverCertificateValidUntil)

        # we should still be able to send queries with the previous certificate
        self.doDNSCryptQuery(client, query, response, False)
        self.doDNSCryptQuery(client, query, response, True)
        cert = client.getResolverCertificate()
        self.assertTrue(cert)
        self.assertEqual(cert.serial, self._resolverCertificateSerial)

        # but refreshing should get us the new one
        client.refreshResolverCertificates()
        cert = client.getResolverCertificate()
        self.assertTrue(cert)
        self.assertEqual(cert.serial, self._resolverCertificateSerial + 1)
        # we should still get the old ones
        certs = client.getAllResolverCertificates(True)
        self.assertEqual(len(certs), 2)
        self.assertEqual(certs[0].serial, self._resolverCertificateSerial)
        self.assertEqual(certs[1].serial, self._resolverCertificateSerial + 1)

        # generate a third certificate, this time in memory
        self.sendConsoleCommand("getDNSCryptBind(0):generateAndLoadInMemoryCertificate('DNSCryptProviderPrivate.key', {!s}, {:.0f}, {:.0f})".format(self._resolverCertificateSerial + 2, self._resolverCertificateValidFrom, self._resolverCertificateValidUntil))

        # we should still be able to send queries with the previous certificate
        self.doDNSCryptQuery(client, query, response, False)
        self.doDNSCryptQuery(client, query, response, True)
        cert = client.getResolverCertificate()
        self.assertTrue(cert)
        self.assertEqual(cert.serial, self._resolverCertificateSerial + 1)

        # but refreshing should get us the new one
        client.refreshResolverCertificates()
        cert = client.getResolverCertificate()
        self.assertTrue(cert)
        self.assertEqual(cert.serial, self._resolverCertificateSerial + 2)
        # we should still get the old ones
        certs = client.getAllResolverCertificates(True)
        self.assertEqual(len(certs), 3)
        self.assertEqual(certs[0].serial, self._resolverCertificateSerial)
        self.assertEqual(certs[1].serial, self._resolverCertificateSerial + 1)
        self.assertEqual(certs[2].serial, self._resolverCertificateSerial + 2)

        # generate a fourth certificate, still in memory
        self.sendConsoleCommand("getDNSCryptBind(0):generateAndLoadInMemoryCertificate('DNSCryptProviderPrivate.key', {!s}, {:.0f}, {:.0f})".format(self._resolverCertificateSerial + 3, self._resolverCertificateValidFrom, self._resolverCertificateValidUntil))

        # mark the old ones as inactive
        self.sendConsoleCommand("getDNSCryptBind(0):markInactive({!s})".format(self._resolverCertificateSerial))
        self.sendConsoleCommand("getDNSCryptBind(0):markInactive({!s})".format(self._resolverCertificateSerial + 1))
        self.sendConsoleCommand("getDNSCryptBind(0):markInactive({!s})".format(self._resolverCertificateSerial + 2))
        # we should still be able to send queries with the third one
        self.doDNSCryptQuery(client, query, response, False)
        self.doDNSCryptQuery(client, query, response, True)
        cert = client.getResolverCertificate()
        self.assertTrue(cert)
        self.assertEqual(cert.serial, self._resolverCertificateSerial + 2)
        # now remove them
        self.sendConsoleCommand("getDNSCryptBind(0):removeInactiveCertificate({!s})".format(self._resolverCertificateSerial))
        self.sendConsoleCommand("getDNSCryptBind(0):removeInactiveCertificate({!s})".format(self._resolverCertificateSerial + 1))
        self.sendConsoleCommand("getDNSCryptBind(0):removeInactiveCertificate({!s})".format(self._resolverCertificateSerial + 2))

        # we should not be able to send with the old ones anymore
        try:
            data = client.query(query.to_wire())
        except socket.timeout:
            data = None
        self.assertEqual(data, None)

        # refreshing should get us the fourth one
        client.refreshResolverCertificates()
        cert = client.getResolverCertificate()
        self.assertTrue(cert)
        self.assertEqual(cert.serial, self._resolverCertificateSerial + 3)
        # and only that one
        certs = client.getAllResolverCertificates(True)
        self.assertEqual(len(certs), 1)
        # and we should be able to query with it
        self.doDNSCryptQuery(client, query, response, False)
        self.doDNSCryptQuery(client, query, response, True)
        cert = client.getResolverCertificate()
        self.assertTrue(cert)
        self.assertEqual(cert.serial, self._resolverCertificateSerial + 3)

    def testProtocolUDP(self):
        """
        DNSCrypt: Test DNSQuestion.Protocol over UDP
        """
        client = dnscrypt.DNSCryptClient(self._providerName, self._providerFingerprint, "127.0.0.1", self._dnsDistPortDNSCrypt)
        name = 'udp.protocols.dnscrypt.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        self.doDNSCryptQuery(client, query, response, False)

    def testProtocolTCP(self):
        """
        DNSCrypt: Test DNSQuestion.Protocol over TCP
        """
        client = dnscrypt.DNSCryptClient(self._providerName, self._providerFingerprint, "127.0.0.1", self._dnsDistPortDNSCrypt)
        name = 'tcp.protocols.dnscrypt.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        self.doDNSCryptQuery(client, query, response, True)

class TestDNSCryptWithCache(DNSCryptTest):

    _config_params = ['_resolverCertificateSerial', '_resolverCertificateValidFrom', '_resolverCertificateValidUntil', '_dnsDistPortDNSCrypt', '_providerName', '_testServerPort']
    _config_template = """
    generateDNSCryptCertificate("DNSCryptProviderPrivate.key", "DNSCryptResolver.cert", "DNSCryptResolver.key", %d, %d, %d)
    addDNSCryptBind("127.0.0.1:%d", "%s", "DNSCryptResolver.cert", "DNSCryptResolver.key")
    pc = newPacketCache(5, {maxTTL=86400, minTTL=1, numberOfShards=1})
    getPool(""):setCache(pc)
    newServer{address="127.0.0.1:%s"}
    """

    def testCachedSimpleA(self):
        """
        DNSCrypt: encrypted A query served from cache
        """
        misses = 0
        client = dnscrypt.DNSCryptClient(self._providerName, self._providerFingerprint, "127.0.0.1", self._dnsDistPortDNSCrypt)
        name = 'cacheda.dnscrypt.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.2.0.1')
        response.answer.append(rrset)

        # first query to fill the cache
        self._toResponderQueue.put(response)
        data = client.query(query.to_wire())
        receivedResponse = dns.message.from_wire(data)
        receivedQuery = None
        if not self._fromResponderQueue.empty():
            receivedQuery = self._fromResponderQueue.get(query)

        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
        misses += 1

        # second query should get a cached response
        data = client.query(query.to_wire())
        receivedResponse = dns.message.from_wire(data)
        receivedQuery = None
        if not self._fromResponderQueue.empty():
            receivedQuery = self._fromResponderQueue.get(query)

        self.assertEqual(receivedQuery, None)
        self.assertTrue(receivedResponse)
        self.assertEqual(response, receivedResponse)
        total = 0
        for key in self._responsesCounter:
            total += self._responsesCounter[key]
        self.assertEqual(total, misses)

class TestDNSCryptAutomaticRotation(DNSCryptTest):
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")
    generateDNSCryptCertificate("DNSCryptProviderPrivate.key", "DNSCryptResolver.cert", "DNSCryptResolver.key", %d, %d, %d)
    addDNSCryptBind("127.0.0.1:%d", "%s", "DNSCryptResolver.cert", "DNSCryptResolver.key")
    newServer{address="127.0.0.1:%s"}

    local last = 0
    serial = %d
    function maintenance()
      local now = os.time()
      if ((now - last) > 2) then
        serial = serial + 1
        getDNSCryptBind(0):generateAndLoadInMemoryCertificate('DNSCryptProviderPrivate.key', serial, now - 60, now + 120)
        last = now
      end
    end
    """

    _config_params = ['_consoleKeyB64', '_consolePort', '_resolverCertificateSerial', '_resolverCertificateValidFrom', '_resolverCertificateValidUntil', '_dnsDistPortDNSCrypt', '_providerName', '_testServerPort', '_resolverCertificateSerial']

    def testCertRotation(self):
        """
        DNSCrypt: automatic certificate rotation
        """
        client = dnscrypt.DNSCryptClient(self._providerName, self._providerFingerprint, "127.0.0.1", self._dnsDistPortDNSCrypt)

        client.refreshResolverCertificates()
        cert = client.getResolverCertificate()
        self.assertTrue(cert)
        firstSerial = cert.serial
        self.assertGreaterEqual(cert.serial, self._resolverCertificateSerial)

        time.sleep(3)

        client.refreshResolverCertificates()
        cert = client.getResolverCertificate()
        self.assertTrue(cert)
        secondSerial = cert.serial
        self.assertGreater(cert.serial, firstSerial)

        name = 'automatic-rotation.dnscrypt.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.2.0.1')
        response.answer.append(rrset)

        self.doDNSCryptQuery(client, query, response, False)
        self.doDNSCryptQuery(client, query, response, True)
