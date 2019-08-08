#!/usr/bin/env python

from __future__ import print_function

import threading
import unittest

import dns
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

from authtests import AuthTest

aliasUDPReactorRunning = False


class TestALIAS(AuthTest):
    _config_template = """
expand-alias=yes
resolver=%s.1:5301
any-to-tcp=no
launch=bind
"""

    _config_params = ['_PREFIX']

    _zones = {
        'example.org': """
example.org.                 3600 IN SOA  {soa}
example.org.                 3600 IN NS   ns1.example.org.
example.org.                 3600 IN NS   ns2.example.org.
ns1.example.org.             3600 IN A    {prefix}.10
ns2.example.org.             3600 IN A    {prefix}.11

noerror.example.org.         3600 IN ALIAS noerror.example.com.
nxd.example.org.             3600 IN ALIAS nxd.example.com.
servfail.example.org.        3600 IN ALIAS servfail.example.com
        """,
    }

    @classmethod
    def startResponders(cls):
        global aliasUDPReactorRunning

        address = cls._PREFIX + '.1'
        port = 5301

        if not aliasUDPReactorRunning:
            reactor.listenUDP(port, AliasUDPResponder(), interface=address)

            aliasUDPReactorRunning = True

        if not reactor.running:
            cls._ALIASResponder = threading.Thread(name='ALIAS Responder',
                                                   target=reactor.run,
                                                   args=(False,))
            cls._ALIASResponder.setDaemon(True)
            cls._ALIASResponder.start()

    def testNoError(self):
        expected_a = [dns.rrset.from_text('noerror.example.org.',
                                          0, dns.rdataclass.IN, 'A',
                                          '192.0.2.1')]
        expected_aaaa = [dns.rrset.from_text('noerror.example.org.',
                                             0, dns.rdataclass.IN, 'AAAA',
                                             '2001:DB8::1')]

        query = dns.message.make_query('noerror.example.org', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_a)

        query = dns.message.make_query('noerror.example.org', 'AAAA')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_aaaa)

        query = dns.message.make_query('noerror.example.org', 'ANY')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_a)
        self.assertAnyRRsetInAnswer(res, expected_aaaa)

        # NODATA
        query = dns.message.make_query('noerror.example.org', 'MX')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(len(res.answer), 0)

    def testNxDomain(self):
        query = dns.message.make_query('nxd.example.org', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        query = dns.message.make_query('nxd.example.org', 'AAAA')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        # TODO this should actually return SOA + NS?
        query = dns.message.make_query('nxd.example.org', 'ANY')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

    def testServFail(self):
        query = dns.message.make_query('servfail.example.org', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        query = dns.message.make_query('servfail.example.org', 'AAAA')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        # TODO this should actually return SOA + NS?
        query = dns.message.make_query('servfail.example.org', 'ANY')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

    def testNoErrorTCP(self):
        expected_a = [dns.rrset.from_text('noerror.example.org.',
                                          0, dns.rdataclass.IN, 'A',
                                          '192.0.2.1')]
        expected_aaaa = [dns.rrset.from_text('noerror.example.org.',
                                             0, dns.rdataclass.IN, 'AAAA',
                                             '2001:DB8::1')]

        query = dns.message.make_query('noerror.example.org', 'A')
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_a)

        query = dns.message.make_query('noerror.example.org', 'AAAA')
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_aaaa)

        query = dns.message.make_query('noerror.example.org', 'ANY')
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_a)
        self.assertAnyRRsetInAnswer(res, expected_aaaa)

        # NODATA
        query = dns.message.make_query('noerror.example.org', 'MX')
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(len(res.answer), 0)

    def testNxDomainTCP(self):
        query = dns.message.make_query('nxd.example.org', 'A')
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        query = dns.message.make_query('nxd.example.org', 'AAAA')
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        query = dns.message.make_query('nxd.example.org', 'ANY')
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

    def testServFailTCP(self):
        query = dns.message.make_query('servfail.example.org', 'A')
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        query = dns.message.make_query('servfail.example.org', 'AAAA')
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        query = dns.message.make_query('servfail.example.org', 'ANY')
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)


class AliasUDPResponder(DatagramProtocol):
    def datagramReceived(self, datagram, address):
        request = dns.message.from_wire(datagram)
        response = dns.message.make_response(request)
        response.use_edns(edns=False)
        response.flags |= dns.flags.RA

        if request.question[0].name == dns.name.from_text(
                'noerror.example.com.'):
            response.set_rcode(dns.rcode.NOERROR)
            if request.question[0].rdtype in [dns.rdatatype.A,
                                              dns.rdatatype.ANY]:
                response.answer.append(
                    dns.rrset.from_text(
                        request.question[0].name,
                        0, dns.rdataclass.IN, 'A', '192.0.2.1'))

            if request.question[0].rdtype in [dns.rdatatype.AAAA,
                                              dns.rdatatype.ANY]:
                response.answer.append(
                    dns.rrset.from_text(request.question[0].name,
                                        0, dns.rdataclass.IN, 'AAAA',
                                        '2001:DB8::1'))
        if request.question[0].name == dns.name.from_text(
                'nxd.example.com.'):
            response.set_rcode(dns.rcode.NXDOMAIN)
            response.authority.append(
                dns.rrset.from_text(
                    'example.com.',
                    0, dns.rdataclass.IN, 'SOA', 'ns1.example.com. hostmaster.example.com. 2018062101 1 2 3 4'))

        if request.question[0].name == dns.name.from_text(
                'servfail.example.com.'):
            response.set_rcode(dns.rcode.SERVFAIL)

        self.transport.write(response.to_wire(max_size=65535), address)
