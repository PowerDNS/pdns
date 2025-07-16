import dns
import socket
import copy
import os
from recursortests import RecursorTest
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import threading

class InteropTest(RecursorTest):
    _confdir = 'Interop'
    _auth_zones = RecursorTest._default_auth_zones

    _config_template = """dnssec=validate
packetcache-ttl=0 # explicitly disable packetcache
forward-zones=undelegated.secure.example=%s.12
forward-zones+=undelegated.insecure.example=%s.12
    """ % (os.environ['PREFIX'], os.environ['PREFIX'])

    def testFORMERR(self):
        """
        #3841, when we encounter a server that does not understands OPT records
        (or something else), we don't retry without EDNS in dnssec=validate mode
        """
        expected = dns.rrset.from_text('host1.insecure-formerr.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')

        query = dns.message.make_query('cname-to-formerr.secure.example.', 'A')
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)

    def testCNAMEWithLowerEntries(self):
        """
        #4158, When chasing down for DS/DNSKEY and we find a CNAME, skip a level
        """
        expected = dns.rrset.from_text('node1.insecure.sub2.secure.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.18')

        query = dns.message.make_query('node1.insecure.sub2.secure.example.', 'A')
        query.flags |= dns.flags.AD
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], [])
        self.assertRRsetInAnswer(res, expected)

    def testUndelegatedForwardedZoneExisting(self):
        """
        #4369. Ensure we SERVFAIL when forwarding to undelegated zones for a name that exists
        """

        query = dns.message.make_query('node1.undelegated.secure.example.', 'A')
        query.flags |= dns.flags.AD

        # twice, so we hit the record cache
        self.sendUDPQuery(query)
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], [])

    def testUndelegatedForwardedZoneNXDOMAIN(self):
        """
        #4369. Ensure we SERVFAIL when forwarding to undelegated zones for a name that does not exist
        """

        query = dns.message.make_query('node2.undelegated.secure.example.', 'A')
        query.flags |= dns.flags.AD

        # twice, so we hit the negative record cache
        self.sendUDPQuery(query)
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], [])

    def testUndelegatedForwardedInsecureZoneExisting(self):
        """
        #4369. Ensure we answer when forwarding to an undelegated zone in an insecure zone for a name that exists
        """

        expected = dns.rrset.from_text('node1.undelegated.insecure.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.22')
        query = dns.message.make_query('node1.undelegated.insecure.example.', 'A')
        query.flags |= dns.flags.AD

        # twice, so we hit the record cache
        self.sendUDPQuery(query)
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], [])
        self.assertRRsetInAnswer(res, expected)

    def testUndelegatedForwardedInsecureZoneNXDOMAIN(self):
        """
        #4369. Ensure we answer when forwarding to an undelegated zone in an insecure zone for a name that does not exist
        """

        query = dns.message.make_query('node2.undelegated.insecure.example.', 'A')
        query.flags |= dns.flags.AD

        # twice, so we hit the negative record cache
        self.sendUDPQuery(query)
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], [])

    def testBothSecureCNAMEAtApex(self):
        """
        #4466: a CNAME at the apex of a secure domain to another secure domain made us use the wrong DNSKEY to validate
        """
        query = dns.message.make_query('cname-secure.example.', 'A')
        query.flags |= dns.flags.AD

        res = self.sendUDPQuery(query)
        expectedCNAME = dns.rrset.from_text('cname-secure.example.', 0, dns.rdataclass.IN, 'CNAME', 'secure.example.')
        expectedA = dns.rrset.from_text('secure.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.17')

        self.assertRRsetInAnswer(res, expectedA)
        self.assertRRsetInAnswer(res, expectedCNAME)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RD', 'RA', 'AD'], [])

    def testNonApexDNSKEY(self):
        """
        a DNSKEY not at the apex of a zone should not be treated as a DNSKEY in validation
        """
        query = dns.message.make_query('non-apex-dnskey.secure.example.', 'DNSKEY')
        query.flags |= dns.flags.AD

        res = self.sendUDPQuery(query)
        print(res)
        expectedDNSKEY = dns.rrset.from_text('non-apex-dnskey.secure.example.', 0, dns.rdataclass.IN, 'DNSKEY', '257 3 13 CT6AJ4MEOtNDgj0+xLtTLGHf1WbLsKWZI8ONHOt/6q7hTjeWSnY/SGig1dIKZrHg+pJFUSPaxeShv48SYVRKEg==')

        self.assertRRsetInAnswer(res, expectedDNSKEY)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RD', 'RA', 'AD'], [])


    @classmethod
    def startResponders(cls):
        print("Launching responders..")

        address = cls._PREFIX + '.2'
        port = 53

        reactor.listenUDP(port, UDPResponder(), interface=address)

        if not reactor.running:
            cls._UDPResponder = threading.Thread(name='UDP Responder', target=reactor.run, args=(False,))
            cls._UDPResponder.setDaemon(True)
            cls._UDPResponder.start()

class InteropProcessTest(RecursorTest):
    _confdir = 'InteropProcess'
    _auth_zones = RecursorTest._default_auth_zones

    _config_template = """dnssec=process
packetcache-ttl=0 # explicitly disable packetcache
forward-zones=undelegated.secure.example=%s.12
forward-zones+=undelegated.insecure.example=%s.12
    """ % (os.environ['PREFIX'], os.environ['PREFIX'])

    def testNonApexDNSKEY2(self):
        """
        a DNSKEY not at the apex of a zone should not be treated as a DNSKEY in validation,
        even when it was cached with Indeterminate validation state before
        """

        # send the query with +CD so the record ends up cached with Indeterminate validation state
        query = dns.message.make_query('non-apex-dnskey2.secure.example.', 'DNSKEY')
        query.flags |= dns.flags.CD

        res = self.sendUDPQuery(query)
        print(res)
        expectedDNSKEY = dns.rrset.from_text('non-apex-dnskey2.secure.example.', 0, dns.rdataclass.IN, 'DNSKEY', '256 3 13 CT6AJ4MEOtNDgj0+xLtTLGHf1WbLsKWZI8ONHOt/6q7hTjeWSnY/SGig1dIKZrHg+pJFUSPaxeShv48SYVRKEg==')

        self.assertRRsetInAnswer(res, expectedDNSKEY)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RD', 'RA', 'CD'], [])

        # now ask again with +AD so it has to be validated from cache
        query = dns.message.make_query('non-apex-dnskey2.secure.example.', 'DNSKEY')
        query.flags |= dns.flags.AD

        res = self.sendUDPQuery(query)
        print(res)
        expectedDNSKEY = dns.rrset.from_text('non-apex-dnskey2.secure.example.', 0, dns.rdataclass.IN, 'DNSKEY', '256 3 13 CT6AJ4MEOtNDgj0+xLtTLGHf1WbLsKWZI8ONHOt/6q7hTjeWSnY/SGig1dIKZrHg+pJFUSPaxeShv48SYVRKEg==')

        self.assertRRsetInAnswer(res, expectedDNSKEY)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RD', 'RA', 'AD'], [])

    def testNonApexDNSKEYANYQuery(self):
        """
        a DNSKEY not at the apex of a zone should not be treated as a DNSKEY in validation,
        even when it was cached with Indeterminate validation state before.
        This code tests the ANY path which is separate from the qtype=DNSKEY path tested in testNonApexDNSKEY2
        """

        # send the query with +CD so the record ends up cached with Indeterminate validation state
        query = dns.message.make_query('non-apex-dnskey3.secure.example.', 'DNSKEY')
        query.flags |= dns.flags.CD

        res = self.sendUDPQuery(query)
        print(res)
        expectedDNSKEY = dns.rrset.from_text('non-apex-dnskey3.secure.example.', 0, dns.rdataclass.IN, 'DNSKEY', '256 3 13 DT6AJ4MEOtNDgj0+xLtTLGHf1WbLsKWZI8ONHOt/6q7hTjeWSnY/SGig1dIKZrHg+pJFUSPaxeShv48SYVRKEg==')

        self.assertRRsetInAnswer(res, expectedDNSKEY)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RD', 'RA', 'CD'], [])

        # now ask again with +AD so it has to be validated from cache
        query = dns.message.make_query('non-apex-dnskey3.secure.example.', 'ANY')
        query.flags |= dns.flags.AD

        res = self.sendUDPQuery(query)
        print(res)
        expectedDNSKEY = dns.rrset.from_text('non-apex-dnskey3.secure.example.', 0, dns.rdataclass.IN, 'DNSKEY', '256 3 13 DT6AJ4MEOtNDgj0+xLtTLGHf1WbLsKWZI8ONHOt/6q7hTjeWSnY/SGig1dIKZrHg+pJFUSPaxeShv48SYVRKEg==')

        self.assertRRsetInAnswer(res, expectedDNSKEY)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RD', 'RA', 'AD'], [])

class UDPResponder(DatagramProtocol):
    def datagramReceived(self, datagram, address):
        request = dns.message.from_wire(datagram)

        response = dns.message.make_response(request)
        response.flags = dns.flags.AA + dns.flags.QR

        if request.edns != -1:
            response.set_rcode(dns.rcode.FORMERR)
            response.use_edns(edns=-1)

            response.additional = []
        else:
            if request.question[0].name == dns.name.from_text('host1.insecure-formerr.example.') and request.question[0].rdtype == dns.rdatatype.A:
                answer = dns.rrset.from_text('host1.insecure-formerr.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.1')
                response.answer.append(answer)
            elif request.question[0].name == dns.name.from_text('insecure-formerr.example.') and request.question[0].rdtype == dns.rdatatype.NS:
                answer = dns.rrset.from_text('insecure-formerr.example.', 15, dns.rdataclass.IN, 'NS', 'ns1.insecure-formerr.example.')
                response.answer.append(answer)
                additional = dns.rrset.from_text('ns1.insecure-formerr.example.', 15, dns.rdataclass.IN, 'A', '127.0.0.2')
                response.additional.append(additional)

        self.transport.write(response.to_wire(), address)
