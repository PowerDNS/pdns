#!/usr/bin/env python

import dns
from dnsdisttests import DNSDistTest

class XPFTest(DNSDistTest):
    """
    dnsdist is configured to add XPF to the query
    """

    _xpfCode = 65422
    _config_template = """
    newServer{address="127.0.0.1:%d", addXPF=%d}
    """
    _config_params = ['_testServerPort', '_xpfCode']

    def checkMessageHasXPF(self, msg, expectedValue):
        self.assertGreaterEqual(len(msg.additional), 1)

        found = False
        for add in msg.additional:
            if add.rdtype == self._xpfCode:
                found = True
                self.assertEquals(add.rdclass, dns.rdataclass.IN)
                self.assertEquals(add.ttl, 0)
                xpfData = add.to_rdataset()[0].to_text()
                # skip the ports
                self.assertEquals(xpfData[:26], expectedValue[:26])

        self.assertTrue(found)

    def testXPF(self):
        """
        XPF
        """
        name = 'xpf.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        expectedQuery = dns.message.make_query(name, 'A', 'IN')
        # 0x04 is IPv4, 0x11 (17) is UDP then 127.0.0.1 as source and destination
        # and finally the ports, zeroed because we have no way to know them beforehand
        xpfData = "\# 14 04117f0000017f00000100000000"
        rdata = dns.rdata.from_text(dns.rdataclass.IN, self._xpfCode, xpfData)
        rrset = dns.rrset.from_rdata(name, 60, rdata)
        expectedQuery.additional.append(rrset)

        response = dns.message.make_response(expectedQuery)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        receivedResponse.id = response.id

        self.assertEquals(receivedQuery, expectedQuery)
        self.checkMessageHasXPF(receivedQuery, xpfData)
        self.assertEquals(response, receivedResponse)

        expectedQuery = dns.message.make_query(name, 'A', 'IN')
        # 0x04 is IPv4, 0x06 (6) is TCP then 127.0.0.1 as source and destination
        # and finally the ports, zeroed because we have no way to know them beforehand
        xpfData = "\# 14 04067f0000017f00000100000000"
        rdata = dns.rdata.from_text(dns.rdataclass.IN, self._xpfCode, xpfData)
        rrset = dns.rrset.from_rdata(name, 60, rdata)
        expectedQuery.additional.append(rrset)

        response = dns.message.make_response(expectedQuery)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = expectedQuery.id
        receivedResponse.id = response.id

        self.assertEquals(receivedQuery, expectedQuery)
        self.checkMessageHasXPF(receivedQuery, xpfData)
        self.assertEquals(response, receivedResponse)
