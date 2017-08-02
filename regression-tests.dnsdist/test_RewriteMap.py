#!/usr/bin/env python
import dns
from dnsdisttests import DNSDistTest

class TestRewriteMap(DNSDistTest):

    _config_template = """

    rewriteMap =  { ['tests.powerdns.com.'] = 'tests.not-powerdns.org.', ['one-long-domain.org.'] = 'sho.rt.', ['2.0.192.in-addr.arpa.'] = '100.51.198.in-addr.arpa.' }

    addAction(AllRule(), RewriteMapAction(rewriteMap))
    addResponseAction(AllRule(), RewriteMapResponseAction(rewriteMap))

    newServer{address="127.0.0.1:%s"}
    """

    def testRewriteMapCNAME(self):
        """
        RewriteMap: CNAME
        """
        name = 'cname.rewritemap.tests.powerdns.com.'
        rewrittenName = 'cname.rewritemap.tests.not-powerdns.org.'
        query = dns.message.make_query(name, 'A', 'IN')

        rewrittenQuery = dns.message.make_query(rewrittenName, 'A', 'IN')

        backendResponse = dns.message.make_response(rewrittenQuery)
        rrset = dns.rrset.from_text(rewrittenName,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'cname-target.rewritemap.tests.not-powerdns.org.')
        backendResponse.answer.append(rrset)

        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'cname-target.rewritemap.tests.powerdns.com.')
        expectedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, backendResponse)
        receivedQuery.id = rewrittenQuery.id
        self.assertEquals(rewrittenQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, backendResponse)
        receivedQuery.id = rewrittenQuery.id
        self.assertEquals(rewrittenQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

    def testRewriteMapCNAMEShorter(self):
        """
        RewriteMap: CNAME with a target shorter than the initial name
        """
        name = 'cname.one-long-domain.org.'
        rewrittenName = 'cname.sho.rt.'
        query = dns.message.make_query(name, 'A', 'IN')

        rewrittenQuery = dns.message.make_query(rewrittenName, 'A', 'IN')

        backendResponse = dns.message.make_response(rewrittenQuery)
        rrset = dns.rrset.from_text(rewrittenName,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'cname-target.sho.rt.')
        backendResponse.answer.append(rrset)

        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'cname-target.one-long-domain.org.')
        expectedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, backendResponse)
        receivedQuery.id = rewrittenQuery.id
        self.assertEquals(rewrittenQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, backendResponse)
        receivedQuery.id = rewrittenQuery.id
        self.assertEquals(rewrittenQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

    def testRewriteMapUnrelatedCNAME(self):
        """
        RewriteMap: Unrelated CNAME
        """
        name = 'unrelated-cname.rewritemap.tests.powerdns.com.'
        rewrittenName = 'unrelated-cname.rewritemap.tests.not-powerdns.org.'
        query = dns.message.make_query(name, 'A', 'IN')

        rewrittenQuery = dns.message.make_query(rewrittenName, 'A', 'IN')

        backendResponse = dns.message.make_response(rewrittenQuery)
        rrset = dns.rrset.from_text(rewrittenName,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'cname-target.rewritemap.tests.really-really-not-powerdns.org.')
        backendResponse.answer.append(rrset)

        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'cname-target.rewritemap.tests.really-really-not-powerdns.org.')
        expectedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, backendResponse)
        receivedQuery.id = rewrittenQuery.id
        self.assertEquals(rewrittenQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, backendResponse)
        receivedQuery.id = rewrittenQuery.id
        self.assertEquals(rewrittenQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

    def testRewriteMapUnrelatedQueryWithMatchingTarget(self):
        """
        RewriteMap: Unrelated Query with matching target
        """
        name = 'unrelated-query-matching-target.rewritemap.tests.this-domain-is-not-powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'cname-target.rewritemap.tests.not-powerdns.org.')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testRewriteMapMX(self):
        """
        RewriteMap: MX
        """
        name = 'mx.rewritemap.tests.powerdns.com.'
        rewrittenName = 'mx.rewritemap.tests.not-powerdns.org.'
        query = dns.message.make_query(name, 'MX', 'IN')

        rewrittenQuery = dns.message.make_query(rewrittenName, 'MX', 'IN')

        backendResponse = dns.message.make_response(rewrittenQuery)
        rrset = dns.rrset.from_text(rewrittenName,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.MX,
                                    '10 mx-target.rewritemap.tests.not-powerdns.org.')
        backendResponse.answer.append(rrset)

        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.MX,
                                    '10 mx-target.rewritemap.tests.powerdns.com.')
        expectedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, backendResponse)
        receivedQuery.id = rewrittenQuery.id
        self.assertEquals(rewrittenQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, backendResponse)
        receivedQuery.id = rewrittenQuery.id
        self.assertEquals(rewrittenQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

    def testRewriteMapNS(self):
        """
        RewriteMap: NS
        """
        name = 'ns.rewritemap.tests.powerdns.com.'
        rewrittenName = 'ns.rewritemap.tests.not-powerdns.org.'
        query = dns.message.make_query(name, 'NS', 'IN')

        rewrittenQuery = dns.message.make_query(rewrittenName, 'NS', 'IN')

        backendResponse = dns.message.make_response(rewrittenQuery)
        rrset = dns.rrset.from_text(rewrittenName,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.NS,
                                    'ns-target.rewritemap.tests.not-powerdns.org.')
        backendResponse.answer.append(rrset)

        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.NS,
                                    'ns-target.rewritemap.tests.powerdns.com.')
        expectedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, backendResponse)
        receivedQuery.id = rewrittenQuery.id
        self.assertEquals(rewrittenQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, backendResponse)
        receivedQuery.id = rewrittenQuery.id
        self.assertEquals(rewrittenQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

    def testRewriteMapSRV(self):
        """
        RewriteMap: SRV
        """
        name = '_sip._tcp.rewritemap.tests.powerdns.com.'
        rewrittenName = '_sip._tcp.rewritemap.tests.not-powerdns.org.'
        query = dns.message.make_query(name, 'SRV', 'IN')

        rewrittenQuery = dns.message.make_query(rewrittenName, 'SRV', 'IN')

        backendResponse = dns.message.make_response(rewrittenQuery)
        rrset = dns.rrset.from_text(rewrittenName,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.SRV,
                                    '10 50 5060 sip.rewritemap.tests.not-powerdns.org.')
        backendResponse.answer.append(rrset)

        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.SRV,
                                    '10 50 5060 sip.rewritemap.tests.powerdns.com.')
        expectedResponse.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, backendResponse)
        receivedQuery.id = rewrittenQuery.id
        self.assertEquals(rewrittenQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, backendResponse)
        receivedQuery.id = rewrittenQuery.id
        self.assertEquals(rewrittenQuery, receivedQuery)
        self.assertEquals(expectedResponse, receivedResponse)
