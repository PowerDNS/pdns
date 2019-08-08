#!/usr/bin/env python
import copy
import os
import dns
from dnsdisttests import DNSDistTest

class TestRecordsCountOnlyOneAR(DNSDistTest):

    _config_template = """
    addAction(NotRule(RecordsCountRule(DNSSection.Additional, 1, 1)), RCodeAction(DNSRCode.REFUSED))
    newServer{address="127.0.0.1:%s"}
    """

    def testRecordsCountRefuseEmptyAR(self):
        """
        RecordsCount: Refuse arcount == 0 (No OPT)

        Send a query to "refuseemptyar.recordscount.tests.powerdns.com.",
        check that we are getting a REFUSED response.
        """
        name = 'refuseemptyar.recordscount.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, expectedResponse)

    def testRecordsCountAllowOneAR(self):
        """
        RecordsCount: Allow arcount == 1 (OPT)

        Send a query to "allowonear.recordscount.tests.powerdns.com.",
        check that we are getting a valid response.
        """
        name = 'allowonear.recordscount.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text(name,
                                                   3600,
                                                   dns.rdataclass.IN,
                                                   dns.rdatatype.A,
                                                   '127.0.0.1'))

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

    def testRecordsCountRefuseTwoAR(self):
        """
        RecordsCount: Refuse arcount > 1 (OPT + a bogus additional record)

        Send a query to "refusetwoar.recordscount.tests.powerdns.com.",
        check that we are getting a REFUSED response.
        """
        name = 'refusetwoar.recordscount.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        query.additional.append(dns.rrset.from_text(name,
                                                    3600,
                                                    dns.rdataclass.IN,
                                                    dns.rdatatype.A,
                                                    '127.0.0.1'))
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, expectedResponse)

class TestRecordsCountMoreThanOneLessThanFour(DNSDistTest):

    _config_template = """
    addAction(RecordsCountRule(DNSSection.Answer, 2, 3), AllowAction())
    addAction(AllRule(), RCodeAction(DNSRCode.REFUSED))
    newServer{address="127.0.0.1:%s"}
    """

    def testRecordsCountRefuseOneAN(self):
        """
        RecordsCount: Refuse ancount == 0

        Send a query to "refusenoan.recordscount.tests.powerdns.com.",
        check that we are getting a REFUSED response.
        """
        name = 'refusenoan.recordscount.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, expectedResponse)

    def testRecordsCountAllowTwoAN(self):
        """
        RecordsCount: Allow ancount == 2

        Send a query to "allowtwoan.recordscount.tests.powerdns.com.",
        check that we are getting a valid response.
        """
        name = 'allowtwoan.recordscount.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        rrset = dns.rrset.from_text_list(name,
                                         3600,
                                         dns.rdataclass.IN,
                                         dns.rdatatype.A,
                                         ['127.0.0.1', '127.0.0.2'])
        query.answer.append(rrset)
        response = dns.message.make_response(query)
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

    def testRecordsCountRefuseFourAN(self):
        """
        RecordsCount: Refuse ancount > 3

        Send a query to "refusefouran.recordscount.tests.powerdns.com.",
        check that we are getting a REFUSED response.
        """
        name = 'refusefouran.recordscount.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        rrset = dns.rrset.from_text_list(name,
                                         3600,
                                         dns.rdataclass.IN,
                                         dns.rdatatype.A,
                                         ['127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4'])
        query.answer.append(rrset)

        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, expectedResponse)

class TestRecordsCountNothingInNS(DNSDistTest):

    _config_template = """
    addAction(RecordsCountRule(DNSSection.Authority, 0, 0), AllowAction())
    addAction(AllRule(), RCodeAction(DNSRCode.REFUSED))
    newServer{address="127.0.0.1:%s"}
    """

    def testRecordsCountRefuseNS(self):
        """
        RecordsCount: Refuse nscount != 0

        Send a query to "refusens.recordscount.tests.powerdns.com.",
        check that we are getting a REFUSED response.
        """
        name = 'refusens.recordscount.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.NS,
                                    'ns.tests.powerdns.com.')
        query.authority.append(rrset)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)
        expectedResponse.authority.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, expectedResponse)


    def testRecordsCountAllowEmptyNS(self):
        """
        RecordsCount: Allow nscount == 0

        Send a query to "allowns.recordscount.tests.powerdns.com.",
        check that we are getting a valid response.
        """
        name = 'allowns.recordscount.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text(name,
                                                   3600,
                                                   dns.rdataclass.IN,
                                                   dns.rdatatype.A,
                                                   '127.0.0.1'))

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

class TestRecordsCountNoOPTInAR(DNSDistTest):

    _config_template = """
    addAction(NotRule(RecordsTypeCountRule(DNSSection.Additional, DNSQType.OPT, 0, 0)), RCodeAction(DNSRCode.REFUSED))
    newServer{address="127.0.0.1:%s"}
    """

    def testRecordsCountRefuseOPTinAR(self):
        """
        RecordsTypeCount: Refuse OPT in AR

        Send a query to "refuseoptinar.recordscount.tests.powerdns.com.",
        check that we are getting a REFUSED response.
        """
        name = 'refuseoptinar.recordscount.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEquals(receivedResponse, expectedResponse)

    def testRecordsCountAllowNoOPTInAR(self):
        """
        RecordsTypeCount: Allow no OPT in AR

        Send a query to "allownooptinar.recordscount.tests.powerdns.com.",
        check that we are getting a valid response.
        """
        name = 'allowwnooptinar.recordscount.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text(name,
                                                   3600,
                                                   dns.rdataclass.IN,
                                                   dns.rdatatype.A,
                                                   '127.0.0.1'))

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)

    def testRecordsCountAllowTwoARButNoOPT(self):
        """
        RecordsTypeCount: Allow arcount > 1 without OPT

        Send a query to "allowtwoarnoopt.recordscount.tests.powerdns.com.",
        check that we are getting a valid response.
        """
        name = 'allowtwoarnoopt.recordscount.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.additional.append(dns.rrset.from_text(name,
                                                    3600,
                                                    dns.rdataclass.IN,
                                                    dns.rdatatype.A,
                                                    '127.0.0.1'))
        query.additional.append(dns.rrset.from_text(name,
                                                    3600,
                                                    dns.rdataclass.IN,
                                                    dns.rdatatype.A,
                                                    '127.0.0.1'))

        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text(name,
                                                   3600,
                                                   dns.rdataclass.IN,
                                                   dns.rdatatype.A,
                                                   '127.0.0.1'))

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEquals(query, receivedQuery)
            self.assertEquals(response, receivedResponse)
