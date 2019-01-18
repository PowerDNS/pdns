#!/usr/bin/env python
import dns
from dnsdisttests import DNSDistTest

class TestSelfAnsweredResponses(DNSDistTest):

    _config_template = """
    -- this is a silly test config, please do not do this in production.
    addAction(makeRule("udp.selfanswered.tests.powerdns.com."), SpoofAction("192.0.2.1"))
    addSelfAnsweredResponseAction(AndRule({makeRule("udp.selfanswered.tests.powerdns.com."), NotRule(MaxQPSRule(1))}), DropResponseAction())
    addAction(makeRule("tcp.selfanswered.tests.powerdns.com."), SpoofAction("192.0.2.1"))
    addSelfAnsweredResponseAction(AndRule({makeRule("tcp.selfanswered.tests.powerdns.com."), NotRule(MaxQPSRule(1))}), DropResponseAction())
    newServer{address="127.0.0.1:%s"}
    """

    def testSelfAnsweredUDP(self):
        """
        SelfAnsweredResponses: Drop when served from the cache
        """
        ttl = 60
        name = 'udp.selfanswered.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)
        response.flags |= dns.flags.RA

        # self-answered, but no SelfAnswered rule matches.
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(receivedResponse, response)

        # self-answered, AND SelfAnswered rule matches. Should not see a reply.
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertIsNone(receivedResponse)

    def testSelfAnsweredTCP(self):
        """
        SelfAnsweredResponses: TCP: Drop after exceeding QPS
        """
        ttl = 60
        name = 'tcp.selfanswered.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    ttl,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)
        response.flags |= dns.flags.RA

        # self-answered, but no SelfAnswered rule matches.
        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        self.assertEquals(receivedResponse, response)

        # self-answered, AND SelfAnswered rule matches. Should not see a reply.
        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertIsNone(receivedResponse)
