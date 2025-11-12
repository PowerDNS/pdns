#!/usr/bin/env python
import base64
from datetime import datetime, timedelta
import os
import sys
import time
import unittest
import dns
import clientsubnetoption
import cookiesoption
from dnsdisttests import DNSDistTest

class TestAdvancedAllow(DNSDistTest):

    _config_template = """
    addAction(AllRule(), NoneAction())
    addAction(QNameSuffixRule("allowed.advanced.tests.powerdns.com."), AllowAction())
    addAction(AllRule(), DropAction())
    newServer{address="127.0.0.1:%d"}
    """

    def testAdvancedAllow(self):
        """
        Advanced: Allowed qname is not dropped

        A query for allowed.advanced.tests.powerdns.com. should be allowed
        while others should be dropped.
        """
        name = 'allowed.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

    def testAdvancedAllowDropped(self):
        """
        Advanced: Not allowed qname is dropped

        A query for notallowed.advanced.tests.powerdns.com. should be dropped.
        """
        name = 'notallowed.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, None)

class TestAdvancedRemoveRD(DNSDistTest):

    _config_template = """
    addAction("norecurse.advanced.tests.powerdns.com.", SetNoRecurseAction())
    newServer{address="127.0.0.1:%d"}
    """

    def testAdvancedNoRD(self):
        """
        Advanced: No RD

        Send a query with RD,
        check that dnsdist clears the RD flag.
        """
        name = 'norecurse.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN')
        expectedQuery.flags &= ~dns.flags.RD

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.assertEqual(expectedQuery, receivedQuery)
            self.assertEqual(response, receivedResponse)

    def testAdvancedKeepRD(self):
        """
        Advanced: No RD canary

        Send a query with RD for a canary domain,
        check that dnsdist does not clear the RD flag.
        """
        name = 'keeprecurse.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

class TestAdvancedAddCD(DNSDistTest):

    _config_template = """
    addAction("setcd.advanced.tests.powerdns.com.", SetDisableValidationAction())
    newServer{address="127.0.0.1:%d"}
    """

    def testAdvancedSetCD(self):
        """
        Advanced: Set CD

        Send a query with CD cleared,
        check that dnsdist set the CD flag.
        """
        name = 'setcd.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN')
        expectedQuery.flags |= dns.flags.CD

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.assertEqual(expectedQuery, receivedQuery)
            self.assertEqual(response, receivedResponse)

    def testAdvancedKeepNoCD(self):
        """
        Advanced: Preserve CD canary

        Send a query without CD for a canary domain,
        check that dnsdist does not set the CD flag.
        """
        name = 'keepnocd.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

class TestAdvancedClearRD(DNSDistTest):

    _config_template = """
    addAction("clearrd.advanced.tests.powerdns.com.", SetNoRecurseAction())
    newServer{address="127.0.0.1:%d"}
    """

    def testAdvancedClearRD(self):
        """
        Advanced: Clear RD

        Send a query with RD set,
        check that dnsdist clears the RD flag.
        """
        name = 'clearrd.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN')
        expectedQuery.flags &= ~dns.flags.RD

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.assertEqual(expectedQuery, receivedQuery)
            self.assertEqual(response, receivedResponse)

    def testAdvancedKeepRD(self):
        """
        Advanced: Preserve RD canary

        Send a query with RD for a canary domain,
        check that dnsdist does not clear the RD flag.
        """
        name = 'keeprd.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)


class TestAdvancedDelay(DNSDistTest):

    _config_template = """
    addAction(AllRule(), DelayAction(1000))
    newServer{address="127.0.0.1:%d"}
    """

    def testDelayed(self):
        """
        Advanced: Delayed

        Send an A query to "tests.powerdns.com.",
        check that the response delay is longer than 1000 ms
        over UDP, less than that over TCP.
        """
        name = 'tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        begin = datetime.now()
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        end = datetime.now()
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.assertGreater(end - begin, timedelta(0, 1))

        begin = datetime.now()
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        end = datetime.now()
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.assertLess(end - begin, timedelta(0, 1))

class TestAdvancedAndNot(DNSDistTest):

    _config_template = """
    addAction(AndRule({NotRule(QTypeRule("A")), TCPRule(false)}), RCodeAction(DNSRCode.NOTIMP))
    newServer{address="127.0.0.1:%d"}
    """
    def testAOverUDPReturnsNotImplementedCanary(self):
        """
        Advanced: !A && UDP canary

        dnsdist is configured to reply 'not implemented' for query
        over UDP AND !qtype A.
        We send an A query over UDP and TCP, and check that the
        response is OK.
        """
        name = 'andnot.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)

    def testAOverUDPReturnsNotImplemented(self):
        """
        Advanced: !A && UDP

        dnsdist is configured to reply 'not implemented' for query
        over UDP AND !qtype A.
        We send a TXT query over UDP and TCP, and check that the
        response is OK for TCP and 'not implemented' for UDP.
        """
        name = 'andnot.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'TXT', 'IN')
        # dnsdist sets RA = RD for TC responses
        query.flags &= ~dns.flags.RD

        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.NOTIMP)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.TXT,
                                    'nothing to see here')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

class TestAdvancedOr(DNSDistTest):

    _config_template = """
    addAction(OrRule({QTypeRule("A"), TCPRule(false)}), RCodeAction(DNSRCode.NOTIMP))
    newServer{address="127.0.0.1:%d"}
    """
    def testAAAAOverUDPReturnsNotImplemented(self):
        """
        Advanced: A || UDP: AAAA

        dnsdist is configured to reply 'not implemented' for query
        over UDP OR qtype A.
        We send an AAAA query over UDP and TCP, and check that the
        response is 'not implemented' for UDP and OK for TCP.
        """
        name = 'aorudp.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.NOTIMP)

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, expectedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

    def testAOverUDPReturnsNotImplemented(self):
        """
        Advanced: A || UDP: A

        dnsdist is configured to reply 'not implemented' for query
        over UDP OR qtype A.
        We send an A query over UDP and TCP, and check that the
        response is 'not implemented' for both.
        """
        name = 'aorudp.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD

        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.NOTIMP)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)


class TestAdvancedLogAction(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%d"}
    addAction(AllRule(), LogAction("dnsdist.log", false))
    """
    def testAdvancedLogAction(self):
        """
        Advanced: Log all queries

        """
        count = 50
        name = 'logaction.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for _ in range(count):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        self.assertTrue(os.path.isfile('dnsdist.log'))
        self.assertGreater(os.stat('dnsdist.log').st_size, 0)

class TestAdvancedDNSSEC(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%d"}
    addAction(DNSSECRule(), DropAction())
    """
    def testAdvancedDNSSECDrop(self):
        """
        Advanced: DNSSEC Rule

        """
        name = 'dnssec.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        doquery = dns.message.make_query(name, 'A', 'IN', want_dnssec=True)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(doquery, response=None, useQueue=False)
            self.assertEqual(receivedResponse, None)

class TestAdvancedQClass(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%d"}
    addAction(QClassRule(DNSClass.CHAOS), DropAction())
    """
    def testAdvancedQClassChaosDrop(self):
        """
        Advanced: Drop QClass CHAOS

        """
        name = 'qclasschaos.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'TXT', 'CHAOS')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, None)

    def testAdvancedQClassINAllow(self):
        """
        Advanced: Allow QClass IN

        """
        name = 'qclassin.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

class TestAdvancedOpcode(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%d"}
    addAction(OpcodeRule(DNSOpcode.Notify), DropAction())
    """
    def testAdvancedOpcodeNotifyDrop(self):
        """
        Advanced: Drop Opcode NOTIFY

        """
        name = 'opcodenotify.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.set_opcode(dns.opcode.NOTIFY)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, None)

    def testAdvancedOpcodeUpdateINAllow(self):
        """
        Advanced: Allow Opcode UPDATE

        """
        name = 'opcodeupdate.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'SOA', 'IN')
        query.set_opcode(dns.opcode.UPDATE)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

class TestAdvancedNonTerminalRule(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%d", pool="real"}
    addAction(AllRule(), SetDisableValidationAction())
    addAction(AllRule(), PoolAction("real"))
    addAction(AllRule(), DropAction())
    """
    def testAdvancedNonTerminalRules(self):
        """
        Advanced: Non terminal rules

        We check that SetDisableValidationAction() is applied
        but does not stop the processing, then that
        PoolAction() is applied _and_ stop the processing.
        """
        name = 'nonterminal.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN')
        expectedQuery.flags |= dns.flags.CD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.assertEqual(expectedQuery, receivedQuery)
            self.assertEqual(response, receivedResponse)

class TestAdvancedRestoreFlagsOnSelfResponse(DNSDistTest):

    _config_template = """
    addAction(AllRule(), SetDisableValidationAction())
    addAction(AllRule(), SpoofAction("192.0.2.1"))
    newServer{address="127.0.0.1:%d"}
    """

    def testAdvancedRestoreFlagsOnSpoofResponse(self):
        """
        Advanced: Restore flags on spoofed response

        Send a query with CD flag cleared, dnsdist is
        instructed to set it, then to spoof the response,
        check that response has the flag cleared.
        """
        name = 'spoofed.restoreflags.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(response, receivedResponse)

class TestAdvancedQPS(DNSDistTest):

    _config_template = """
    addAction("qps.advanced.tests.powerdns.com", QPSAction(10))
    newServer{address="127.0.0.1:%d"}
    """

    def testAdvancedQPSLimit(self):
        """
        Advanced: QPS Limit

        Send queries to "qps.advanced.tests.powerdns.com."
        check that dnsdist drops queries when the max QPS has been reached.
        """
        maxQPS = 10
        name = 'qps.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for _ in range(maxQPS):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        # we should now be dropped
        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)

        time.sleep(1)

        # again, over TCP this time
        for _ in range(maxQPS):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)


        (_, receivedResponse) = self.sendTCPQuery(query, response=None, useQueue=False)
        self.assertEqual(receivedResponse, None)

class TestAdvancedQPSNone(DNSDistTest):

    _config_template = """
    addAction("qpsnone.advanced.tests.powerdns.com", QPSAction(100))
    addAction(AllRule(), RCodeAction(DNSRCode.REFUSED))
    newServer{address="127.0.0.1:%d"}
    """

    def testAdvancedQPSNone(self):
        """
        Advanced: Not matching QPS returns None, not Allow

        Send queries to "qps.advanced.tests.powerdns.com."
        check that the rule returns None when the QPS has not been
        reached, not Allow.
        """
        name = 'qpsnone.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

class TestAdvancedNMGRule(DNSDistTest):

    _config_template = """
    allowed = newNMG()
    allowed:addMask("192.0.2.1/32")
    addAction(NotRule(NetmaskGroupRule(allowed)), RCodeAction(DNSRCode.REFUSED))
    newServer{address="127.0.0.1:%d"}
    """

    def testAdvancedNMGRule(self):
        """
        Advanced: NMGRule should refuse our queries

        Send queries to "nmgrule.advanced.tests.powerdns.com.",
        check that we are getting a REFUSED response.
        """
        name = 'nmgrule.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

class TestAdvancedNMGAddNMG(DNSDistTest):
    _config_template = """
    oneNMG = newNMG()
    anotherNMG = newNMG()
    anotherNMG:addMask('127.0.0.1/32')
    oneNMG:addNMG(anotherNMG)
    addAction(NotRule(NetmaskGroupRule(oneNMG)), DropAction())
    addAction(AllRule(), SpoofAction('192.0.2.1'))
    newServer{address="127.0.0.1:%d"}
    """

    def testAdvancedNMGRuleAddNMG(self):
        """
        Advanced: NMGRule:addNMG()
        """
        name = 'nmgrule-addnmg.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_,receivedResponse) = sender(query, response=expectedResponse, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

class TestAdvancedNMGRuleFromString(DNSDistTest):

    _config_template = """
    addAction(NotRule(NetmaskGroupRule('192.0.2.1')), RCodeAction(DNSRCode.REFUSED))
    newServer{address="127.0.0.1:%d"}
    """

    def testAdvancedNMGRule(self):
        """
        Advanced: NMGRule (from string) should refuse our queries
        """
        name = 'nmgrule-from-string.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

class TestAdvancedNMGRuleFromMultipleStrings(DNSDistTest):

    _config_template = """
    addAction(NotRule(NetmaskGroupRule({'192.0.2.1', '192.0.2.128/25'})), RCodeAction(DNSRCode.REFUSED))
    newServer{address="127.0.0.1:%d"}
    """

    def testAdvancedNMGRule(self):
        """
        Advanced: NMGRule (from multiple strings) should refuse our queries
        """
        name = 'nmgrule-from-multiple-strings.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

class TestDSTPortRule(DNSDistTest):

    _config_params = ['_dnsDistPort', '_testServerPort']
    _config_template = """
    addAction(DSTPortRule(%d), RCodeAction(DNSRCode.REFUSED))
    newServer{address="127.0.0.1:%d"}
    """

    def testDSTPortRule(self):
        """
        Advanced: DSTPortRule should capture our queries

        Send queries to "dstportrule.advanced.tests.powerdns.com.",
        check that we are getting a REFUSED response.
        """

        name = 'dstportrule.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

class TestAdvancedLabelsCountRule(DNSDistTest):

    _config_template = """
    addAction(QNameLabelsCountRule(5,6), RCodeAction(DNSRCode.REFUSED))
    newServer{address="127.0.0.1:%d"}
    """

    def testAdvancedLabelsCountRule(self):
        """
        Advanced: QNameLabelsCountRule(5,6)
        """
        # 6 labels, we should be fine
        name = 'ok.labelscount.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        # more than 6 labels, the query should be refused
        name = 'not.ok.labelscount.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

        # less than 5 labels, the query should be refused
        name = 'labelscountadvanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

class TestAdvancedWireLengthRule(DNSDistTest):

    _config_template = """
    addAction(QNameWireLengthRule(54,56), RCodeAction(DNSRCode.REFUSED))
    newServer{address="127.0.0.1:%d"}
    """

    def testAdvancedWireLengthRule(self):
        """
        Advanced: QNameWireLengthRule(54,56)
        """
        name = 'longenough.qnamewirelength.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        # too short, the query should be refused
        name = 'short.qnamewirelength.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

        # too long, the query should be refused
        name = 'toolongtobevalid.qnamewirelength.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

class TestAdvancedLuaDO(DNSDistTest):

    _config_template = """
    function nxDOLua(dq)
        if dq:getDO() then
            return DNSAction.Nxdomain, ""
        end
        return DNSAction.None, ""
    end
    addAction(AllRule(), LuaAction(nxDOLua))
    newServer{address="127.0.0.1:%d"}
    """

    def testNxDOViaLua(self):
        """
        Advanced: Nx DO queries via Lua
        """
        name = 'nxdo.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)
        queryWithDO = dns.message.make_query(name, 'A', 'IN', want_dnssec=True)
        doResponse = dns.message.make_response(queryWithDO)
        doResponse.set_rcode(dns.rcode.NXDOMAIN)

        # without DO
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)

        # with DO
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(queryWithDO, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            doResponse.id = receivedResponse.id
            self.assertEqual(receivedResponse, doResponse)

class TestAdvancedLuaRefused(DNSDistTest):

    _config_template = """
    function refuse(dq)
        return DNSAction.Refused, ""
    end
    addAction(AllRule(), LuaAction(refuse))
    newServer{address="127.0.0.1:%d"}
    """

    def testRefusedViaLua(self):
        """
        Advanced: Refused via Lua
        """
        name = 'refused.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)
        refusedResponse = dns.message.make_response(query)
        refusedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            refusedResponse.id = receivedResponse.id
            self.assertEqual(receivedResponse, refusedResponse)

class TestAdvancedLuaActionReturnSyntax(DNSDistTest):

    _config_template = """
    function refuse(dq)
        return DNSAction.Refused
    end
    addAction(AllRule(), LuaAction(refuse))
    newServer{address="127.0.0.1:%d"}
    """

    def testRefusedWithEmptyRule(self):
        """
        Advanced: Short syntax for LuaAction return values
        """
        name = 'short.refused.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)
        refusedResponse = dns.message.make_response(query)
        refusedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            refusedResponse.id = receivedResponse.id
            self.assertEqual(receivedResponse, refusedResponse)

class TestAdvancedLuaTruncated(DNSDistTest):

    _config_template = """
    function trunc(dq)
        if not dq.tcp then
          return DNSAction.Truncate, ""
        end
        return DNSAction.None, ""
    end
    addAction(AllRule(), LuaAction(trunc))
    newServer{address="127.0.0.1:%d"}
    """

    def testTCViaLua(self):
        """
        Advanced: TC via Lua
        """
        name = 'tc.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist sets RA = RD for TC responses
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        truncatedResponse = dns.message.make_response(query)
        truncatedResponse.flags |= dns.flags.TC

        (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
        self.assertTrue(receivedResponse)
        truncatedResponse.id = receivedResponse.id
        self.assertEqual(receivedResponse, truncatedResponse)

        # no truncation over TCP
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

class TestAdvancedRD(DNSDistTest):

    _config_template = """
    addAction(RDRule(), RCodeAction(DNSRCode.REFUSED))
    newServer{address="127.0.0.1:%d"}
    """

    def testAdvancedRDRefused(self):
        """
        Advanced: RD query is refused
        """
        name = 'rd.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)
        expectedResponse.flags |= dns.flags.RA

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

    def testAdvancedNoRDAllowed(self):
        """
        Advanced: No-RD query is allowed
        """
        name = 'no-rd.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        response = dns.message.make_response(query)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(receivedQuery, query)
            self.assertEqual(receivedResponse, response)

class TestAdvancedLuaTempFailureTTL(DNSDistTest):

    _config_template = """
    function testAction(dq)
      if dq.tempFailureTTL ~= nil then
        return DNSAction.Spoof, "initially.not.nil.but." + dq.tempFailureTTL + ".tests.powerdns.com."
      end
      dq.tempFailureTTL = 30
      if dq.tempFailureTTL ~= 30 then
        return DNSAction.Spoof, "after.set.not.expected.value.but." + dq.tempFailureTTL + ".tests.powerdns.com."
      end
      dq.tempFailureTTL = nil
      if dq.tempFailureTTL ~= nil then
        return DNSAction.Spoof, "after.unset.not.nil.but." + dq.tempFailureTTL + ".tests.powerdns.com."
      end
      return DNSAction.None, ""
    end
    addAction(AllRule(), LuaAction(testAction))
    newServer{address="127.0.0.1:%d"}
    """

    def testTempFailureTTLBinding(self):
        """
        Advanced: Exercise dq.tempFailureTTL Lua binding
        """
        name = 'tempfailurettlbinding.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)

class TestAdvancedEDNSOptionRule(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%d"}
    addAction(EDNSOptionRule(EDNSOptionCode.ECS), DropAction())
    """

    def testDropped(self):
        """
        Advanced: A question with ECS is dropped
        """

        name = 'ednsoptionrule.advanced.tests.powerdns.com.'

        ecso = clientsubnetoption.ClientSubnetOption('127.0.0.1', 24)
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, options=[ecso], payload=512)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, None)

    def testReplied(self):
        """
        Advanced: A question without ECS is answered
        """

        name = 'ednsoptionrule.advanced.tests.powerdns.com.'

        # both with EDNS
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, options=[], payload=512)
        response = dns.message.make_response(query)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)

            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)

        # and with no EDNS at all
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        response = dns.message.make_response(query)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)

            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)

class TestAdvancedEDNSVersionRule(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%d"}
    addAction(EDNSVersionRule(0), ERCodeAction(DNSRCode.BADVERS))
    """

    def testBadVers(self):
        """
        Advanced: A question with ECS version larger than 0 yields BADVERS
        """

        if sys.version_info >= (3, 11) and sys.version_info < (3, 12):
            raise unittest.SkipTest("Test skipped, see https://github.com/PowerDNS/pdns/pull/12912")

        name = 'ednsversionrule.advanced.tests.powerdns.com.'

        query = dns.message.make_query(name, 'A', 'IN', use_edns=1)
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.BADVERS)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, expectedResponse)

    def testNoEDNS0Pass(self):
        """
        Advanced: A question with ECS version 0 goes through
        """

        name = 'ednsversionrule.advanced.tests.powerdns.com.'

        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        response = dns.message.make_response(query)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)

    def testReplied(self):
        """
        Advanced: A question without ECS goes through
        """

        name = 'ednsoptionrule.advanced.tests.powerdns.com.'

        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        response = dns.message.make_response(query)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)

class TestSetRules(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}
    addAction(AllRule(), SpoofAction("192.0.2.1"))
    """

    def testClearThenSetRules(self):
        """
        Advanced: Clear rules, set rules

        """
        name = 'clearthensetrules.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)

            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # clear all the rules, we should not be spoofing and get a SERVFAIL from the responder instead
        self.sendConsoleCommand("clearRules()")

        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.SERVFAIL)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)

            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # insert a new spoofing rule
        self.sendConsoleCommand("setRules({ newRuleAction(AllRule(), SpoofAction(\"192.0.2.2\")) })")

        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.2')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)

            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

class TestRmRules(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}
    addAction(AllRule(), SpoofAction("192.0.2.1"), {name='myFirstRule', uuid='090736ca-2fb6-41e7-a836-58efaca3d71e'})
    addAction(AllRule(), SpoofAction("192.0.2.1"), {name='mySecondRule'})
    addResponseAction(AllRule(), AllowResponseAction(), {name='myFirstResponseRule', uuid='745a03b5-89e0-4eee-a6bf-c9700b0d31f0'})
    addResponseAction(AllRule(), AllowResponseAction(), {name='mySecondResponseRule'})
    """

    def testRmRules(self):
        """
        Advanced: Remove rules
        """
        lines = self.sendConsoleCommand("showRules({showUUIDs=true})").splitlines()
        self.assertEqual(len(lines), 3)
        self.assertIn('myFirstRule', lines[1])
        self.assertIn('mySecondRule', lines[2])
        self.assertIn('090736ca-2fb6-41e7-a836-58efaca3d71e', lines[1])

        lines = self.sendConsoleCommand("showResponseRules({showUUIDs=true})").splitlines()
        self.assertEqual(len(lines), 3)
        self.assertIn('myFirstResponseRule', lines[1])
        self.assertIn('mySecondResponseRule', lines[2])
        self.assertIn('745a03b5-89e0-4eee-a6bf-c9700b0d31f0', lines[1])

        self.sendConsoleCommand("rmRule('090736ca-2fb6-41e7-a836-58efaca3d71e')")
        self.sendConsoleCommand("rmRule('mySecondRule')")
        lines = self.sendConsoleCommand("showRules({showUUIDs=true})").splitlines()
        self.assertEqual(len(lines), 1)

        self.sendConsoleCommand("rmResponseRule('745a03b5-89e0-4eee-a6bf-c9700b0d31f0')")
        self.sendConsoleCommand("rmResponseRule('mySecondResponseRule')")
        lines = self.sendConsoleCommand("showResponseRules({showUUIDs=true})").splitlines()
        self.assertEqual(len(lines), 1)

class TestAdvancedContinueAction(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%d", pool="mypool"}
    addAction("nocontinue.continue-action.advanced.tests.powerdns.com.", PoolAction("mypool"))
    addAction("continue.continue-action.advanced.tests.powerdns.com.", ContinueAction(PoolAction("mypool")))
    addAction(AllRule(), SetDisableValidationAction())
    """

    def testNoContinue(self):
        """
        Advanced: Query routed to pool, PoolAction should be terminal
        """

        name = 'nocontinue.continue-action.advanced.tests.powerdns.com.'

        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN')

        response = dns.message.make_response(query)
        expectedResponse = dns.message.make_response(query)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            expectedQuery.id = receivedQuery.id
            self.assertEqual(receivedQuery, expectedQuery)
            self.assertEqual(receivedResponse, expectedResponse)

    def testContinue(self):
        """
        Advanced: Query routed to pool, ContinueAction() should not stop the processing
        """

        name = 'continue.continue-action.advanced.tests.powerdns.com.'

        query = dns.message.make_query(name, 'A', 'IN')
        expectedQuery = dns.message.make_query(name, 'A', 'IN')
        expectedQuery.flags |= dns.flags.CD

        response = dns.message.make_response(query)
        expectedResponse = dns.message.make_response(query)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            expectedQuery.id = receivedQuery.id
            self.assertEqual(receivedQuery, expectedQuery)
            self.assertEqual(receivedResponse, expectedResponse)

class TestAdvancedNegativeAndSOA(DNSDistTest):

    _selfGeneratedPayloadSize = 1232
    _config_template = """
    addAction("nxd.negativeandsoa.advanced.tests.powerdns.com.", NegativeAndSOAAction(true, "auth.", 42, "mname", "rname", 5, 4, 3, 2, 1))
    addAction("nodata.negativeandsoa.advanced.tests.powerdns.com.", NegativeAndSOAAction(false, "another-auth.", 42, "mname", "rname", 1, 2, 3, 4, 5))
    setPayloadSizeOnSelfGeneratedAnswers(%d)
    newServer{address="127.0.0.1:%d"}
    """
    _config_params = ['_selfGeneratedPayloadSize', '_testServerPort']


    def testAdvancedNegativeAndSOANXD(self):
        """
        Advanced: NegativeAndSOAAction NXD
        """
        name = 'nxd.negativeandsoa.advanced.tests.powerdns.com.'
        # no EDNS
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.NXDOMAIN)
        soa = dns.rrset.from_text("auth.",
                                  42,
                                  dns.rdataclass.IN,
                                  dns.rdatatype.SOA,
                                  'mname. rname. 5 4 3 2 1')
        expectedResponse.additional.append(soa)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)

        # withEDNS
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query, our_payload=self._selfGeneratedPayloadSize)
        expectedResponse.set_rcode(dns.rcode.NXDOMAIN)
        soa = dns.rrset.from_text("auth.",
                                  42,
                                  dns.rdataclass.IN,
                                  dns.rdatatype.SOA,
                                  'mname. rname. 5 4 3 2 1')
        expectedResponse.additional.append(soa)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageEDNSWithoutOptions(expectedResponse, receivedResponse)

    def testAdvancedNegativeAndSOANoData(self):
        """
        Advanced: NegativeAndSOAAction NoData
        """
        name = 'nodata.negativeandsoa.advanced.tests.powerdns.com.'
        # no EDNS
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.NOERROR)
        soa = dns.rrset.from_text("another-auth.",
                                  42,
                                  dns.rdataclass.IN,
                                  dns.rdatatype.SOA,
                                  'mname. rname. 1 2 3 4 5')
        expectedResponse.additional.append(soa)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)

        # with EDNS
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query, our_payload=self._selfGeneratedPayloadSize)
        expectedResponse.set_rcode(dns.rcode.NOERROR)
        soa = dns.rrset.from_text("another-auth.",
                                  42,
                                  dns.rdataclass.IN,
                                  dns.rdatatype.SOA,
                                  'mname. rname. 1 2 3 4 5')
        expectedResponse.additional.append(soa)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageEDNSWithoutOptions(expectedResponse, receivedResponse)


class TestAdvancedNegativeAndSOAAuthSection(DNSDistTest):

    _selfGeneratedPayloadSize = 1232
    _config_template = """
    addAction("nxd.negativeandsoa.advanced.tests.powerdns.com.", NegativeAndSOAAction(true, "auth.", 42, "mname", "rname", 5, 4, 3, 2, 1, { soaInAuthoritySection=true }))
    addAction("nodata.negativeandsoa.advanced.tests.powerdns.com.", NegativeAndSOAAction(false, "another-auth.", 42, "mname", "rname", 1, 2, 3, 4, 5, { soaInAuthoritySection=true }))
    setPayloadSizeOnSelfGeneratedAnswers(%d)
    newServer{address="127.0.0.1:%d"}
    """
    _config_params = ['_selfGeneratedPayloadSize', '_testServerPort']


    def testAdvancedNegativeAndSOANXD(self):
        """
        Advanced: NegativeAndSOAAction NXD
        """
        name = 'nxd.negativeandsoa.advanced.tests.powerdns.com.'
        # no EDNS
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.NXDOMAIN)
        soa = dns.rrset.from_text("auth.",
                                  42,
                                  dns.rdataclass.IN,
                                  dns.rdatatype.SOA,
                                  'mname. rname. 5 4 3 2 1')
        expectedResponse.authority.append(soa)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)

        # withEDNS
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query, our_payload=self._selfGeneratedPayloadSize)
        expectedResponse.set_rcode(dns.rcode.NXDOMAIN)
        soa = dns.rrset.from_text("auth.",
                                  42,
                                  dns.rdataclass.IN,
                                  dns.rdatatype.SOA,
                                  'mname. rname. 5 4 3 2 1')
        expectedResponse.authority.append(soa)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageEDNSWithoutOptions(expectedResponse, receivedResponse)

    def testAdvancedNegativeAndSOANoData(self):
        """
        Advanced: NegativeAndSOAAction NoData
        """
        name = 'nodata.negativeandsoa.advanced.tests.powerdns.com.'
        # no EDNS
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.NOERROR)
        soa = dns.rrset.from_text("another-auth.",
                                  42,
                                  dns.rdataclass.IN,
                                  dns.rdatatype.SOA,
                                  'mname. rname. 1 2 3 4 5')
        expectedResponse.authority.append(soa)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)

        # with EDNS
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query, our_payload=self._selfGeneratedPayloadSize)
        expectedResponse.set_rcode(dns.rcode.NOERROR)
        soa = dns.rrset.from_text("another-auth.",
                                  42,
                                  dns.rdataclass.IN,
                                  dns.rdatatype.SOA,
                                  'mname. rname. 1 2 3 4 5')
        expectedResponse.authority.append(soa)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageEDNSWithoutOptions(expectedResponse, receivedResponse)


class TestAdvancedLuaRule(DNSDistTest):

    _config_template = """

    function luarulefunction(dq)
      if dq:getTag('a-tag') ~= 'a-value' then
        print('invalid tag value')
        return false
      end

      if tostring(dq.qname) ~= 'lua-rule.advanced.tests.powerdns.com.' then
        print('invalid qname')
        return false
      end

      return true
    end

    addAction(AllRule(), SetTagAction('a-tag', 'a-value'))
    addAction(LuaRule(luarulefunction), RCodeAction(DNSRCode.NOTIMP))
    addAction(AllRule(), RCodeAction(DNSRCode.REFUSED))
    -- newServer{address="127.0.0.1:%d"}
    """

    def testAdvancedLuaRule(self):
        """
        Advanced: Test the LuaRule rule
        """
        name = 'lua-rule.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        notimplResponse = dns.message.make_response(query)
        notimplResponse.set_rcode(dns.rcode.NOTIMP)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, notimplResponse)

        name = 'not-lua-rule.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        refusedResponse = dns.message.make_response(query)
        refusedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, refusedResponse)

class TestAdvancedSetEDNSOptionAction(DNSDistTest):

    _config_template = """
    addAction(AllRule(), SetEDNSOptionAction(10, "deadbeefdeadc0de"))
    newServer{address="127.0.0.1:%d"}
    """

    def testAdvancedSetEDNSOption(self):
        """
        Advanced: Set EDNS Option
        """
        name = 'setednsoption.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        eco = cookiesoption.CookiesOption(b'deadbeef', b'deadc0de')
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=512, options=[eco])

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.assertEqual(expectedQuery, receivedQuery)
            self.checkResponseNoEDNS(response, receivedResponse)
            self.checkQueryEDNS(expectedQuery, receivedQuery)

    def testAdvancedSetEDNSOptionOverwrite(self):
        """
        Advanced: Set EDNS Option overwrites an existing option
        """
        name = 'setednsoption-overwrite.advanced.tests.powerdns.com.'
        initialECO = cookiesoption.CookiesOption(b'aaaaaaaa', b'bbbbbbbb')
        query = dns.message.make_query(name, 'A', 'IN')

        overWrittenECO = cookiesoption.CookiesOption(b'deadbeef', b'deadc0de')
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=512, options=[overWrittenECO])

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.assertEqual(expectedQuery, receivedQuery)
            self.checkResponseNoEDNS(response, receivedResponse)
            self.checkQueryEDNS(expectedQuery, receivedQuery)

    def testAdvancedSetEDNSOptionWithDOSet(self):
        """
        Advanced: Set EDNS Option (DO bit set)
        """
        # check that the DO bit is correctly handled, as we messed that up once
        name = 'setednsoption-do.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, want_dnssec=True, payload=4096)

        eco = cookiesoption.CookiesOption(b'deadbeef', b'deadc0de')
        expectedQuery = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[eco], want_dnssec=True)

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = expectedQuery.id
            self.assertEqual(expectedQuery, receivedQuery)
            self.checkResponseEDNSWithoutECS(response, receivedResponse)
            self.checkQueryEDNS(expectedQuery, receivedQuery)

class TestAdvancedLuaGetContent(DNSDistTest):

    _config_template = """
    function accessContentLua(dq)
        local expectedSize = 57
        local content = dq:getContent()
        if content == nil or #content == 0 then
            errlog('No content')
            return DNSAction.Nxdomain, ""
        end
        if #content ~= expectedSize then
            errlog('Invalid content size'..#content)
            return DNSAction.Nxdomain, ""
        end
        -- the qname is right after the header, and we have only the qtype and qclass after that
        local qname = string.sub(content, 13, -5)
        local expectedQName = '\\011get-content\\008advanced\\005tests\\008powerdns\\003com\\000'
        if qname ~= expectedQName then
            errlog('Invalid qname '..qname..', expecting '..expectedQName)
            return DNSAction.Nxdomain, ""
        end
        return DNSAction.None, ""
    end
    addAction(AllRule(), LuaAction(accessContentLua))
    newServer{address="127.0.0.1:%d"}
    """

    def testGetContentViaLua(self):
        """
        Advanced: Test getContent() via Lua
        """
        name = 'get-content.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'AAAA', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)
