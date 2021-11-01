#!/usr/bin/env python
import base64
from datetime import datetime, timedelta
import os
import shutil
import string
import time
import dns
import clientsubnetoption
import cookiesoption
from dnsdisttests import DNSDistTest

class TestAdvancedAllow(DNSDistTest):

    _config_template = """
    addAction(AllRule(), NoneAction())
    addAction(makeRule("allowed.advanced.tests.powerdns.com."), AllowAction())
    addAction(AllRule(), DropAction())
    newServer{address="127.0.0.1:%s"}
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

class TestAdvancedFixupCase(DNSDistTest):

    _config_template = """
    truncateTC(true)
    fixupCase(true)
    newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedFixupCase(self):
        """
        Advanced: Fixup Case

        Send a query with lower and upper chars,
        make the backend return a lowercase version,
        check that dnsdist fixes the response.
        """
        name = 'fiXuPCasE.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        lowercasequery = dns.message.make_query(name.lower(), 'A', 'IN')
        response = dns.message.make_response(lowercasequery)
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(expectedResponse, receivedResponse)

class TestAdvancedRemoveRD(DNSDistTest):

    _config_template = """
    addAction("norecurse.advanced.tests.powerdns.com.", SetNoRecurseAction())
    newServer{address="127.0.0.1:%s"}
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
    newServer{address="127.0.0.1:%s"}
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
    newServer{address="127.0.0.1:%s"}
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


class TestAdvancedACL(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
    """
    _acl = ['192.0.2.1/32']

    def testACLBlocked(self):
        """
        Advanced: ACL blocked

        Send an A query to "tests.powerdns.com.",
        we expect no response since 127.0.0.1 is not on the
        ACL.
        """
        name = 'tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, None)

class TestAdvancedDelay(DNSDistTest):

    _config_template = """
    addAction(AllRule(), DelayAction(1000))
    newServer{address="127.0.0.1:%s"}
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
        self.assertTrue((end - begin) > timedelta(0, 1))

        begin = datetime.now()
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        end = datetime.now()
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)
        self.assertTrue((end - begin) < timedelta(0, 1))

class TestAdvancedAndNot(DNSDistTest):

    _config_template = """
    addAction(AndRule({NotRule(QTypeRule("A")), TCPRule(false)}), RCodeAction(DNSRCode.NOTIMP))
    newServer{address="127.0.0.1:%s"}
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
    newServer{address="127.0.0.1:%s"}
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
    newServer{address="127.0.0.1:%s"}
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
        self.assertTrue(os.stat('dnsdist.log').st_size > 0)

class TestAdvancedDNSSEC(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
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
    newServer{address="127.0.0.1:%s"}
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
    newServer{address="127.0.0.1:%s"}
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
    newServer{address="127.0.0.1:%s", pool="real"}
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

class TestAdvancedStringOnlyServer(DNSDistTest):

    _config_template = """
    newServer("127.0.0.1:%s")
    """

    def testAdvancedStringOnlyServer(self):
        """
        Advanced: "string-only" server is placed in the default pool
        """
        name = 'string-only-server.advanced.tests.powerdns.com.'
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

class TestAdvancedRestoreFlagsOnSelfResponse(DNSDistTest):

    _config_template = """
    addAction(AllRule(), SetDisableValidationAction())
    addAction(AllRule(), SpoofAction("192.0.2.1"))
    newServer{address="127.0.0.1:%s"}
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
    newServer{address="127.0.0.1:%s"}
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
    newServer{address="127.0.0.1:%s"}
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
    newServer{address="127.0.0.1:%s"}
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

class TestDSTPortRule(DNSDistTest):

    _config_params = ['_dnsDistPort', '_testServerPort']
    _config_template = """
    addAction(DSTPortRule(%d), RCodeAction(DNSRCode.REFUSED))
    newServer{address="127.0.0.1:%s"}
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
    newServer{address="127.0.0.1:%s"}
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
    newServer{address="127.0.0.1:%s"}
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

class TestAdvancedIncludeDir(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")
    -- this directory contains a file allowing includedir.advanced.tests.powerdns.com.
    includeDirectory('test-include-dir')
    newServer{address="127.0.0.1:%s"}
    """
    _verboseMode = True

    def testAdvancedIncludeDirAllowed(self):
        """
        Advanced: includeDirectory()
        """

        print(shutil.disk_usage('.'))
        print(shutil.disk_usage('/'))
        print(shutil.disk_usage('/tmp'))
        print(shutil.disk_usage('/run'))
        print(shutil.disk_usage('/var'))

        name = 'includedir.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            print("includedir " + method)
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            print(receivedResponse)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        # this one should be refused
        name = 'notincludedir.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            print("notincludedir " + method)
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            print(receivedResponse)
            print(self.sendConsoleCommand('grepq("")'))
            print(self.sendConsoleCommand('showRules()'))
            print(self.sendConsoleCommand('showBinds()'))
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
    newServer{address="127.0.0.1:%s"}
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
    newServer{address="127.0.0.1:%s"}
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
    newServer{address="127.0.0.1:%s"}
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
    newServer{address="127.0.0.1:%s"}
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

class TestStatNodeRespRingSince(DNSDistTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")
    s1 = newServer{address="127.0.0.1:%s"}
    s1:setUp()
    function visitor(node, self, childstat)
        table.insert(nodesSeen, node.fullname)
    end
    """

    def testStatNodeRespRingSince(self):
        """
        Advanced: StatNodeRespRing with optional since parameter

        """
        name = 'statnodesince.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    1,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(response, receivedResponse)

        self.sendConsoleCommand("nodesSeen = {}")
        self.sendConsoleCommand("statNodeRespRing(visitor)")
        nodes = self.sendConsoleCommand("str = '' for key,value in pairs(nodesSeen) do str = str..value..\"\\n\" end return str")
        nodes = nodes.strip("\n")
        self.assertEqual(nodes, """statnodesince.advanced.tests.powerdns.com.
advanced.tests.powerdns.com.
tests.powerdns.com.
powerdns.com.
com.""")

        self.sendConsoleCommand("nodesSeen = {}")
        self.sendConsoleCommand("statNodeRespRing(visitor, 0)")
        nodes = self.sendConsoleCommand("str = '' for key,value in pairs(nodesSeen) do str = str..value..\"\\n\" end return str")
        nodes = nodes.strip("\n")
        self.assertEqual(nodes, """statnodesince.advanced.tests.powerdns.com.
advanced.tests.powerdns.com.
tests.powerdns.com.
powerdns.com.
com.""")

        time.sleep(5)

        self.sendConsoleCommand("nodesSeen = {}")
        self.sendConsoleCommand("statNodeRespRing(visitor)")
        nodes = self.sendConsoleCommand("str = '' for key,value in pairs(nodesSeen) do str = str..value..\"\\n\" end return str")
        nodes = nodes.strip("\n")
        self.assertEqual(nodes, """statnodesince.advanced.tests.powerdns.com.
advanced.tests.powerdns.com.
tests.powerdns.com.
powerdns.com.
com.""")

        self.sendConsoleCommand("nodesSeen = {}")
        self.sendConsoleCommand("statNodeRespRing(visitor, 5)")
        nodes = self.sendConsoleCommand("str = '' for key,value in pairs(nodesSeen) do str = str..value..\"\\n\" end return str")
        nodes = nodes.strip("\n")
        self.assertEqual(nodes, """""")

        self.sendConsoleCommand("nodesSeen = {}")
        self.sendConsoleCommand("statNodeRespRing(visitor, 10)")
        nodes = self.sendConsoleCommand("str = '' for key,value in pairs(nodesSeen) do str = str..value..\"\\n\" end return str")
        nodes = nodes.strip("\n")
        self.assertEqual(nodes, """statnodesince.advanced.tests.powerdns.com.
advanced.tests.powerdns.com.
tests.powerdns.com.
powerdns.com.
com.""")

class TestAdvancedRD(DNSDistTest):

    _config_template = """
    addAction(RDRule(), RCodeAction(DNSRCode.REFUSED))
    newServer{address="127.0.0.1:%s"}
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

class TestAdvancedGetLocalPort(DNSDistTest):

    _config_template = """
    function answerBasedOnLocalPort(dq)
      local port = dq.localaddr:getPort()
      return DNSAction.Spoof, "port-was-"..port..".local-port.advanced.tests.powerdns.com."
    end
    addAction("local-port.advanced.tests.powerdns.com.", LuaAction(answerBasedOnLocalPort))
    newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedGetLocalPort(self):
        """
        Advanced: Return CNAME containing the local port
        """
        name = 'local-port.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'port-was-{}.local-port.advanced.tests.powerdns.com.'.format(self._dnsDistPort))
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, response)

class TestAdvancedGetLocalPortOnAnyBind(DNSDistTest):

    _config_template = """
    function answerBasedOnLocalPort(dq)
      local port = dq.localaddr:getPort()
      return DNSAction.Spoof, "port-was-"..port..".local-port-any.advanced.tests.powerdns.com."
    end
    addAction("local-port-any.advanced.tests.powerdns.com.", LuaAction(answerBasedOnLocalPort))
    newServer{address="127.0.0.1:%s"}
    """
    _dnsDistListeningAddr = "0.0.0.0"

    def testAdvancedGetLocalPortOnAnyBind(self):
        """
        Advanced: Return CNAME containing the local port for an ANY bind
        """
        name = 'local-port-any.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'port-was-{}.local-port-any.advanced.tests.powerdns.com.'.format(self._dnsDistPort))
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, response)

class TestAdvancedGetLocalAddressOnAnyBind(DNSDistTest):

    _config_template = """
    function answerBasedOnLocalAddress(dq)
      local dest = tostring(dq.localaddr)
      local i, j = string.find(dest, "[0-9.]+")
      local addr = string.sub(dest, i, j)
      local dashAddr = string.gsub(addr, "[.]", "-")
      return DNSAction.Spoof, "address-was-"..dashAddr..".local-address-any.advanced.tests.powerdns.com."
    end
    addAction("local-address-any.advanced.tests.powerdns.com.", LuaAction(answerBasedOnLocalAddress))
    newServer{address="127.0.0.1:%s"}
    """
    _dnsDistListeningAddr = "0.0.0.0"

    def testAdvancedGetLocalAddressOnAnyBind(self):
        """
        Advanced: Return CNAME containing the local address for an ANY bind
        """
        name = 'local-address-any.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'address-was-127-0-0-1.local-address-any.advanced.tests.powerdns.com.')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
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
    newServer{address="127.0.0.1:%s"}
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
    newServer{address="127.0.0.1:%s"}
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

class TestAdvancedAllowHeaderOnly(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
    setAllowEmptyResponse(true)
    """

    def testHeaderOnlyRefused(self):
        """
        Advanced: Header-only refused response
        """
        name = 'header-only-refused-response.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)
        response.question = []

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)

    def testHeaderOnlyNoErrorResponse(self):
        """
        Advanced: Header-only NoError response should be allowed
        """
        name = 'header-only-noerror-response.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.question = []

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)

    def testHeaderOnlyNXDResponse(self):
        """
        Advanced: Header-only NXD response should be allowed
        """
        name = 'header-only-nxd-response.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)
        response.question = []

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)

class TestAdvancedEDNSVersionRule(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
    addAction(EDNSVersionRule(0), ERCodeAction(DNSRCode.BADVERS))
    """

    def testBadVers(self):
        """
        Advanced: A question with ECS version larger than 0 yields BADVERS
        """

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
    controlSocket("127.0.0.1:%s")
    newServer{address="127.0.0.1:%s"}
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

class TestAdvancedContinueAction(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s", pool="mypool"}
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
            self.assertEqual(receivedQuery, expectedQuery)
            self.assertEqual(receivedResponse, expectedResponse)

    def testNoContinue(self):
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
    newServer{address="127.0.0.1:%s"}
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
    -- newServer{address="127.0.0.1:%s"}
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

class TestAdvancedLuaFFI(DNSDistTest):

    _config_template = """
    local ffi = require("ffi")

    local expectingUDP = true

    function luaffirulefunction(dq)
      local qtype = ffi.C.dnsdist_ffi_dnsquestion_get_qtype(dq)
      if qtype ~= DNSQType.A and qtype ~= DNSQType.SOA then
        print('invalid qtype')
        return false
      end

      local qclass = ffi.C.dnsdist_ffi_dnsquestion_get_qclass(dq)
      if qclass ~= DNSClass.IN then
        print('invalid qclass')
        return false
      end

      local ret_ptr = ffi.new("char *[1]")
      local ret_ptr_param = ffi.cast("const char **", ret_ptr)
      local ret_size = ffi.new("size_t[1]")
      local ret_size_param = ffi.cast("size_t*", ret_size)
      ffi.C.dnsdist_ffi_dnsquestion_get_qname_raw(dq, ret_ptr_param, ret_size_param)
      if ret_size[0] ~= 36 then
        print('invalid length for the qname ')
        print(ret_size[0])
        return false
      end

      local expectedQname = string.char(6)..'luaffi'..string.char(8)..'advanced'..string.char(5)..'tests'..string.char(8)..'powerdns'..string.char(3)..'com'
      if ffi.string(ret_ptr[0]) ~= expectedQname then
        print('invalid qname')
        print(ffi.string(ret_ptr[0]))
        return false
      end

      local rcode = ffi.C.dnsdist_ffi_dnsquestion_get_rcode(dq)
      if rcode ~= 0 then
        print('invalid rcode')
        return false
      end

      local opcode = ffi.C.dnsdist_ffi_dnsquestion_get_opcode(dq)
      if qtype == DNSQType.A and opcode ~= DNSOpcode.Query then
        print('invalid opcode')
        return false
      elseif qtype == DNSQType.SOA and opcode ~= DNSOpcode.Update then
        print('invalid opcode')
        return false
      end

      local tcp = ffi.C.dnsdist_ffi_dnsquestion_get_tcp(dq)
      if expectingUDP == tcp then
        print('invalid tcp')
        return false
      end
      expectingUDP = expectingUDP == false

      local dnssecok = ffi.C.dnsdist_ffi_dnsquestion_get_do(dq)
      if dnssecok ~= false then
        print('invalid DNSSEC OK')
        return false
      end

      local len = ffi.C.dnsdist_ffi_dnsquestion_get_len(dq)
      if len ~= 52 then
        print('invalid length')
        print(len)
        return false
      end

      local tag = ffi.C.dnsdist_ffi_dnsquestion_get_tag(dq, 'a-tag')
      if ffi.string(tag) ~= 'a-value' then
        print('invalid tag value')
        print(ffi.string(tag))
        return false
      end
      return true
    end

    function luaffiactionfunction(dq)
      local qtype = ffi.C.dnsdist_ffi_dnsquestion_get_qtype(dq)
      if qtype == DNSQType.A then
        local str = "192.0.2.1"
        local buf = ffi.new("char[?]", #str + 1)
        ffi.copy(buf, str)
        ffi.C.dnsdist_ffi_dnsquestion_set_result(dq, buf, #str)
        return DNSAction.Spoof
      elseif qtype == DNSQType.SOA then
        ffi.C.dnsdist_ffi_dnsquestion_set_rcode(dq, DNSRCode.REFUSED)
        return DNSAction.Refused
      end
    end

    function luaffiactionsettag(dq)
      ffi.C.dnsdist_ffi_dnsquestion_set_tag(dq, 'a-tag', 'a-value')
      return DNSAction.None
    end

    addAction(AllRule(), LuaFFIAction(luaffiactionsettag))
    addAction(LuaFFIRule(luaffirulefunction), LuaFFIAction(luaffiactionfunction))
    -- newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedLuaFFI(self):
        """
        Advanced: Test the Lua FFI interface
        """
        name = 'luaffi.advanced.tests.powerdns.com.'
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
            self.assertEqual(receivedResponse, response)

    def testAdvancedLuaFFIUpdate(self):
        """
        Advanced: Test the Lua FFI interface via an update
        """
        name = 'luaffi.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'SOA', 'IN')
        query.set_opcode(dns.opcode.UPDATE)
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, response)

class TestAdvancedLuaFFIPerThread(DNSDistTest):

    _config_template = """

    local rulefunction = [[
      local ffi = require("ffi")

      return function(dq)
        local qtype = ffi.C.dnsdist_ffi_dnsquestion_get_qtype(dq)
        if qtype ~= DNSQType.A and qtype ~= DNSQType.SOA then
          print('invalid qtype')
          return false
        end

        local qclass = ffi.C.dnsdist_ffi_dnsquestion_get_qclass(dq)
        if qclass ~= DNSClass.IN then
          print('invalid qclass')
          return false
        end

        local ret_ptr = ffi.new("char *[1]")
        local ret_ptr_param = ffi.cast("const char **", ret_ptr)
        local ret_size = ffi.new("size_t[1]")
        local ret_size_param = ffi.cast("size_t*", ret_size)
        ffi.C.dnsdist_ffi_dnsquestion_get_qname_raw(dq, ret_ptr_param, ret_size_param)
        if ret_size[0] ~= 45 then
          print('invalid length for the qname ')
          print(ret_size[0])
          return false
        end

        local expectedQname = string.char(15)..'luaffiperthread'..string.char(8)..'advanced'..string.char(5)..'tests'..string.char(8)..'powerdns'..string.char(3)..'com'
        if ffi.string(ret_ptr[0]) ~= expectedQname then
          print('invalid qname')
          print(ffi.string(ret_ptr[0]))
          return false
        end

        local rcode = ffi.C.dnsdist_ffi_dnsquestion_get_rcode(dq)
        if rcode ~= 0 then
          print('invalid rcode')
          return false
        end

        local opcode = ffi.C.dnsdist_ffi_dnsquestion_get_opcode(dq)
        if qtype == DNSQType.A and opcode ~= DNSOpcode.Query then
          print('invalid opcode')
          return false
        elseif qtype == DNSQType.SOA and opcode ~= DNSOpcode.Update then
          print('invalid opcode')
          return false
        end

        local dnssecok = ffi.C.dnsdist_ffi_dnsquestion_get_do(dq)
        if dnssecok ~= false then
          print('invalid DNSSEC OK')
          return false
        end

        local len = ffi.C.dnsdist_ffi_dnsquestion_get_len(dq)
        if len ~= 61 then
          print('invalid length')
          print(len)
          return false
        end

        local tag = ffi.C.dnsdist_ffi_dnsquestion_get_tag(dq, 'a-tag')
        if ffi.string(tag) ~= 'a-value' then
          print('invalid tag value')
          print(ffi.string(tag))
          return false
        end

        return true
      end
    ]]

    local actionfunction = [[
      local ffi = require("ffi")

      return function(dq)
        local qtype = ffi.C.dnsdist_ffi_dnsquestion_get_qtype(dq)
        if qtype == DNSQType.A then
          local str = "192.0.2.1"
          local buf = ffi.new("char[?]", #str + 1)
          ffi.copy(buf, str)
          ffi.C.dnsdist_ffi_dnsquestion_set_result(dq, buf, #str)
          return DNSAction.Spoof
        elseif qtype == DNSQType.SOA then
          ffi.C.dnsdist_ffi_dnsquestion_set_rcode(dq, DNSRCode.REFUSED)
          return DNSAction.Refused
        end
      end
    ]]

    local settagfunction = [[
      local ffi = require("ffi")

      return function(dq)
        ffi.C.dnsdist_ffi_dnsquestion_set_tag(dq, 'a-tag', 'a-value')
        return DNSAction.None
      end
    ]]

    addAction(AllRule(), LuaFFIPerThreadAction(settagfunction))
    addAction(LuaFFIPerThreadRule(rulefunction), LuaFFIPerThreadAction(actionfunction))
    -- newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedLuaPerthreadFFI(self):
        """
        Advanced: Test the Lua FFI per-thread interface
        """
        name = 'luaffiperthread.advanced.tests.powerdns.com.'
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
            self.assertEqual(receivedResponse, response)

    def testAdvancedLuaFFIPerThreadUpdate(self):
        """
        Advanced: Test the Lua FFI per-thread interface via an update
        """
        name = 'luaffiperthread.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'SOA', 'IN')
        query.set_opcode(dns.opcode.UPDATE)
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, response)

class TestAdvancedDropEmptyQueries(DNSDistTest):

    _config_template = """
    setDropEmptyQueries(true)
    newServer{address="127.0.0.1:%s"}
    """

    def testAdvancedDropEmptyQueries(self):
        """
        Advanced: Drop empty queries
        """
        name = 'drop-empty-queries.advanced.tests.powerdns.com.'
        query = dns.message.Message()

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, None)

class TestProtocols(DNSDistTest):
    _config_template = """
    function checkUDP(dq)
      if dq:getProtocol() ~= "Do53 UDP" then
        return DNSAction.Spoof, '1.2.3.4'
      end
      return DNSAction.None
    end

    function checkTCP(dq)
      if dq:getProtocol() ~= "Do53 TCP" then
        return DNSAction.Spoof, '1.2.3.4'
      end
      return DNSAction.None
    end

    addAction("udp.protocols.advanced.tests.powerdns.com.", LuaAction(checkUDP))
    addAction("tcp.protocols.advanced.tests.powerdns.com.", LuaAction(checkTCP))
    newServer{address="127.0.0.1:%s"}
    """

    def testProtocolUDP(self):
        """
        Advanced: Test DNSQuestion.Protocol over UDP
        """
        name = 'udp.protocols.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)

    def testProtocolTCP(self):
        """
        Advanced: Test DNSQuestion.Protocol over TCP
        """
        name = 'tcp.protocols.advanced.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEqual(receivedQuery, query)
        self.assertEqual(receivedResponse, response)

class TestAdvancedSetEDNSOptionAction(DNSDistTest):

    _config_template = """
    addAction("setednsoption.advanced.tests.powerdns.com.", SetEDNSOptionAction(10, "deadbeefdeadc0de"))
    newServer{address="127.0.0.1:%s"}
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
