#!/usr/bin/env python
from datetime import datetime, timedelta
import time
import dns
from dnsdisttests import DNSDistTest

class TestResponseRuleNXDelayed(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
    addResponseAction(RCodeRule(dnsdist.NXDOMAIN), DelayResponseAction(1000))
    """

    def testNXDelayed(self):
        """
        Responses: Delayed on NXDomain

        Send an A query to "delayed.responses.tests.powerdns.com.",
        check that the response delay is longer than 1000 ms
        for a NXDomain response over UDP, shorter for a NoError one.
        """
        name = 'delayed.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        # NX over UDP
        response.set_rcode(dns.rcode.NXDOMAIN)
        begin = datetime.now()
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        end = datetime.now()
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        self.assertTrue((end - begin) > timedelta(0, 1))

        # NoError over UDP
        response.set_rcode(dns.rcode.NOERROR)
        begin = datetime.now()
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        end = datetime.now()
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        self.assertTrue((end - begin) < timedelta(0, 1))

        # NX over TCP
        response.set_rcode(dns.rcode.NXDOMAIN)
        begin = datetime.now()
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        end = datetime.now()
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        self.assertTrue((end - begin) < timedelta(0, 1))

class TestResponseRuleQNameDropped(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
    addResponseAction("drop.responses.tests.powerdns.com.", DropResponseAction())
    """

    def testDropped(self):
        """
        Responses: Dropped on QName

        Send an A query to "drop.responses.tests.powerdns.com.",
        check that the response (not the query) is dropped.
        """
        name = 'drop.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, None)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, None)

    def testNotDropped(self):
        """
        Responses: NOT Dropped on QName

        Send an A query to "dontdrop.responses.tests.powerdns.com.",
        check that the response is not dropped.
        """
        name = 'dontdrop.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

class TestResponseRuleQNameAllowed(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s"}
    addResponseAction("allow.responses.tests.powerdns.com.", AllowResponseAction())
    addResponseAction(AllRule(), DropResponseAction())
    """

    def testAllowed(self):
        """
        Responses: Allowed on QName

        Send an A query to "allow.responses.tests.powerdns.com.",
        check that the response is allowed.
        """
        name = 'allow.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)

    def testNotAllowed(self):
        """
        Responses: Not allowed on QName

        Send an A query to "dontallow.responses.tests.powerdns.com.",
        check that the response is dropped.
        """
        name = 'dontallow.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, None)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(receivedResponse, None)

class TestResponseRuleEditTTL(DNSDistTest):

    _ttl = 5
    _config_params = ['_testServerPort', '_ttl']
    _config_template = """
    newServer{address="127.0.0.1:%s"}

    function editTTLCallback(section, class, type, ttl)
      return %d
    end

    function editTTLFunc(dr)
      dr:editTTLs(editTTLCallback)
      return DNSAction.None, ""
    end

    addLuaResponseAction(AllRule(), editTTLFunc)
    """

    def testTTLEdited(self):
        """
        Responses: Alter the TTLs
        """
        name = 'editttl.responses.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        self.assertNotEquals(response.answer[0].ttl, receivedResponse.answer[0].ttl)
        self.assertEquals(receivedResponse.answer[0].ttl, self._ttl)

        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        self.assertNotEquals(response.answer[0].ttl, receivedResponse.answer[0].ttl)
        self.assertEquals(receivedResponse.answer[0].ttl, self._ttl)
