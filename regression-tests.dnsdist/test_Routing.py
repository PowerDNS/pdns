#!/usr/bin/env python
import base64
import threading
import time
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort

class TestRoutingPoolRouting(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s", pool="real"}
    addAction(makeRule("poolaction.routing.tests.powerdns.com"), PoolAction("real"))
    -- by default PoolAction stops the processing so the second rule should not be executed
    addAction(makeRule("poolaction.routing.tests.powerdns.com"), PoolAction("not-real"))

    -- this time we configure PoolAction to not stop the processing
    addAction(makeRule("poolaction-nostop.routing.tests.powerdns.com"), PoolAction("no-real", false))
    -- so the second rule should be executed
    addAction(makeRule("poolaction-nostop.routing.tests.powerdns.com"), PoolAction("real"))
    """

    def testPolicyPoolAction(self):
        """
        Routing: Set pool by qname via PoolAction

        Send an A query to "poolaction.routing.tests.powerdns.com.",
        check that dnsdist routes the query to the "real" pool.
        """
        name = 'poolaction.routing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

    def testPolicyPoolActionNoStop(self):
        """
        Routing: Set pool by qname via PoolAction (no stop)
        """
        name = 'poolaction-nostop.routing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

    def testDefaultPool(self):
        """
        Routing: Set pool by qname canary

        Send an A query to "notpool.routing.tests.powerdns.com.",
        check that dnsdist sends no response (no servers
        in the default pool).
        """
        name = 'notpool.routing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedResponse, None)

class TestRoutingQPSPoolRouting(DNSDistTest):
    _config_template = """
    newServer{address="127.0.0.1:%s", pool="regular"}
    addAction(makeRule("qpspoolaction.routing.tests.powerdns.com"), QPSPoolAction(10, "regular"))
    """

    def testQPSPoolAction(self):
        """
        Routing: Set pool by QPS via action

        Send queries to "qpspoolaction.routing.tests.powerdns.com."
        check that dnsdist does not route the query to the "regular" pool
        when the max QPS has been reached.
        """
        maxQPS = 10
        name = 'qpspoolaction.routing.tests.powerdns.com.'
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

        # we should now be sent to the "abuse" pool which is empty,
        # so the queries should be dropped
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


class TestRoutingRoundRobinLB(DNSDistTest):

    _testServer2Port = pickAvailablePort()
    _config_params = ['_testServerPort', '_testServer2Port']
    _config_template = """
    setServerPolicy(roundrobin)
    s1 = newServer{address="127.0.0.1:%s"}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%s"}
    s2:setUp()
    """

    @classmethod
    def startResponders(cls):
        print("Launching responders..")
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder.daemon = True
        cls._UDPResponder.start()
        cls._UDPResponder2 = threading.Thread(name='UDP Responder 2', target=cls.UDPResponder, args=[cls._testServer2Port, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder2.daemon = True
        cls._UDPResponder2.start()

        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._TCPResponder.daemon = True
        cls._TCPResponder.start()

        cls._TCPResponder2 = threading.Thread(name='TCP Responder 2', target=cls.TCPResponder, args=[cls._testServer2Port, cls._toResponderQueue, cls._fromResponderQueue])
        cls._TCPResponder2.daemon = True
        cls._TCPResponder2.start()

    def testRR(self):
        """
        Routing: Round Robin

        Send 10 A queries to "rr.routing.tests.powerdns.com.",
        check that dnsdist routes half of it to each backend.
        """
        numberOfQueries = 10
        name = 'rr.routing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        # the round robin counter is shared for UDP and TCP,
        # so we need to do UDP then TCP to have a clean count
        for _ in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        for _ in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        for key in self._responsesCounter:
            value = self._responsesCounter[key]
            self.assertEqual(value, numberOfQueries / 2)

class TestRoutingRoundRobinLBOneDown(DNSDistTest):

    _testServer2Port = pickAvailablePort()
    _config_params = ['_testServerPort', '_testServer2Port']
    _config_template = """
    setServerPolicy(roundrobin)
    s1 = newServer{address="127.0.0.1:%s"}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%s"}
    s2:setDown()
    """

    def testRRWithOneDown(self):
        """
        Routing: Round Robin with one server down

        Send 100 A queries to "rr.routing.tests.powerdns.com.",
        check that dnsdist routes all of it to the only backend up.
        """
        numberOfQueries = 10
        name = 'rr.routing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        # the round robin counter is shared for UDP and TCP,
        # so we need to do UDP then TCP to have a clean count
        for _ in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        for _ in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        total = 0
        for key in self._responsesCounter:
            value = self._responsesCounter[key]
            self.assertTrue(value == numberOfQueries or value == 0)
            total += value

        self.assertEqual(total, numberOfQueries * 2)

class TestRoutingRoundRobinLBAllDown(DNSDistTest):

    _testServer2Port = pickAvailablePort()
    _config_params = ['_testServerPort', '_testServer2Port']
    _config_template = """
    setServerPolicy(roundrobin)
    setRoundRobinFailOnNoServer(true)
    s1 = newServer{address="127.0.0.1:%s"}
    s1:setDown()
    s2 = newServer{address="127.0.0.1:%s"}
    s2:setDown()
    """

    def testRRWithAllDown(self):
        """
        Routing: Round Robin with all servers down
        """
        numberOfQueries = 10
        name = 'alldown.rr.routing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
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
            self.assertEqual(receivedResponse, None)

class TestRoutingLuaFFIPerThreadRoundRobinLB(DNSDistTest):

    _testServer2Port = pickAvailablePort()
    _config_params = ['_testServerPort', '_testServer2Port']
    _config_template = """
    -- otherwise we start too many TCP workers, and as each thread
    -- uses it own counter this makes the TCP queries distribution hard to predict
    setMaxTCPClientThreads(1)
    setServerPolicyLuaFFIPerThread("luaffiroundrobin", [[
      local ffi = require("ffi")
      local C = ffi.C

      local counter = 0
      return function(servers_list, dq)
        counter = counter + 1
        return (counter %% tonumber(C.dnsdist_ffi_servers_list_get_count(servers_list)))
      end
    ]])

    s1 = newServer{address="127.0.0.1:%s"}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%s"}
    s2:setUp()
    """

    @classmethod
    def startResponders(cls):
        print("Launching responders..")
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder.daemon = True
        cls._UDPResponder.start()
        cls._UDPResponder2 = threading.Thread(name='UDP Responder 2', target=cls.UDPResponder, args=[cls._testServer2Port, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder2.daemon = True
        cls._UDPResponder2.start()

        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._TCPResponder.daemon = True
        cls._TCPResponder.start()

        cls._TCPResponder2 = threading.Thread(name='TCP Responder 2', target=cls.TCPResponder, args=[cls._testServer2Port, cls._toResponderQueue, cls._fromResponderQueue])
        cls._TCPResponder2.daemon = True
        cls._TCPResponder2.start()

    def testRR(self):
        """
        Routing: Round Robin

        Send 10 A queries to "rr.routing.tests.powerdns.com.",
        check that dnsdist routes half of it to each backend.
        """
        numberOfQueries = 10
        name = 'rr.routing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        # the round robin counter is shared for UDP and TCP,
        # so we need to do UDP then TCP to have a clean count
        for _ in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        for _ in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        for key in self._responsesCounter:
            value = self._responsesCounter[key]
            self.assertEqual(value, numberOfQueries / 2)

class TestRoutingOrder(DNSDistTest):

    _testServer2Port = pickAvailablePort()
    _config_params = ['_testServerPort', '_testServer2Port']
    _config_template = """
    setServerPolicy(firstAvailable)
    s1 = newServer{address="127.0.0.1:%s", order=2}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%s", order=1}
    s2:setUp()
    """

    @classmethod
    def startResponders(cls):
        print("Launching responders..")
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder.daemon = True
        cls._UDPResponder.start()
        cls._UDPResponder2 = threading.Thread(name='UDP Responder 2', target=cls.UDPResponder, args=[cls._testServer2Port, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder2.daemon = True
        cls._UDPResponder2.start()

        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._TCPResponder.daemon = True
        cls._TCPResponder.start()

        cls._TCPResponder2 = threading.Thread(name='TCP Responder 2', target=cls.TCPResponder, args=[cls._testServer2Port, cls._toResponderQueue, cls._fromResponderQueue])
        cls._TCPResponder2.daemon = True
        cls._TCPResponder2.start()

    def testOrder(self):
        """
        Routing: firstAvailable policy based on 'order'

        Send 50 A queries to "order.routing.tests.powerdns.com.",
        check that dnsdist routes all of it to the second backend
        because it has the lower order value.
        """
        numberOfQueries = 50
        name = 'order.routing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for _ in range(numberOfQueries):
            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                (receivedQuery, receivedResponse) = sender(query, response)
                receivedQuery.id = query.id
                self.assertEqual(query, receivedQuery)
                self.assertEqual(response, receivedResponse)

        total = 0
        if 'UDP Responder' in self._responsesCounter:
            self.assertEqual(self._responsesCounter['UDP Responder'], 0)
        self.assertEqual(self._responsesCounter['UDP Responder 2'], numberOfQueries)
        if 'TCP Responder' in self._responsesCounter:
            self.assertEqual(self._responsesCounter['TCP Responder'], 0)
        self.assertEqual(self._responsesCounter['TCP Responder 2'], numberOfQueries)

class TestFirstAvailableQPSPacketCacheHits(DNSDistTest):

    _verboseMode = True
    _testServer2Port = pickAvailablePort()
    _config_params = ['_testServerPort', '_testServer2Port']
    _config_template = """
    setServerPolicy(firstAvailable)
    s1 = newServer{address="127.0.0.1:%s", order=2}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%s", order=1, qps=10}
    s2:setUp()
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)
    """

    @classmethod
    def startResponders(cls):
        print("Launching responders..")
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder.daemon = True
        cls._UDPResponder.start()
        cls._UDPResponder2 = threading.Thread(name='UDP Responder 2', target=cls.UDPResponder, args=[cls._testServer2Port, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder2.daemon = True
        cls._UDPResponder2.start()

        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._TCPResponder.daemon = True
        cls._TCPResponder.start()

        cls._TCPResponder2 = threading.Thread(name='TCP Responder 2', target=cls.TCPResponder, args=[cls._testServer2Port, cls._toResponderQueue, cls._fromResponderQueue])
        cls._TCPResponder2.daemon = True
        cls._TCPResponder2.start()

    def testOrderQPSCacheHits(self):
        """
        Routing: firstAvailable policy with QPS limit and packet cache

        Send 50 A queries for "order-qps-cache.routing.tests.powerdns.com.",
        then 10 A queries for "order-qps-cache-2.routing.tests.powerdns.com." (uncached)
        check that dnsdist routes all of the (uncached) queries to the second backend, because it has the lower order value,
        and the QPS should only be counted for cache misses.
        """
        numberOfQueries = 50
        name = 'order-qps-cache.routing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        # first queries to fill the cache
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

        for _ in range(numberOfQueries):
            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                (_, receivedResponse) = sender(query, response=None, useQueue=False)
                self.assertEqual(receivedResponse, response)

        numberOfQueries = 10
        name = 'order-qps-cache-2.routing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        # first queries to fill the cache
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)
        (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

        for _ in range(numberOfQueries):
            for method in ("sendUDPQuery", "sendTCPQuery"):
                sender = getattr(self, method)
                (_, receivedResponse) = sender(query, response=None, useQueue=False)
                self.assertEqual(receivedResponse, response)

        # 4 queries should made it through, 2 UDP and 2 TCP
        for k,v in self._responsesCounter.items():
            print(k)
            print(v)

        if 'UDP Responder' in self._responsesCounter:
            self.assertEqual(self._responsesCounter['UDP Responder'], 0)
        self.assertEqual(self._responsesCounter['UDP Responder 2'], 2)
        if 'TCP Responder' in self._responsesCounter:
            self.assertEqual(self._responsesCounter['TCP Responder'], 0)
        self.assertEqual(self._responsesCounter['TCP Responder 2'], 2)

class TestRoutingNoServer(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%s", pool="real"}
    setServFailWhenNoServer(true)
    """

    def testPolicyPoolNoServer(self):
        """
        Routing: No server should return ServFail
        """
        # without EDNS
        name = 'noserver.routing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.SERVFAIL)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageNoEDNS(expectedResponse, receivedResponse)

        # now with EDNS
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, want_dnssec=False)
        expectedResponse = dns.message.make_response(query, our_payload=1232)
        expectedResponse.set_rcode(dns.rcode.SERVFAIL)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.checkMessageEDNSWithoutOptions(expectedResponse, receivedResponse)
            self.assertFalse(receivedResponse.ednsflags & dns.flags.DO)
            self.assertEqual(receivedResponse.payload, 1232)

class TestRoutingWRandom(DNSDistTest):

    _testServer2Port = pickAvailablePort()
    _config_params = ['_testServerPort', '_testServer2Port']
    _config_template = """
    setServerPolicy(wrandom)
    s1 = newServer{address="127.0.0.1:%s", weight=1}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%s", weight=2}
    s2:setUp()
    """

    @classmethod
    def startResponders(cls):
        print("Launching responders..")
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder.daemon = True
        cls._UDPResponder.start()
        cls._UDPResponder2 = threading.Thread(name='UDP Responder 2', target=cls.UDPResponder, args=[cls._testServer2Port, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder2.daemon = True
        cls._UDPResponder2.start()

        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._TCPResponder.daemon = True
        cls._TCPResponder.start()

        cls._TCPResponder2 = threading.Thread(name='TCP Responder 2', target=cls.TCPResponder, args=[cls._testServer2Port, cls._toResponderQueue, cls._fromResponderQueue])
        cls._TCPResponder2.daemon = True
        cls._TCPResponder2.start()

    def testWRandom(self):
        """
        Routing: WRandom

        Send 100 A queries to "wrandom.routing.tests.powerdns.com.",
        check that dnsdist routes less than half to one, more to the other.
        """
        numberOfQueries = 100
        name = 'wrandom.routing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        # the counter is shared for UDP and TCP,
        # so we need to do UDP then TCP to have a clean count
        for _ in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        for _ in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        # The lower weight downstream should receive less than half the queries
        self.assertLess(self._responsesCounter['UDP Responder'], numberOfQueries * 0.50)
        self.assertLess(self._responsesCounter['TCP Responder'], numberOfQueries * 0.50)

        # The higher weight downstream should receive more than half the queries
        self.assertGreater(self._responsesCounter['UDP Responder 2'], numberOfQueries * 0.50)
        self.assertGreater(self._responsesCounter['TCP Responder 2'], numberOfQueries * 0.50)


class TestRoutingHighValueWRandom(DNSDistTest):

    _testServer2Port = pickAvailablePort()
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServerPort', '_testServer2Port']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")
    setServerPolicy(wrandom)
    s1 = newServer{address="127.0.0.1:%s", weight=2000000000}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%s", weight=2000000000}
    s2:setUp()
    """

    @classmethod
    def startResponders(cls):
        print("Launching responders..")
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder.daemon = True
        cls._UDPResponder.start()
        cls._UDPResponder2 = threading.Thread(name='UDP Responder 2', target=cls.UDPResponder, args=[cls._testServer2Port, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder2.daemon = True
        cls._UDPResponder2.start()

        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._TCPResponder.daemon = True
        cls._TCPResponder.start()

        cls._TCPResponder2 = threading.Thread(name='TCP Responder 2', target=cls.TCPResponder, args=[cls._testServer2Port, cls._toResponderQueue, cls._fromResponderQueue])
        cls._TCPResponder2.daemon = True
        cls._TCPResponder2.start()

    def testHighValueWRandom(self):
        """
        Routing: WRandom (overflow)

        Send 100 A queries to "wrandom-overflow.routing.tests.powerdns.com.",
        check that dnsdist routes to each downstream, rather than failing with
        no-policy.
        """
        numberOfQueries = 100
        name = 'wrandom-overflow.routing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        # the counter is shared for UDP and TCP,
        # so we need to do UDP then TCP to have a clean count
        for _ in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        for _ in range(numberOfQueries):
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        stats = self.sendConsoleCommand("dumpStats()").split()
        stats_dict = {}

        # Map to a dict with every other element being the value to the previous one
        for i, x in enumerate(stats):
            if not i % 2:
                stats_dict[x] = stats[i+1]

        # There should be no queries getting "no-policy" responses
        self.assertEqual(stats_dict['no-policy'], '0')

        # Each downstream should receive some queries, but it will be unbalanced
        # because the sum of the weights is higher than INT_MAX.
        # The first downstream will receive more than half the queries
        self.assertGreater(self._responsesCounter['UDP Responder'], numberOfQueries / 2)
        self.assertGreater(self._responsesCounter['TCP Responder'], numberOfQueries / 2)

        # The second downstream will receive the remainder of the queries, but it might very well be 0
        if 'UDP Responder 2' in self._responsesCounter:
            self.assertEqual(self._responsesCounter['UDP Responder 2'], numberOfQueries - self._responsesCounter['UDP Responder'])
        if 'TCP Responder 2' in self._responsesCounter:
            self.assertEqual(self._responsesCounter['TCP Responder 2'], numberOfQueries - self._responsesCounter['TCP Responder'])
