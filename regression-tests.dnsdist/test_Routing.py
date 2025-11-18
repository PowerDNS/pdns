#!/usr/bin/env python
import base64
import threading
import time
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort

class TestRoutingPoolRouting(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%d", pool="real"}
    addAction(SuffixMatchNodeRule("poolaction.routing.tests.powerdns.com"), PoolAction("real"))
    -- by default PoolAction stops the processing so the second rule should not be executed
    addAction(SuffixMatchNodeRule("poolaction.routing.tests.powerdns.com"), PoolAction("not-real"))

    -- this time we configure PoolAction to not stop the processing
    addAction(SuffixMatchNodeRule("poolaction-nostop.routing.tests.powerdns.com"), PoolAction("no-real", false))
    -- so the second rule should be executed
    addAction(SuffixMatchNodeRule("poolaction-nostop.routing.tests.powerdns.com"), PoolAction("real"))
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
    newServer{address="127.0.0.1:%d", pool="regular"}
    addAction(SuffixMatchNodeRule("qpspoolaction.routing.tests.powerdns.com"), QPSPoolAction(10, "regular"))
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

class RoundRobinTest(object):
    def doTestRR(self, name):
        """
        Routing: Round Robin

        Send 10 A queries to the requested name,
        check that dnsdist routes half of it to each backend.
        """
        numberOfQueries = 10
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

class TestRoutingRoundRobinLB(RoundRobinTest, DNSDistTest):

    _testServer2Port = pickAvailablePort()
    _config_params = ['_testServerPort', '_testServer2Port']
    _config_template = """
    setServerPolicy(roundrobin)
    s1 = newServer{address="127.0.0.1:%d"}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%d"}
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
        self.doTestRR('rr.routing.tests.powerdns.com.')

class TestRoutingRoundRobinLBViaPool(RoundRobinTest, DNSDistTest):

    _testServer2Port = pickAvailablePort()
    _config_params = ['_testServerPort', '_testServer2Port']
    _config_template = """
    s1 = newServer{address="127.0.0.1:%d"}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%d"}
    s2:setUp()
    setPoolServerPolicy(roundrobin, '')
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
        Routing: Round Robin (pool)

        Send 10 A queries to "rr-pool.routing.tests.powerdns.com.",
        check that dnsdist routes half of it to each backend.
        """
        self.doTestRR('rr-pool.routing.tests.powerdns.com.')

class TestRoutingRoundRobinLBOneDown(DNSDistTest):

    _testServer2Port = pickAvailablePort()
    _config_params = ['_testServerPort', '_testServer2Port']
    _config_template = """
    setServerPolicy(roundrobin)
    s1 = newServer{address="127.0.0.1:%d"}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%d"}
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
    s1 = newServer{address="127.0.0.1:%d"}
    s1:setDown()
    s2 = newServer{address="127.0.0.1:%d"}
    s2:setDown()
    """

    def testRRWithAllDown(self):
        """
        Routing: Round Robin with all servers down
        """
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

class TestRoutingLuaFFIPerThreadRoundRobinLB(RoundRobinTest, DNSDistTest):

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

    s1 = newServer{address="127.0.0.1:%d"}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%d"}
    s2:setUp()

    function atExit()
      setServerPolicy(leastOutstanding)
      collectgarbage()
    end
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
        Routing: Round Robin (LuaFFI)
        """
        self.doTestRR('rr-luaffi.routing.tests.powerdns.com.')

class TestRoutingCustomLuaRoundRobinLB(RoundRobinTest, DNSDistTest):

    _testServer2Port = pickAvailablePort()
    _config_params = ['_testServerPort', '_testServer2Port']
    _config_template = """
    -- otherwise we start too many TCP workers, and as each thread
    -- uses it own counter this makes the TCP queries distribution hard to predict
    setMaxTCPClientThreads(1)

    local counter = 0
    function luaroundrobin(servers_list, dq)
      counter = counter + 1
      return (counter %% #servers_list)+1
    end
    setServerPolicy(newServerPolicy("custom lua round robin policy", luaroundrobin))

    s1 = newServer{address="127.0.0.1:%d"}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%d"}
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
        Routing: Round Robin (Lua)
        """
        self.doTestRR('rr-lua.routing.tests.powerdns.com.')

class TestRoutingOrder(DNSDistTest):

    _testServer2Port = pickAvailablePort()
    _config_params = ['_testServerPort', '_testServer2Port']
    _config_template = """
    setServerPolicy(firstAvailable)
    s1 = newServer{address="127.0.0.1:%d", order=2}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%d", order=1}
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
    s1 = newServer{address="127.0.0.1:%d", order=2}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%d", order=1, qps=10}
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
        #for k,v in self._responsesCounter.items():
        #    print(k)
        #    print(v)

        if 'UDP Responder' in self._responsesCounter:
            self.assertEqual(self._responsesCounter['UDP Responder'], 0)
        self.assertEqual(self._responsesCounter['UDP Responder 2'], 2)
        if 'TCP Responder' in self._responsesCounter:
            self.assertEqual(self._responsesCounter['TCP Responder'], 0)
        self.assertEqual(self._responsesCounter['TCP Responder 2'], 2)

class TestRoutingNoServer(DNSDistTest):

    _config_template = """
    newServer{address="127.0.0.1:%d", pool="real"}
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
    setWeightedBalancingFactor(1.5)
    -- this is the default, but let's ensure we can reset it to the initial value
    setWeightedBalancingFactor(0)
    s1 = newServer{address="127.0.0.1:%d", weight=1}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%d", weight=2}
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
    controlSocket("127.0.0.1:%d")
    setServerPolicy(wrandom)
    s1 = newServer{address="127.0.0.1:%d", weight=2000000000}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%d", weight=2000000000}
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

class TestRoutingWHashed(DNSDistTest):

    _testServer2Port = pickAvailablePort()
    _config_params = ['_testServerPort', '_testServer2Port']
    _config_template = """
    setServerPolicy(whashed)
    setWeightedBalancingFactor(1.5)
    -- this is the default, but let's ensure we can reset it to the initial value
    setWeightedBalancingFactor(0)
    s1 = newServer{address="127.0.0.1:%d", weight=1}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%d", weight=1}
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

    def testHashed(self):
        """
        Routing: WHashed

        Send 100 A queries to "<num>.whashed.routing.tests.powerdns.com.",
        check that dnsdist routes at least 25% to each backend (hashing
        will not be perfect, especially with so few datapoints, but still).
        """
        numberOfQueries = 100
        suffix = 'whashed.routing.tests.powerdns.com.'

        # the counter is shared for UDP and TCP,
        # so we need to do UDP then TCP to have a clean count
        for idx in range(numberOfQueries):
            name = str(idx) + '.udp.' + suffix
            query = dns.message.make_query(name, 'A', 'IN')
            response = dns.message.make_response(query)
            rrset = dns.rrset.from_text(name,
                                        60,
                                        dns.rdataclass.IN,
                                        dns.rdatatype.A,
                                        '192.0.2.1')
            response.answer.append(rrset)
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        for idx in range(numberOfQueries):
            name = str(idx) + '.tcp.' + suffix
            query = dns.message.make_query(name, 'A', 'IN')
            response = dns.message.make_response(query)
            rrset = dns.rrset.from_text(name,
                                        60,
                                        dns.rdataclass.IN,
                                        dns.rdatatype.A,
                                        '192.0.2.1')
            response.answer.append(rrset)
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        self.assertGreater(self._responsesCounter['UDP Responder'], numberOfQueries * 0.25)
        self.assertGreater(self._responsesCounter['TCP Responder'], numberOfQueries * 0.25)
        self.assertGreater(self._responsesCounter['UDP Responder 2'], numberOfQueries * 0.25)
        self.assertGreater(self._responsesCounter['TCP Responder 2'], numberOfQueries * 0.25)

class TestRoutingCHashed(DNSDistTest):

    _testServer2Port = pickAvailablePort()
    _config_params = ['_testServerPort', '_testServer2Port']
    _config_template = """
    setServerPolicy(chashed)
    setConsistentHashingBalancingFactor(1.5)
    -- this is the default, but let's ensure we can reset it to the initial value
    setConsistentHashingBalancingFactor(0)
    s1 = newServer{address="127.0.0.1:%d", weight=1000}
    s1:setUp()
    s2 = newServer{address="127.0.0.1:%d", weight=1000}
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

    def testHashed(self):
        """
        Routing: CHashed

        Send 100 A queries to "<num>.chashed.routing.tests.powerdns.com.",
        check that dnsdist routes at least 25% to each backend (hashing
        will not be perfect, especially with so few datapoints, but still).
        """
        numberOfQueries = 100
        suffix = 'chashed.routing.tests.powerdns.com.'

        # the counter is shared for UDP and TCP,
        # so we need to do UDP then TCP to have a clean count
        for idx in range(numberOfQueries):
            name = str(idx) + '.udp.' + suffix
            query = dns.message.make_query(name, 'A', 'IN')
            response = dns.message.make_response(query)
            rrset = dns.rrset.from_text(name,
                                        60,
                                        dns.rdataclass.IN,
                                        dns.rdatatype.A,
                                        '192.0.2.1')
            response.answer.append(rrset)
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        for idx in range(numberOfQueries):
            name = str(idx) + '.tcp.' + suffix
            query = dns.message.make_query(name, 'A', 'IN')
            response = dns.message.make_response(query)
            rrset = dns.rrset.from_text(name,
                                        60,
                                        dns.rdataclass.IN,
                                        dns.rdatatype.A,
                                        '192.0.2.1')
            response.answer.append(rrset)
            (receivedQuery, receivedResponse) = self.sendTCPQuery(query, response)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        self.assertGreater(self._responsesCounter['UDP Responder'], numberOfQueries * 0.25)
        self.assertGreater(self._responsesCounter['TCP Responder'], numberOfQueries * 0.25)
        self.assertGreater(self._responsesCounter['UDP Responder 2'], numberOfQueries * 0.25)
        self.assertGreater(self._responsesCounter['TCP Responder 2'], numberOfQueries * 0.25)

class TestRoutingLuaFFILBNoServer(DNSDistTest):

    _config_template = """
    -- we want a ServFail answer when all servers are down
    setServFailWhenNoServer(true)

    local ffi = require("ffi")
    local C = ffi.C
    function luaffipolicy(servers_list, dq)
      -- return a large value, outside of the number of servers, to indicate that
      -- no server is available
      return tonumber(C.dnsdist_ffi_servers_list_get_count(servers_list)) + 100
    end
    setServerPolicyLuaFFI("luaffipolicy", luaffipolicy)

    s1 = newServer{address="127.0.0.1:%d"}
    s1:setDown()
    """
    _verboseMode = True

    def testOurPolicy(self):
        """
        Routing: LuaFFI policy, all servers are down
        """
        name = 'lua-ffi-no-servers.routing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.SERVFAIL)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(expectedResponse, receivedResponse)


class QueryCounter:

    def __init__(self, name):
        self.name = name
        self.refuse = False
        self.qcnt = 0

    def __call__(self):
        return self.qcnt

    def reset(self):
        self.qcnt = 0

    def set_refuse(self, flag):
        self.refuse = True if flag else False

    def create_cb(self):
        def callback(request):
            self.qcnt += 1
            response = dns.message.make_response(request)
            rrset = dns.rrset.from_text(request.question[0].name,
                                3600,
                                dns.rdataclass.IN,
                                dns.rdatatype.A,
                                '127.0.0.1')
            response.set_rcode(dns.rcode.REFUSED) if self.refuse else response.answer.append(rrset)
            return response.to_wire()
        return callback

class TestRoutingOrderedWRandUntag(DNSDistTest):

    _queryCounts = {}

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _testServer1Port = pickAvailablePort()
    _testServer2Port = pickAvailablePort()
    _testServer3Port = pickAvailablePort()
    _testServer4Port = pickAvailablePort()
    _serverPorts = [_testServer1Port, _testServer2Port, _testServer3Port, _testServer4Port]
    _config_params = ['_consoleKeyB64', '_consolePort', '_testServer1Port', '_testServer2Port', '_testServer3Port', '_testServer4Port']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    setServerPolicy(orderedWrandUntag)
    s11 = newServer{name="s11", address="127.0.0.1:%d", order=1, weight=1}
    s11:setUp()
    s12 = newServer{name="s12", address="127.0.0.1:%d", order=1, weight=2}
    s12:setUp()
    s21 = newServer{name="s21", address="127.0.0.1:%d", order=2, weight=1}
    s21:setUp()
    s22 = newServer{name="s22", address="127.0.0.1:%d", order=2, weight=2}
    s22:setUp()
    function setServerState(name, flag)
        for _, s in ipairs(getServers()) do
            if s.name == name then
                if flag then s:setUp() else s:setDown() end
            end
        end
    end
    function makeQueryRestartable(dq) dq:setRestartable() return DNSAction.None end
    addAction(AllRule(), LuaAction(makeQueryRestartable))
    function restartQuery(dr)
        dr:setTag(dr:getSelectedBackend():getNameWithAddr(), "1")
        dr:restart()
        return DNSResponseAction.None
    end
    addResponseAction(RCodeRule(DNSRCode.REFUSED), LuaResponseAction(restartQuery))
    """

    @classmethod
    def startResponders(cls):
        print("Launching responders..")

        for i, name in enumerate(['s11', 's12', 's21', 's22']):
            cls._queryCounts[name] = QueryCounter(name)
            cb = cls._queryCounts[name].create_cb()
            responder = threading.Thread(name=name, target=cls.UDPResponder, args=[cls._serverPorts[i], cls._toResponderQueue, cls._fromResponderQueue, False, cb])
            responder.daemon = True
            responder.start()

    def setServerUp(self, name):
        self.sendConsoleCommand("setServerState('{}', true)".format(name))

    def setServerDown(self, name):
        self.sendConsoleCommand("setServerState('{}', false)".format(name))

    def testPolicy(self):
        """
        Routing: orderedWrandUntag

        Send multiple A queries to "ordered.wrand.routing.tests.powerdns.com.",
        check that dnsdist routes based on order first then weighted.
        """
        numberOfQueries = 100
        name = 'ordered.wrand.routing.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        ### test normal first ordered then random weighted routing ###

        # send 100 queries
        for _ in range(numberOfQueries):
            (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # Only order 1 servers get queries and weighted
        self.assertGreater(self._queryCounts['s12'](),  numberOfQueries * 0.50)
        self.assertLess(self._queryCounts['s11'](),  numberOfQueries * 0.50)
        self.assertEqual(self._queryCounts['s21'](),  0)
        self.assertEqual(self._queryCounts['s22'](),  0)

        ### test tagged servers for restart

        # reset counters
        for name in ['s11', 's12', 's21', 's22']:
            self._queryCounts[name].reset()

        self._queryCounts['s11'].set_refuse(True)
        self.setServerDown('s12')

        # send 100 queries
        for _ in range(numberOfQueries):
            (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # s11 receives all 100 initial queries and always refuse to trigger restart
        # s12 is not selected for both initial and restarted queries
        # s21+s22 shall receive all the 100 restarted queries
        self.assertEqual(self._queryCounts['s11'](),  numberOfQueries)
        self.assertEqual(self._queryCounts['s12'](),  0)
        self.assertEqual(self._queryCounts['s21']()+self._queryCounts['s22'](), numberOfQueries)

        self._queryCounts['s11'].set_refuse(False)
        self.setServerUp('s12')

        ### further test server down conditions ###

        # reset counters
        for name in ['s11', 's12', 's21', 's22']:
            self._queryCounts[name].reset()

        self.setServerDown('s11')

        # send 100 queries
        for _ in range(numberOfQueries):
            (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # queries shall arrive 's12' only
        self.assertEqual(self._queryCounts['s11'](),  0)
        self.assertEqual(self._queryCounts['s12'](),  numberOfQueries)
        self.assertEqual(self._queryCounts['s21'](),  0)
        self.assertEqual(self._queryCounts['s22'](),  0)

        # reset counters
        for name in ['s11', 's12', 's21', 's22']:
            self._queryCounts[name].reset()

        self.setServerDown('s12')

        # send 100 queries
        for _ in range(numberOfQueries):
            (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # queries now shall be sent to order 2 servers and weighted
        self.assertEqual(self._queryCounts['s11'](),  0)
        self.assertEqual(self._queryCounts['s12'](),  0)
        self.assertLess(self._queryCounts['s21'](),  numberOfQueries * 0.50)
        self.assertGreater(self._queryCounts['s22'](),  numberOfQueries * 0.50)
