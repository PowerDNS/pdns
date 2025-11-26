#!/usr/bin/env python
from queue import Queue
import threading
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort
from proxyprotocolutils import ProxyProtocolUDPResponder, ProxyProtocolTCPResponder


def servFailResponseCallback(request):
    response = dns.message.make_response(request)
    response.set_rcode(dns.rcode.SERVFAIL)
    return response.to_wire()


def normalResponseCallback(request):
    response = dns.message.make_response(request)
    rrset = dns.rrset.from_text(request.question[0].name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
    response.answer.append(rrset)
    return response.to_wire()


class TestRestartQuery(DNSDistTest):
    # this test suite uses different responder ports
    _testNormalServerPort = pickAvailablePort()
    _testServfailServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%d", pool='restarted'}:setUp()
    newServer{address="127.0.0.1:%d", pool=''}:setUp()

    function makeQueryRestartable(dq)
      dq:setRestartable()
      return DNSAction.None
    end

    function restartOnServFail(dr)
      if dr.rcode == DNSRCode.SERVFAIL then
        dr.pool = 'restarted'
        dr:restart()
      end

      return DNSResponseAction.None
    end

    addAction(AllRule(), LuaAction(makeQueryRestartable))
    addResponseAction(AllRule(), LuaResponseAction(restartOnServFail))
    """
    _config_params = ["_testNormalServerPort", "_testServfailServerPort"]
    _verboseMode = True

    @classmethod
    def startResponders(cls):
        print("Launching responders..")

        # servfail
        cls._UDPResponder = threading.Thread(
            name="UDP Responder",
            target=cls.UDPResponder,
            args=[
                cls._testServfailServerPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                servFailResponseCallback,
            ],
        )
        cls._UDPResponder.daemon = True
        cls._UDPResponder.start()
        cls._TCPResponder = threading.Thread(
            name="TCP Responder",
            target=cls.TCPResponder,
            args=[
                cls._testServfailServerPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                servFailResponseCallback,
            ],
        )
        cls._TCPResponder.daemon = True
        cls._TCPResponder.start()
        cls._UDPResponderNormal = threading.Thread(
            name="UDP ResponderNormal",
            target=cls.UDPResponder,
            args=[
                cls._testNormalServerPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                normalResponseCallback,
            ],
        )
        cls._UDPResponderNormal.daemon = True
        cls._UDPResponderNormal.start()
        cls._TCPResponderNormal = threading.Thread(
            name="TCP ResponderNormal",
            target=cls.TCPResponder,
            args=[
                cls._testNormalServerPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                normalResponseCallback,
            ],
        )
        cls._TCPResponderNormal.daemon = True
        cls._TCPResponderNormal.start()

    def testRestartingQuery(self):
        """
        Restart: ServFail then restarted to a second pool
        """
        name = "restart.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        expectedResponse = dns.message.make_response(query)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(receivedResponse, expectedResponse)


toProxyQueue = Queue()
fromProxyQueue = Queue()
proxyResponderPort = pickAvailablePort()

udpResponder = threading.Thread(
    name="UDP Proxy Protocol Responder",
    target=ProxyProtocolUDPResponder,
    args=[proxyResponderPort, toProxyQueue, fromProxyQueue],
)
udpResponder.daemon = True
udpResponder.start()
tcpResponder = threading.Thread(
    name="TCP Proxy Protocol Responder",
    target=ProxyProtocolTCPResponder,
    args=[proxyResponderPort, toProxyQueue, fromProxyQueue],
)
tcpResponder.daemon = True
tcpResponder.start()


class TestRestartProxyProtocolThenNot(DNSDistTest):
    _restartPool = "restart-pool"
    _config_template = """
    fallbackPool = '%s'
    newServer{address="127.0.0.1:%d", useProxyProtocol=true}
    newServer{address="127.0.0.1:%d", pool={fallbackPool}}

    local function makeQueryRestartable(dq)
      dq:setRestartable()
      return DNSAction.None
    end

    local function restart(dr)
      if dr.pool ~= fallbackPool then
        dr.pool = fallbackPool
        dr:restart()
      end

      return DNSResponseAction.None
    end

    addAction(AllRule(), LuaAction(makeQueryRestartable))
    addResponseAction(AllRule(), LuaResponseAction(restart))
    """
    _proxyResponderPort = proxyResponderPort
    _config_params = ["_restartPool", "_proxyResponderPort", "_testServerPort"]

    def testRestart(self):
        """
        Restart: queries is first forwarded to proxy-protocol enabled backend, then restarted to a non-PP backend
        """
        name = "proxy.restart.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        response = dns.message.make_response(query)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            # push a response to the first backend
            toProxyQueue.put(response, True, 2.0)

            sender = getattr(self, method)
            # we get the query received by the second backend, and the
            # response received from dnsdist
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

            # pop the query received by the first backend
            (receivedProxyPayload, receivedDNSData) = fromProxyQueue.get(True, 2.0)
            self.assertTrue(receivedProxyPayload)
            self.assertTrue(receivedDNSData)


class QueryCounter:
    def __init__(self, name):
        self.name = name
        self.qcnt = 0

    def __call__(self):
        return self.qcnt

    def create_cb(self):
        def callback(request):
            self.qcnt += 1
            response = dns.message.make_response(request)
            response.set_rcode(dns.rcode.REFUSED)
            return response.to_wire()

        return callback


class TestRestartCount(DNSDistTest):
    _queryCounts = {}

    _testServer1Port = pickAvailablePort()
    _testServer2Port = pickAvailablePort()
    _testServer3Port = pickAvailablePort()
    _testServer4Port = pickAvailablePort()
    _serverPorts = [_testServer1Port, _testServer2Port, _testServer3Port, _testServer4Port]
    _config_params = ["_testServer1Port", "_testServer2Port", "_testServer3Port", "_testServer4Port"]
    _config_template = """
    MaxRestart = 2
    s0 = newServer{name="s0", address="127.0.0.1:%d"}
    s0:setUp()
    s0:addPool("pool0")
    s1 = newServer{name="s1", address="127.0.0.1:%d"}
    s1:setUp()
    s1:addPool("pool1")
    s2 = newServer{name="s2", address="127.0.0.1:%d"}
    s2:setUp()
    s2:addPool("pool2")
    s3 = newServer{name="s3", address="127.0.0.1:%d"}
    s3:setUp()
    s3:addPool("pool3")
    function makeQueryRestartable(dq) dq:setRestartable() return DNSAction.None end
    addAction(AllRule(), LuaAction(makeQueryRestartable))
    function restartQuery(dr)
        if dr:getRestartCount() < MaxRestart then
            dr.pool = "pool"..tostring(dr:getRestartCount() + 1)
            dr:restart()
        else
            return DNSResponseAction.ServFail
        end
        return DNSResponseAction.None
    end
    addResponseAction(RCodeRule(DNSRCode.REFUSED), LuaResponseAction(restartQuery))
    addAction(AllRule(), PoolAction("pool0"))
    """

    @classmethod
    def startResponders(cls):
        print("Launching responders..")

        for i, name in enumerate(["s0", "s1", "s2", "s3"]):
            cls._queryCounts[name] = QueryCounter(name)
            cb = cls._queryCounts[name].create_cb()
            responder = threading.Thread(
                name=name,
                target=cls.UDPResponder,
                args=[cls._serverPorts[i], cls._toResponderQueue, cls._fromResponderQueue, False, cb],
            )
            responder.daemon = True
            responder.start()

    def testDefault(self):
        numberOfQueries = 100
        name = "restart.count.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        expectedResponse = dns.message.make_response(query)
        expectedResponse.set_rcode(dns.rcode.SERVFAIL)

        # send 100 queries
        for _ in range(numberOfQueries):
            (_, receivedResponse) = self.sendUDPQuery(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # if restart count is correct, s0/s1/s2 would get all the queies while s3 would get none
        self.assertEqual(self._queryCounts["s0"](), numberOfQueries)
        self.assertEqual(self._queryCounts["s1"](), numberOfQueries)
        self.assertEqual(self._queryCounts["s2"](), numberOfQueries)
        self.assertEqual(self._queryCounts["s3"](), 0)
