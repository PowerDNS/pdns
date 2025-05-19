#!/usr/bin/env python
from queue import Queue
import threading
import clientsubnetoption
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort
from proxyprotocolutils import ProxyProtocolUDPResponder, ProxyProtocolTCPResponder

def servFailResponseCallback(request):
    response = dns.message.make_response(request)
    response.set_rcode(dns.rcode.SERVFAIL)
    return response.to_wire()

def normalResponseCallback(request):
    response = dns.message.make_response(request)
    rrset = dns.rrset.from_text(request.question[0].name,
                                3600,
                                dns.rdataclass.IN,
                                dns.rdatatype.A,
                                '127.0.0.1')
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
    _config_params = ['_testNormalServerPort', '_testServfailServerPort']
    _verboseMode = True

    @classmethod
    def startResponders(cls):
        print("Launching responders..")

        # servfail
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServfailServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, servFailResponseCallback])
        cls._UDPResponder.daemon = True
        cls._UDPResponder.start()
        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServfailServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, servFailResponseCallback])
        cls._TCPResponder.daemon = True
        cls._TCPResponder.start()
        cls._UDPResponderNormal = threading.Thread(name='UDP ResponderNormal', target=cls.UDPResponder, args=[cls._testNormalServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, normalResponseCallback])
        cls._UDPResponderNormal.daemon = True
        cls._UDPResponderNormal.start()
        cls._TCPResponderNormal = threading.Thread(name='TCP ResponderNormal', target=cls.TCPResponder, args=[cls._testNormalServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, normalResponseCallback])
        cls._TCPResponderNormal.daemon = True
        cls._TCPResponderNormal.start()

    def testRestartingQuery(self):
        """
        Restart: ServFail then restarted to a second pool
        """
        name = 'restart.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
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

udpResponder = threading.Thread(name='UDP Proxy Protocol Responder', target=ProxyProtocolUDPResponder, args=[proxyResponderPort, toProxyQueue, fromProxyQueue])
udpResponder.daemon = True
udpResponder.start()
tcpResponder = threading.Thread(name='TCP Proxy Protocol Responder', target=ProxyProtocolTCPResponder, args=[proxyResponderPort, toProxyQueue, fromProxyQueue])
tcpResponder.daemon = True
tcpResponder.start()

class TestRestartProxyProtocolThenNot(DNSDistTest):
    _restartPool = 'restart-pool'
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
    _config_params = ['_restartPool', '_proxyResponderPort', '_testServerPort']

    def testRestart(self):
        """
        Restart: queries is first forwarded to proxy-protocol enabled backend, then restarted to a non-PP backend
        """
        name = 'proxy.restart.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
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
