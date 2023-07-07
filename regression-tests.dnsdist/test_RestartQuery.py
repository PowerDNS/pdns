#!/usr/bin/env python
import threading
import clientsubnetoption
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort

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
 
