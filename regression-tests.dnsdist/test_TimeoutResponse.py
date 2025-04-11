#!/usr/bin/env python
import ssl
import threading
import dns
from dnsdisttests import DNSDistTest, pickAvailablePort, ResponderDropAction

_common_config = """
    addDOHLocal("127.0.0.1:%d", "server.chain", "server.key", {'/dns-query'}, {library='nghttp2'})
    addDOQLocal("127.0.0.1:%d", "server.chain", "server.key")
    addDOH3Local("127.0.0.1:%d", "server.chain", "server.key")
    addTLSLocal("127.0.0.1:%d", "server.chain", "server.key")

    function makeQueryRestartable(dq)
      dq:setRestartable()
      return DNSAction.None
    end

    function restartQuery(dr)
      if dr.pool ~= 'restarted' then
        dr.pool = 'restarted'
        dr:restart()
      end
      return DNSResponseAction.None
    end

    addAction(AllRule(), LuaAction(makeQueryRestartable))
    addTimeoutResponseAction(AllRule(), LuaResponseAction(restartQuery))
"""

def timeoutResponseCallback(request):
    return ResponderDropAction()

def normalResponseCallback(request):
    response = dns.message.make_response(request)
    rrset = dns.rrset.from_text(request.question[0].name,
                                3600,
                                dns.rdataclass.IN,
                                dns.rdatatype.A,
                                '127.0.0.1')
    response.answer.append(rrset)
    return response.to_wire()

def dohTimeoutResponseCallback(request, headers, fromQueue, toQueue):
    return 200, timeoutResponseCallback(request)

def dohNormalResponseCallback(request, headers, fromQueue, toQueue):
    return 200, normalResponseCallback(request)

class TestTimeoutBackendUdpTcp(DNSDistTest):

    # this test suite uses different responder ports
    _testNormalServerPort = pickAvailablePort()
    _testTimeoutServerPort = pickAvailablePort()
    _dohWithNGHTTP2ServerPort = pickAvailablePort()
    _doqServerPort = pickAvailablePort()
    _doh3ServerPort = pickAvailablePort()
    _tlsServerPort = pickAvailablePort()

    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    _dohWithNGHTTP2BaseURL =  ("https://%s:%d/dns-query" % ("127.0.0.1", _dohWithNGHTTP2ServerPort))
    _dohBaseURL = ("https://%s:%d/" % (_serverName, _doh3ServerPort))

    _config_template = """
    newServer{address="127.0.0.1:%d",pool='restarted',udpTimeout=1,tcpRecvTimeout=1}:setUp()
    newServer{address="127.0.0.1:%d",pool='',udpTimeout=1,tcpRecvTimeout=1}:setUp()
    """ + _common_config
    _config_params = ['_testNormalServerPort', '_testTimeoutServerPort', '_dohWithNGHTTP2ServerPort', '_doqServerPort', '_doh3ServerPort', '_tlsServerPort']
    _verboseMode = True

    @classmethod
    def startResponders(cls):
        print("Launching responders..")

        # timeout
        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testTimeoutServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, timeoutResponseCallback])
        cls._UDPResponder.daemon = True
        cls._UDPResponder.start()
        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testTimeoutServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, timeoutResponseCallback])
        cls._TCPResponder.daemon = True
        cls._TCPResponder.start()
        cls._UDPResponderNormal = threading.Thread(name='UDP ResponderNormal', target=cls.UDPResponder, args=[cls._testNormalServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, normalResponseCallback])
        cls._UDPResponderNormal.daemon = True
        cls._UDPResponderNormal.start()
        cls._TCPResponderNormal = threading.Thread(name='TCP ResponderNormal', target=cls.TCPResponder, args=[cls._testNormalServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, normalResponseCallback])
        cls._TCPResponderNormal.daemon = True
        cls._TCPResponderNormal.start()

    def testTimeoutRestartQuery(self):
        """
        Restart: Timeout then restarted to a second pool
        """
        name = 'timeout.restart.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse = dns.message.make_response(query)
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery", "sendDOQQueryWrapper", "sendDOH3QueryWrapper", "sendDOTQueryWrapper", "sendDOHWithNGHTTP2QueryWrapper"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False, timeout=3)
            self.assertTrue(receivedResponse)
            self.assertEqual(receivedResponse, expectedResponse)

class TestTimeoutBackendDOH(TestTimeoutBackendUdpTcp):

    _config_template = """
    newServer{address="127.0.0.1:%d",pool='restarted',udpTimeout=1,tcpRecvTimeout=1,tls='openssl',validateCertificates=true,caStore='ca.pem',subjectName='powerdns.com',dohPath='/dns-query'}:setUp()
    newServer{address="127.0.0.1:%d",pool='',udpTimeout=1,tcpRecvTimeout=1,tls='openssl',validateCertificates=true,caStore='ca.pem',subjectName='powerdns.com',dohPath='/dns-query'}:setUp()
    """ + _common_config

    @classmethod
    def startResponders(cls):

        # timeout
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching DOH responder..")
        cls._DOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[cls._testTimeoutServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, dohTimeoutResponseCallback, tlsContext])
        cls._DOHResponder.daemon = True
        cls._DOHResponder.start()

        cls._DOHResponder = threading.Thread(name='DOH ResponderNormal', target=cls.DOHResponder, args=[cls._testNormalServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, dohNormalResponseCallback, tlsContext])
        cls._DOHResponder.daemon = True
        cls._DOHResponder.start()

class TestTimeoutBackendDOT(TestTimeoutBackendUdpTcp):

    _config_template = """
    newServer{address="127.0.0.1:%d",pool='restarted',udpTimeout=1,tcpRecvTimeout=1,tls='openssl',validateCertificates=true,caStore='ca.pem',subjectName='powerdns.com'}:setUp()
    newServer{address="127.0.0.1:%d",pool='',udpTimeout=1,tcpRecvTimeout=1,tls='openssl',validateCertificates=true,caStore='ca.pem',subjectName='powerdns.com'}:setUp()
    """ + _common_config

    @classmethod
    def startResponders(cls):

        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._testTimeoutServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, timeoutResponseCallback, tlsContext])
        cls._TLSResponder.daemon = True
        cls._TLSResponder.start()

        cls._TLSResponder = threading.Thread(name='TLS ResponderNormal', target=cls.TCPResponder, args=[cls._testNormalServerPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, normalResponseCallback, tlsContext])
        cls._TLSResponder.daemon = True
        cls._TLSResponder.start()
