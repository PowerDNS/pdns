#!/usr/bin/env python
import base64
import dns
import threading
import time
import ssl

from dnsdisttests import DNSDistTest

class TestBackendDiscovery(DNSDistTest):
    _noSVCBackendPort = 10600
    _svcNoUpgradeBackendPort = 10601
    _svcUpgradeDoTBackendPort = 10602
    _svcUpgradeDoHBackendPort = 10603
    _svcUpgradeDoTBackendDifferentAddrPort1 = 10604
    _svcUpgradeDoTBackendDifferentAddrPort2 = 10605
    _svcUpgradeDoTUnreachableBackendPort = 10606
    _upgradedBackendsPool = 'upgraded'

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_noSVCBackendPort', '_svcNoUpgradeBackendPort', '_svcUpgradeDoTBackendPort', '_upgradedBackendsPool', '_svcUpgradeDoHBackendPort', '_svcUpgradeDoTBackendDifferentAddrPort1', '_svcUpgradeDoTBackendDifferentAddrPort2', '_svcUpgradeDoTUnreachableBackendPort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    setMaxTCPClientThreads(1)

    -- no SVCB
    newServer{address="127.0.0.1:%s", caStore='ca.pem', autoUpgrade=true, autoUpgradeKeep=false}:setUp()

    -- SVCB record but no upgrade path available
    newServer{address="127.0.0.1:%s", caStore='ca.pem', autoUpgrade=true, autoUpgradeKeep=false}:setUp()

    -- SVCB upgrade to DoT, same address, keep the backend, different pool
    newServer{address="127.0.0.1:%s", caStore='ca.pem', autoUpgrade=true, autoUpgradePool='%s', autoUpgradeKeep=true}:setUp()

    -- SVCB upgrade to DoH, same address, do not keep the backend, same pool
    newServer{address="127.0.0.1:%s", caStore='ca.pem', autoUpgrade=true, autoUpgradeKeep=false}:setUp()

    -- SVCB upgrade to DoT, different address, certificate is valid for the initial address
    newServer{address="127.0.0.1:%s", caStore='ca.pem', autoUpgrade=true, autoUpgradeKeep=false}:setUp()

    -- SVCB upgrade to DoT, different address, certificate is NOT valid for the initial address
    newServer{address="127.0.0.2:%s", caStore='ca.pem', autoUpgrade=true, autoUpgradeKeep=false}:setUp()

    -- SVCB upgrade to DoT but upgraded port is not reachable
    newServer{address="127.0.0.1:%s", caStore='ca.pem', autoUpgrade=true, autoUpgradeKeep=false}:setUp()
    """
    _verboseMode = True

    def NoSVCCallback(request):
        return dns.message.make_response(request).to_wire()

    def NoUpgradePathCallback(request):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(request.question[0].name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.SVCB,
                                    '1 no-upgrade. alpn="h3"')
        response.answer.append(rrset)
        return response.to_wire()

    def UpgradeDoTCallback(request):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(request.question[0].name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.SVCB,
                                    '1 tls.tests.dnsdist.org. alpn="dot" port=10652 ipv4hint=127.0.0.1')
        response.answer.append(rrset)
        return response.to_wire()

    def UpgradeDoHCallback(request):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(request.question[0].name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.SVCB,
                                    '1 tls.tests.dnsdist.org. alpn="h2" port=10653 ipv4hint=127.0.0.1 key7="/dns-query{?dns}"')
        response.answer.append(rrset)
        return response.to_wire()

    def UpgradeDoTDifferentAddr1Callback(request):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(request.question[0].name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.SVCB,
                                    '1 tls.tests.dnsdist.org. alpn="dot" port=10654 ipv4hint=127.0.0.2')
        response.answer.append(rrset)
        return response.to_wire()

    def UpgradeDoTDifferentAddr2Callback(request):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(request.question[0].name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.SVCB,
                                    '1 tls.tests.dnsdist.org. alpn="dot" port=10655 ipv4hint=127.0.0.1')
        response.answer.append(rrset)
        return response.to_wire()

    def UpgradeDoTUnreachableCallback(request):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(request.question[0].name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.SVCB,
                                    '1 tls.tests.dnsdist.org. alpn="dot" port=10656 ipv4hint=127.0.0.1')
        response.answer.append(rrset)
        return response.to_wire()

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        TCPNoSVCResponder = threading.Thread(name='TCP no SVC Responder', target=cls.TCPResponder, args=[cls._noSVCBackendPort, cls._toResponderQueue, cls._fromResponderQueue, True, False, cls.NoSVCCallback])
        TCPNoSVCResponder.setDaemon(True)
        TCPNoSVCResponder.start()

        TCPNoUpgradeResponder = threading.Thread(name='TCP no upgrade Responder', target=cls.TCPResponder, args=[cls._svcNoUpgradeBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.NoUpgradePathCallback])
        TCPNoUpgradeResponder.setDaemon(True)
        TCPNoUpgradeResponder.start()

        TCPUpgradeToDoTResponder = threading.Thread(name='TCP upgrade to DoT Responder', target=cls.TCPResponder, args=[cls._svcUpgradeDoTBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.UpgradeDoTCallback])
        TCPUpgradeToDoTResponder.setDaemon(True)
        TCPUpgradeToDoTResponder.start()
        # and the corresponding DoT responder
        UpgradedDoTResponder = threading.Thread(name='DoT upgraded Responder', target=cls.TCPResponder, args=[10652, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        UpgradedDoTResponder.setDaemon(True)
        UpgradedDoTResponder.start()

        TCPUpgradeToDoHResponder = threading.Thread(name='TCP upgrade to DoH Responder', target=cls.TCPResponder, args=[cls._svcUpgradeDoHBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.UpgradeDoHCallback])
        TCPUpgradeToDoHResponder.setDaemon(True)
        TCPUpgradeToDoHResponder.start()
        # and the corresponding DoH responder
        UpgradedDOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[10653, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        UpgradedDOHResponder.setDaemon(True)
        UpgradedDOHResponder.start()

        TCPUpgradeToDoTDifferentAddrResponder = threading.Thread(name='TCP upgrade to DoT different addr 1 Responder', target=cls.TCPResponder, args=[cls._svcUpgradeDoTBackendDifferentAddrPort1, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.UpgradeDoTDifferentAddr1Callback])
        TCPUpgradeToDoTDifferentAddrResponder.setDaemon(True)
        TCPUpgradeToDoTDifferentAddrResponder.start()
        # and the corresponding DoT responder
        UpgradedDoTResponder = threading.Thread(name='DoT upgraded different addr 1 Responder', target=cls.TCPResponder, args=[10654, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext, False, '127.0.0.2'])
        UpgradedDoTResponder.setDaemon(True)
        UpgradedDoTResponder.start()

        TCPUpgradeToDoTDifferentAddrResponder = threading.Thread(name='TCP upgrade to DoT different addr 2 Responder', target=cls.TCPResponder, args=[cls._svcUpgradeDoTBackendDifferentAddrPort2, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.UpgradeDoTDifferentAddr2Callback, None, False, '127.0.0.2'])
        TCPUpgradeToDoTDifferentAddrResponder.setDaemon(True)
        TCPUpgradeToDoTDifferentAddrResponder.start()
        # and the corresponding DoT responder
        UpgradedDoTResponder = threading.Thread(name='DoT upgraded different addr 2 Responder', target=cls.TCPResponder, args=[10655, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext, False])
        UpgradedDoTResponder.setDaemon(True)
        UpgradedDoTResponder.start()

        TCPUpgradeToUnreachableDoTResponder = threading.Thread(name='TCP upgrade to unreachable DoT Responder', target=cls.TCPResponder, args=[cls._svcUpgradeDoTUnreachableBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.UpgradeDoTUnreachableCallback])
        TCPUpgradeToUnreachableDoTResponder.setDaemon(True)
        TCPUpgradeToUnreachableDoTResponder.start()
        # and NO corresponding DoT responder
        # this is not a mistake!

    def checkBackendsUpgraded(self):
        output = self.sendConsoleCommand('showServers()')
        print(output)

        backends = {}
        for line in output.splitlines(False):
            if line.startswith('#') or line.startswith('All'):
                continue
            tokens = line.split()
            self.assertTrue(len(tokens) == 12 or len(tokens) == 13)
            self.assertEquals(tokens[2], 'UP')
            pool = ''
            if len(tokens) == 13:
                pool = tokens[12]
            backends[tokens[1]] = pool

        expected = {
            '127.0.0.1:10600': '',
            '127.0.0.1:10601': '',
            '127.0.0.1:10602': '',
            # 10603 has been upgraded to 10653 and removed
            # 10604 has been upgraded to 10654 and removed
            '127.0.0.2:10605': '',
            '127.0.0.1:10606': '',
            '127.0.0.1:10652': 'upgraded',
            '127.0.0.1:10653': '',
            '127.0.0.2:10654': ''
        }
        print(backends)
        return backends == expected

    def testBackendUpgrade(self):
        """
        Backend Discovery: Upgrade
        """

        # enough time for discovery to happen
        # 5s is not enough with TSAN
        time.sleep(10)
        if not self.checkBackendsUpgraded():
            # let's wait a bit longer
            time.sleep(5)
            self.assertTrue(self.checkBackendsUpgraded())
