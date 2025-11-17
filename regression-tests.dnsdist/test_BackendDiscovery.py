#!/usr/bin/env python
import base64
import dns
import threading
import time
import ssl

from dnsdisttests import DNSDistTest

class TestBackendDiscovery(DNSDistTest):
    # these ports are hardcoded for now, sorry about that!
    _noSVCBackendPort = 10600
    _svcNoUpgradeBackendPort = 10601
    _svcUpgradeDoTBackendPort = 10602
    _svcUpgradeDoHBackendPort = 10603
    _svcUpgradeDoTBackendDifferentAddrPort1 = 10604
    _svcUpgradeDoTBackendDifferentAddrPort2 = 10605
    _svcUpgradeDoTUnreachableBackendPort = 10606
    _svcBrokenDNSResponseBackendPort = 10607
    _svcUpgradeDoHBackendWithoutPathPort = 10608
    _connectionRefusedBackendPort = 10609
    _eofBackendPort = 10610
    _servfailBackendPort = 10611
    _wrongNameBackendPort = 10612
    _wrongIDBackendPort = 10613
    _tooManyQuestionsBackendPort = 10614
    _badQNameBackendPort = 10615
    _svcUpgradeDoTNoPortBackendPort = 10616
    _svcUpgradeDoHNoPortBackendPort = 10617
    _upgradedBackendsPool = 'upgraded'

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort', '_noSVCBackendPort', '_svcNoUpgradeBackendPort', '_svcUpgradeDoTBackendPort', '_upgradedBackendsPool', '_svcUpgradeDoHBackendPort', '_svcUpgradeDoTBackendDifferentAddrPort1', '_svcUpgradeDoTBackendDifferentAddrPort2', '_svcUpgradeDoTUnreachableBackendPort', '_svcBrokenDNSResponseBackendPort', '_svcUpgradeDoHBackendWithoutPathPort', '_connectionRefusedBackendPort', '_eofBackendPort', '_servfailBackendPort', '_wrongNameBackendPort', '_wrongIDBackendPort', '_tooManyQuestionsBackendPort', '_badQNameBackendPort', '_svcUpgradeDoTNoPortBackendPort', '_svcUpgradeDoHNoPortBackendPort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    setMaxTCPClientThreads(1)

    -- no SVCB
    newServer{address="127.0.0.1:%d", caStore='ca.pem', autoUpgrade=true, autoUpgradeKeep=false}:setUp()

    -- SVCB record but no upgrade path available
    newServer{address="127.0.0.1:%d", caStore='ca.pem', autoUpgrade=true, autoUpgradeKeep=false}:setUp()

    -- SVCB upgrade to DoT, same address, keep the backend, different pool
    newServer{address="127.0.0.1:%d", caStore='ca.pem', pool={'', 'another-pool'}, autoUpgrade=true, autoUpgradePool='%s', autoUpgradeKeep=true, source='127.0.0.1@lo'}:setUp()

    -- SVCB upgrade to DoH, same address, do not keep the backend, same pool
    newServer{address="127.0.0.1:%d", caStore='ca.pem', pool={'another-pool'}, autoUpgrade=true, autoUpgradeKeep=false}:setUp()

    -- SVCB upgrade to DoT, different address, certificate is valid for the initial address
    newServer{address="127.0.0.1:%d", caStore='ca.pem', autoUpgrade=true, autoUpgradeKeep=false}:setUp()

    -- SVCB upgrade to DoT, different address, certificate is NOT valid for the initial address
    newServer{address="127.0.0.2:%d", caStore='ca.pem', autoUpgrade=true, autoUpgradeKeep=false}:setUp()

    -- SVCB upgrade to DoT but upgraded port is not reachable
    newServer{address="127.0.0.1:%d", caStore='ca.pem', autoUpgrade=true, autoUpgradeKeep=false}:setUp()

    -- The SVCB response is not valid
    newServer{address="127.0.0.1:%d", caStore='ca.pem', autoUpgrade=true, autoUpgradeKeep=false}:setUp()

    -- SVCB upgrade to DoH except the path is not specified
    newServer{address="127.0.0.1:%d", caStore='ca.pem', autoUpgrade=true, autoUpgradeKeep=false}:setUp()

    -- Connection refused
    newServer({address="127.0.0.1:%d", caStore='ca.pem', pool={"", "other-pool"}, autoUpgrade=true, source='127.0.0.1@lo'}):setUp()

    -- EOF
    newServer({address="127.0.0.1:%d", caStore='ca.pem', autoUpgrade=true}):setUp()

    -- ServFail
    newServer({address="127.0.0.1:%d", autoUpgrade=true}):setUp()

    -- Wrong name
    newServer({address="127.0.0.1:%d", autoUpgrade=true}):setUp()

    -- Wrong ID
    newServer({address="127.0.0.1:%d", autoUpgrade=true}):setUp()

    -- Too many questions
    newServer({address="127.0.0.1:%d", autoUpgrade=true}):setUp()

    -- Bad QName
    newServer({address="127.0.0.1:%d", autoUpgrade=true}):setUp()

    -- SVCB upgrade to DoT, same address, no port specified via SVCB
    newServer{address="127.0.0.1:%d", caStore='ca.pem', autoUpgrade=true, autoUpgradeKeep=false}:setUp()

    -- SVCB upgrade to DoH, same address, no port specified via SVCB
    newServer{address="127.0.0.1:%d", caStore='ca.pem', autoUpgrade=true, autoUpgradeKeep=false}:setUp()
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
        # add a useless A record for good measure
        rrset = dns.rrset.from_text(request.question[0].name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)
        # plus more useless records in authority
        rrset = dns.rrset.from_text(request.question[0].name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.authority.append(rrset)
        # and finally valid, albeit useless, hints
        rrset = dns.rrset.from_text('tls.tests.dnsdist.org.',
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.additional.append(rrset)
        rrset = dns.rrset.from_text('tls.tests.dnsdist.org.',
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    '::1')
        response.additional.append(rrset)
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

    def BrokenResponseCallback(request):
        response = dns.message.make_response(request)
        response.use_edns(edns=False)
        response.question = []
        return response.to_wire()

    def UpgradeDoHMissingPathCallback(request):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(request.question[0].name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.SVCB,
                                    '1 tls.tests.dnsdist.org. alpn="h2" port=10653 ipv4hint=127.0.0.1')
        response.answer.append(rrset)
        return response.to_wire()

    def EOFCallback(request):
        return None

    def ServFailCallback(request):
        response = dns.message.make_response(request)
        response.set_rcode(dns.rcode.SERVFAIL)
        return response.to_wire()

    def WrongNameCallback(request):
        query = dns.message.make_query('not-the-right-one.', dns.rdatatype.SVCB)
        response = dns.message.make_response(query)
        response.id = request.id
        return response.to_wire()

    def WrongIDCallback(request):
        response = dns.message.make_response(request)
        response.id = request.id ^ 42
        return response.to_wire()

    def TooManyQuestionsCallback(self):
        response = dns.message.make_response(self)
        response.question.append(response.question[0])
        return response.to_wire()

    def BadQNameCallback(self):
        response = dns.message.make_response(self)
        wire = bytearray(response.to_wire())
        # mess up the first label length
        wire[12] = 0xFF
        return wire

    def UpgradeDoTNoPortCallback(self):
        response = dns.message.make_response(self)
        rrset = dns.rrset.from_text(self.question[0].name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.SVCB,
                                    '1 tls.tests.dnsdist.org. alpn="dot" ipv4hint=127.0.0.1')
        response.answer.append(rrset)
        return response.to_wire()

    def UpgradeDoHNoPortCallback(self):
        response = dns.message.make_response(self)
        rrset = dns.rrset.from_text(self.question[0].name,
                                    60,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.SVCB,
                                    '1 tls.tests.dnsdist.org. alpn="h2" ipv4hint=127.0.0.1 key7="/dns-query{?dns}"')
        response.answer.append(rrset)
        return response.to_wire()

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')

        TCPNoSVCResponder = threading.Thread(name='TCP no SVC Responder', target=cls.TCPResponder, args=[cls._noSVCBackendPort, cls._toResponderQueue, cls._fromResponderQueue, True, False, cls.NoSVCCallback])
        TCPNoSVCResponder.daemon = True
        TCPNoSVCResponder.start()

        TCPNoUpgradeResponder = threading.Thread(name='TCP no upgrade Responder', target=cls.TCPResponder, args=[cls._svcNoUpgradeBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.NoUpgradePathCallback])
        TCPNoUpgradeResponder.daemon = True
        TCPNoUpgradeResponder.start()

        # this one is special, does partial writes!
        TCPUpgradeToDoTResponder = threading.Thread(name='TCP upgrade to DoT Responder', target=cls.TCPResponder, args=[cls._svcUpgradeDoTBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.UpgradeDoTCallback, None, False, '127.0.0.1', True])
        TCPUpgradeToDoTResponder.daemon = True
        TCPUpgradeToDoTResponder.start()
        # and the corresponding DoT responder
        UpgradedDoTResponder = threading.Thread(name='DoT upgraded Responder', target=cls.TCPResponder, args=[10652, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        UpgradedDoTResponder.daemon = True
        UpgradedDoTResponder.start()

        TCPUpgradeToDoHResponder = threading.Thread(name='TCP upgrade to DoH Responder', target=cls.TCPResponder, args=[cls._svcUpgradeDoHBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.UpgradeDoHCallback])
        TCPUpgradeToDoHResponder.daemon = True
        TCPUpgradeToDoHResponder.start()
        # and the corresponding DoH responder
        UpgradedDOHResponder = threading.Thread(name='DOH Responder', target=cls.DOHResponder, args=[10653, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        UpgradedDOHResponder.daemon = True
        UpgradedDOHResponder.start()

        TCPUpgradeToDoTDifferentAddrResponder = threading.Thread(name='TCP upgrade to DoT different addr 1 Responder', target=cls.TCPResponder, args=[cls._svcUpgradeDoTBackendDifferentAddrPort1, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.UpgradeDoTDifferentAddr1Callback])
        TCPUpgradeToDoTDifferentAddrResponder.daemon = True
        TCPUpgradeToDoTDifferentAddrResponder.start()
        # and the corresponding DoT responder
        UpgradedDoTResponder = threading.Thread(name='DoT upgraded different addr 1 Responder', target=cls.TCPResponder, args=[10654, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext, False, '127.0.0.2'])
        UpgradedDoTResponder.daemon = True
        UpgradedDoTResponder.start()

        TCPUpgradeToDoTDifferentAddrResponder = threading.Thread(name='TCP upgrade to DoT different addr 2 Responder', target=cls.TCPResponder, args=[cls._svcUpgradeDoTBackendDifferentAddrPort2, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.UpgradeDoTDifferentAddr2Callback, None, False, '127.0.0.2'])
        TCPUpgradeToDoTDifferentAddrResponder.daemon = True
        TCPUpgradeToDoTDifferentAddrResponder.start()
        # and the corresponding DoT responder
        UpgradedDoTResponder = threading.Thread(name='DoT upgraded different addr 2 Responder', target=cls.TCPResponder, args=[10655, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext, False])
        UpgradedDoTResponder.daemon = True
        UpgradedDoTResponder.start()

        TCPUpgradeToUnreachableDoTResponder = threading.Thread(name='TCP upgrade to unreachable DoT Responder', target=cls.TCPResponder, args=[cls._svcUpgradeDoTUnreachableBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.UpgradeDoTUnreachableCallback])
        TCPUpgradeToUnreachableDoTResponder.daemon = True
        TCPUpgradeToUnreachableDoTResponder.start()
        # and NO corresponding DoT responder
        # this is not a mistake!

        BrokenResponseResponder = threading.Thread(name='Broken response Responder', target=cls.TCPResponder, args=[cls._svcBrokenDNSResponseBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.BrokenResponseCallback])
        BrokenResponseResponder.daemon = True
        BrokenResponseResponder.start()

        DOHMissingPathResponder = threading.Thread(name='DoH missing path Responder', target=cls.TCPResponder, args=[cls._svcUpgradeDoHBackendWithoutPathPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.UpgradeDoHMissingPathCallback])
        DOHMissingPathResponder.daemon = True
        DOHMissingPathResponder.start()

        EOFResponder = threading.Thread(name='EOF Responder', target=cls.TCPResponder, args=[cls._eofBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.EOFCallback])
        EOFResponder.daemon = True
        EOFResponder.start()

        ServFailResponder = threading.Thread(name='ServFail Responder', target=cls.TCPResponder, args=[cls._servfailBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.ServFailCallback])
        ServFailResponder.daemon = True
        ServFailResponder.start()

        WrongNameResponder = threading.Thread(name='Wrong Name Responder', target=cls.TCPResponder, args=[cls._wrongNameBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.WrongNameCallback])
        WrongNameResponder.daemon = True
        WrongNameResponder.start()

        WrongIDResponder = threading.Thread(name='Wrong ID Responder', target=cls.TCPResponder, args=[cls._wrongIDBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.WrongIDCallback])
        WrongIDResponder.daemon = True
        WrongIDResponder.start()

        TooManyQuestionsResponder = threading.Thread(name='Too many questions Responder', target=cls.TCPResponder, args=[cls._tooManyQuestionsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.TooManyQuestionsCallback])
        TooManyQuestionsResponder.daemon = True
        TooManyQuestionsResponder.start()

        badQNameResponder = threading.Thread(name='Bad QName Responder', target=cls.TCPResponder, args=[cls._badQNameBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.BadQNameCallback])
        badQNameResponder.daemon = True
        badQNameResponder.start()

        TCPUpgradeToDoTNoPortResponder = threading.Thread(name='TCP upgrade to DoT (no port) Responder', target=cls.TCPResponder, args=[cls._svcUpgradeDoTNoPortBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.UpgradeDoTNoPortCallback])
        TCPUpgradeToDoTNoPortResponder.daemon = True
        TCPUpgradeToDoTNoPortResponder.start()

        TCPUpgradeToDoHNoPortResponder = threading.Thread(name='TCP upgrade to DoH (no port) Responder', target=cls.TCPResponder, args=[cls._svcUpgradeDoHNoPortBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.UpgradeDoHNoPortCallback])
        TCPUpgradeToDoHNoPortResponder.daemon = True
        TCPUpgradeToDoHNoPortResponder.start()


    def checkBackendsUpgraded(self):
        output = self.sendConsoleCommand('showServers()')
        print(output)

        backends = {}
        for line in output.splitlines(False):
            if line.startswith('#') or line.startswith('All'):
                continue
            tokens = line.split()
            self.assertTrue(len(tokens) == 13 or len(tokens) == 14)
            if tokens[1] == '127.0.0.1:10652':
                # in this particular case, the upgraded backend
                # does not replace the existing one and thus
                # the health-check is forced to auto (or lazy auto)
                self.assertEqual(tokens[2], 'up')
            else:
                self.assertEqual(tokens[2], 'UP')
            pool = ''
            if len(tokens) == 14:
                pool = tokens[13]
            backends[tokens[1]] = pool

        expected = {
            '127.0.0.1:10600': '',
            '127.0.0.1:10601': '',
            '127.0.0.1:10602': 'another-pool',
            # 10603 has been upgraded to 10653 and removed
            # 10604 has been upgraded to 10654 and removed
            '127.0.0.2:10605': '',
            '127.0.0.1:10606': '',
            '127.0.0.1:10607': '',
            '127.0.0.1:10608': '',
            '127.0.0.1:10609': 'other-pool',
            '127.0.0.1:10610': '',
            '127.0.0.1:10611': '',
            '127.0.0.1:10612': '',
            '127.0.0.1:10613': '',
            '127.0.0.1:10614': '',
            '127.0.0.1:10615': '',
            # these two are not upgraded because there is no backend listening on the default ports (443 and 853)
            '127.0.0.1:10616': '',
            '127.0.0.1:10617': '',
            '127.0.0.1:10652': 'upgraded',
            '127.0.0.1:10653': 'another-pool',
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

class TestBackendDiscoveryByHostname(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _config_params = ['_consoleKeyB64', '_consolePort']
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    setVerboseHealthChecks(true)

    function resolveCB(hostname, ips)
      print('Got response for '..hostname)
      for _, ip in ipairs(ips) do
        print(ip)
        newServer(ip:toString())
      end
    end

    getAddressInfo('dns.quad9.net.', resolveCB)
    """
    _verboseMode = True

    def checkBackends(self):
        output = self.sendConsoleCommand('showServers()')
        print(output)
        backends = {}
        for line in output.splitlines(False):
            if line.startswith('#') or line.startswith('All'):
                continue
            tokens = line.split()
            self.assertTrue(len(tokens) == 13 or len(tokens) == 14)
            backends[tokens[1]] = tokens[2]

        if len(backends) == 4:
            for expected in ['9.9.9.9:53', '149.112.112.112:53', '[2620:fe::9]:53', '[2620:fe::fe]:53']:
                self.assertIn(expected, backends)
        elif len(backends) == 2:
            # looks like we are not getting the IPv6 addresses, thanks GitHub!
            for expected in ['9.9.9.9:53', '149.112.112.112:53']:
                self.assertIn(expected, backends)
        else:
            return False

        for backend in backends:
            if str(backend) in ['2620:fe::9]:53', '[2620:fe::fe]:53']:
                # IPv6 is very flaky on GH actions these days (202505),
                # let's not require these to be up
                continue
            if backends[backend] != 'up':
                return False

        return True

    def testBackendFromHostname(self):
        """
        Backend Discovery: From hostname
        """
        # enough time for resolution to happen
        time.sleep(4)
        if not self.checkBackends():
            valid = False
            for _ in range(8):
                time.sleep(0.5)
                if self.checkBackends():
                    valid = True
                    break
            self.assertTrue(valid)
