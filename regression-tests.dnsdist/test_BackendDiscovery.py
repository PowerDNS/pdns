#!/usr/bin/env python
import base64
import dns
import threading
import time
import ssl

from dnsdisttests import DNSDistTest, pickAvailablePort


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
    _svcUpgradeDoTThenRedirect = 10618
    _svcUpgradeDoHThenRedirect = 10619
    _svcUpgradeDoHThenRedirectIntoFailure = 10620
    _svcUpgradeDoTThenRedirectLoop = 10621
    _svcUpgradeDoTRedirectAndKeep = 10622
    _upgradedBackendsPool = "upgraded"

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")
    _consolePort = pickAvailablePort()
    _config_params = [
        "_consoleKeyB64",
        "_consolePort",
        "_noSVCBackendPort",
        "_svcNoUpgradeBackendPort",
        "_svcUpgradeDoTBackendPort",
        "_upgradedBackendsPool",
        "_svcUpgradeDoHBackendPort",
        "_svcUpgradeDoTBackendDifferentAddrPort1",
        "_svcUpgradeDoTBackendDifferentAddrPort2",
        "_svcUpgradeDoTUnreachableBackendPort",
        "_svcBrokenDNSResponseBackendPort",
        "_svcUpgradeDoHBackendWithoutPathPort",
        "_connectionRefusedBackendPort",
        "_eofBackendPort",
        "_servfailBackendPort",
        "_wrongNameBackendPort",
        "_wrongIDBackendPort",
        "_tooManyQuestionsBackendPort",
        "_badQNameBackendPort",
        "_svcUpgradeDoTNoPortBackendPort",
        "_svcUpgradeDoHNoPortBackendPort",
        "_svcUpgradeDoTThenRedirect",
        "_svcUpgradeDoHThenRedirect",
        "_svcUpgradeDoHThenRedirectIntoFailure",
        "_svcUpgradeDoTThenRedirectLoop",
        "_svcUpgradeDoTRedirectAndKeep",
    ]
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

    -- SVCB upgrade to DoT, then redirect from upgraded
    newServer{address="127.0.0.1:%d", caStore='ca.pem', autoUpgrade=true, enableRedirection=true}:setUp()

    -- SVCB upgrade to DoH, then redirect from upgraded
    newServer{address="127.0.0.1:%d", caStore='ca.pem', autoUpgrade=true, enableRedirection=true}:setUp()

    -- SVCB upgrade to DoH, then redirect from upgraded into failure, so
    -- upgraded should be kept
    newServer{address="127.0.0.1:%d", caStore='ca.pem', autoUpgrade=true, enableRedirection=true}:setUp()

    -- SVCB upgrade to DoT, then redirect into loop, which should be stopped
    newServer{address="127.0.0.1:%d", caStore='ca.pem', autoUpgrade=true, enableRedirection=true}:setUp()

    -- SVCB upgrade to DoT, then redirect and keep
    newServer{address="127.0.0.1:%d", caStore='ca.pem', autoUpgrade=true, enableRedirection=true, redirectionKeep=true}:setUp()
    """
    _verboseMode = True

    @staticmethod
    def NoSVCCallback(request):
        return dns.message.make_response(request).to_wire()

    @staticmethod
    def NoUpgradePathCallback(request):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(
            request.question[0].name, 60, dns.rdataclass.IN, dns.rdatatype.SVCB, '1 no-upgrade. alpn="h3"'
        )
        response.answer.append(rrset)
        return response.to_wire()

    @staticmethod
    def UpgradeDoTCallback(request):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(
            request.question[0].name,
            60,
            dns.rdataclass.IN,
            dns.rdatatype.SVCB,
            '1 tls.tests.dnsdist.org. alpn="dot" port=10652 ipv4hint=127.0.0.1',
        )
        response.answer.append(rrset)
        # add a useless A record for good measure
        rrset = dns.rrset.from_text(request.question[0].name, 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
        response.answer.append(rrset)
        # plus more useless records in authority
        rrset = dns.rrset.from_text(request.question[0].name, 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
        response.authority.append(rrset)
        # and finally valid, albeit useless, hints
        rrset = dns.rrset.from_text("tls.tests.dnsdist.org.", 60, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        response.additional.append(rrset)
        rrset = dns.rrset.from_text("tls.tests.dnsdist.org.", 60, dns.rdataclass.IN, dns.rdatatype.AAAA, "::1")
        response.additional.append(rrset)
        return response.to_wire()

    @staticmethod
    def UpgradeDoHCallback(request):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(
            request.question[0].name,
            60,
            dns.rdataclass.IN,
            dns.rdatatype.SVCB,
            '1 tls.tests.dnsdist.org. alpn="h2" port=10653 ipv4hint=127.0.0.1 key7="/dns-query{?dns}"',
        )
        response.answer.append(rrset)
        return response.to_wire()

    @staticmethod
    def UpgradeDoTDifferentAddr1Callback(request):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(
            request.question[0].name,
            60,
            dns.rdataclass.IN,
            dns.rdatatype.SVCB,
            '1 tls.tests.dnsdist.org. alpn="dot" port=10654 ipv4hint=127.0.0.2',
        )
        response.answer.append(rrset)
        return response.to_wire()

    @staticmethod
    def UpgradeDoTDifferentAddr2Callback(request):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(
            request.question[0].name,
            60,
            dns.rdataclass.IN,
            dns.rdatatype.SVCB,
            '1 tls.tests.dnsdist.org. alpn="dot" port=10655 ipv4hint=127.0.0.1',
        )
        response.answer.append(rrset)
        return response.to_wire()

    @staticmethod
    def UpgradeDoTUnreachableCallback(request):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(
            request.question[0].name,
            60,
            dns.rdataclass.IN,
            dns.rdatatype.SVCB,
            '1 tls.tests.dnsdist.org. alpn="dot" port=10656 ipv4hint=127.0.0.1',
        )
        response.answer.append(rrset)
        return response.to_wire()

    @staticmethod
    def BrokenResponseCallback(request):
        response = dns.message.make_response(request)
        response.use_edns(edns=False)
        response.question = []
        return response.to_wire()

    @staticmethod
    def UpgradeDoHMissingPathCallback(request):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(
            request.question[0].name,
            60,
            dns.rdataclass.IN,
            dns.rdatatype.SVCB,
            '1 tls.tests.dnsdist.org. alpn="h2" port=10653 ipv4hint=127.0.0.1',
        )
        response.answer.append(rrset)
        return response.to_wire()

    @staticmethod
    def EOFCallback(request):
        return None

    @staticmethod
    def ServFailCallback(request):
        response = dns.message.make_response(request)
        response.set_rcode(dns.rcode.SERVFAIL)
        return response.to_wire()

    @staticmethod
    def WrongNameCallback(request):
        query = dns.message.make_query("not-the-right-one.", dns.rdatatype.SVCB)
        response = dns.message.make_response(query)
        response.id = request.id
        return response.to_wire()

    @staticmethod
    def WrongIDCallback(request):
        response = dns.message.make_response(request)
        response.id = request.id ^ 42
        return response.to_wire()

    @staticmethod
    def TooManyQuestionsCallback(request):
        response = dns.message.make_response(request)
        response.question.append(response.question[0])
        return response.to_wire()

    @staticmethod
    def BadQNameCallback(request):
        response = dns.message.make_response(request)
        wire = bytearray(response.to_wire())
        # mess up the first label length
        wire[12] = 0xFF
        return wire

    @staticmethod
    def UpgradeDoTNoPortCallback(request):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(
            request.question[0].name,
            60,
            dns.rdataclass.IN,
            dns.rdatatype.SVCB,
            '1 tls.tests.dnsdist.org. alpn="dot" ipv4hint=127.0.0.1',
        )
        response.answer.append(rrset)
        return response.to_wire()

    @staticmethod
    def UpgradeDoHNoPortCallback(request):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(
            request.question[0].name,
            60,
            dns.rdataclass.IN,
            dns.rdatatype.SVCB,
            '1 tls.tests.dnsdist.org. alpn="h2" ipv4hint=127.0.0.1 key7="/dns-query{?dns}"',
        )
        response.answer.append(rrset)
        return response.to_wire()

    @staticmethod
    def RedirectionGenericCallback(request, alpn, port, extra=""):
        response = dns.message.make_response(request)
        rrset = dns.rrset.from_text(
            request.question[0].name,
            60,
            dns.rdataclass.IN,
            dns.rdatatype.SVCB,
            f'1 tls.tests.dnsdist.org. alpn="{alpn}" port={port} ipv4hint=127.0.0.1 {extra}',
        )
        response.answer.append(rrset)
        # add a useless A record for good measure
        rrset = dns.rrset.from_text(request.question[0].name, 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
        response.answer.append(rrset)
        # plus more useless records in authority
        rrset = dns.rrset.from_text(request.question[0].name, 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
        response.authority.append(rrset)
        # and finally valid, albeit useless, hints
        rrset = dns.rrset.from_text("tls.tests.dnsdist.org.", 60, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        response.additional.append(rrset)
        rrset = dns.rrset.from_text("tls.tests.dnsdist.org.", 60, dns.rdataclass.IN, dns.rdatatype.AAAA, "::1")
        response.additional.append(rrset)
        return response.to_wire()

    @staticmethod
    def UpgradeDoTToRedirectCallback(request):
        return TestBackendDiscovery.RedirectionGenericCallback(request, "dot", 10657)

    @staticmethod
    def RedirectDoTCallback(request):
        return TestBackendDiscovery.RedirectionGenericCallback(request, "dot", 10658)

    @staticmethod
    def UpgradeDoHToRedirectCallback(request):
        return TestBackendDiscovery.RedirectionGenericCallback(request, "h2", 10659, 'key7="/dns-query{?dns}"')

    @staticmethod
    def RedirectDoHCallback(request, requestHeaders, fromQueue, toQueue, conn):
        return 200, TestBackendDiscovery.RedirectionGenericCallback(request, "h2", 10660, 'key7="/dns-query{?dns}"')

    @staticmethod
    def UpgradeDoHToRedirectIntoFailureCallback(request):
        return TestBackendDiscovery.RedirectionGenericCallback(request, "h2", 10661, 'key7="/dns-query{?dns}"')

    @staticmethod
    def RedirectDoHFailureCallback(request, requestHeaders, fromQueue, toQueue, conn):
        return 400, ""

    @staticmethod
    def UpgradeDoTToRedirectLoopCallback(request):
        return TestBackendDiscovery.RedirectionGenericCallback(request, "dot", 10662)

    @staticmethod
    def RedirectLoop1Callback(request):
        return TestBackendDiscovery.RedirectionGenericCallback(request, "dot", 10663)

    @staticmethod
    def RedirectLoop2Callback(request):
        return TestBackendDiscovery.RedirectionGenericCallback(request, "dot", 10662)

    @staticmethod
    def UpgradeDoTThenKeepCallback(request):
        return TestBackendDiscovery.RedirectionGenericCallback(request, "dot", 10664)

    @staticmethod
    def RedirectDoTThenKeepCallback(request):
        return TestBackendDiscovery.RedirectionGenericCallback(request, "dot", 10665)

    @classmethod
    def startResponders(cls):
        dotContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        dotContext.load_cert_chain("server.chain", "server.key")
        dotContext.set_alpn_protocols(["dot"])
        dohContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        dohContext.load_cert_chain("server.chain", "server.key")
        dohContext.set_alpn_protocols(["h2"])

        TCPNoSVCResponder = threading.Thread(
            name="TCP no SVC Responder",
            target=cls.TCPResponder,
            args=[
                cls._noSVCBackendPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                True,
                False,
                cls.NoSVCCallback,
            ],
        )
        TCPNoSVCResponder.daemon = True
        TCPNoSVCResponder.start()

        TCPNoUpgradeResponder = threading.Thread(
            name="TCP no upgrade Responder",
            target=cls.TCPResponder,
            args=[
                cls._svcNoUpgradeBackendPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.NoUpgradePathCallback,
            ],
        )
        TCPNoUpgradeResponder.daemon = True
        TCPNoUpgradeResponder.start()

        # this one is special, does partial writes!
        TCPUpgradeToDoTResponder = threading.Thread(
            name="TCP upgrade to DoT Responder",
            target=cls.TCPResponder,
            args=[
                cls._svcUpgradeDoTBackendPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.UpgradeDoTCallback,
                None,
                False,
                "127.0.0.1",
                True,
            ],
        )
        TCPUpgradeToDoTResponder.daemon = True
        TCPUpgradeToDoTResponder.start()
        # and the corresponding DoT responder
        UpgradedDoTResponder = threading.Thread(
            name="DoT upgraded Responder",
            target=cls.TCPResponder,
            args=[
                10652,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                None,
                dotContext,
                False,
                "127.0.0.1",
                False,
                "dot",
            ],
        )
        UpgradedDoTResponder.daemon = True
        UpgradedDoTResponder.start()

        TCPUpgradeToDoHResponder = threading.Thread(
            name="TCP upgrade to DoH Responder",
            target=cls.TCPResponder,
            args=[
                cls._svcUpgradeDoHBackendPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.UpgradeDoHCallback,
            ],
        )
        TCPUpgradeToDoHResponder.daemon = True
        TCPUpgradeToDoHResponder.start()
        # and the corresponding DoH responder
        UpgradedDOHResponder = threading.Thread(
            name="DOH Responder",
            target=cls.DOHResponder,
            args=[
                10653,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                None,
                dohContext,
                False,
                False,
                5.0,
                "h2",
            ],
        )
        UpgradedDOHResponder.daemon = True
        UpgradedDOHResponder.start()

        TCPUpgradeToDoTDifferentAddrResponder = threading.Thread(
            name="TCP upgrade to DoT different addr 1 Responder",
            target=cls.TCPResponder,
            args=[
                cls._svcUpgradeDoTBackendDifferentAddrPort1,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.UpgradeDoTDifferentAddr1Callback,
            ],
        )
        TCPUpgradeToDoTDifferentAddrResponder.daemon = True
        TCPUpgradeToDoTDifferentAddrResponder.start()
        # and the corresponding DoT responder
        UpgradedDoTResponder = threading.Thread(
            name="DoT upgraded different addr 1 Responder",
            target=cls.TCPResponder,
            args=[
                10654,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                None,
                dotContext,
                False,
                "127.0.0.2",
                False,
                "dot",
            ],
        )
        UpgradedDoTResponder.daemon = True
        UpgradedDoTResponder.start()

        TCPUpgradeToDoTDifferentAddrResponder = threading.Thread(
            name="TCP upgrade to DoT different addr 2 Responder",
            target=cls.TCPResponder,
            args=[
                cls._svcUpgradeDoTBackendDifferentAddrPort2,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.UpgradeDoTDifferentAddr2Callback,
                None,
                False,
                "127.0.0.2",
            ],
        )
        TCPUpgradeToDoTDifferentAddrResponder.daemon = True
        TCPUpgradeToDoTDifferentAddrResponder.start()
        # and the corresponding DoT responder
        UpgradedDoTResponder = threading.Thread(
            name="DoT upgraded different addr 2 Responder",
            target=cls.TCPResponder,
            args=[
                10655,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                None,
                dotContext,
                False,
                "127.0.0.1",
                False,
                "dot",
            ],
        )
        UpgradedDoTResponder.daemon = True
        UpgradedDoTResponder.start()

        TCPUpgradeToUnreachableDoTResponder = threading.Thread(
            name="TCP upgrade to unreachable DoT Responder",
            target=cls.TCPResponder,
            args=[
                cls._svcUpgradeDoTUnreachableBackendPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.UpgradeDoTUnreachableCallback,
            ],
        )
        TCPUpgradeToUnreachableDoTResponder.daemon = True
        TCPUpgradeToUnreachableDoTResponder.start()
        # and NO corresponding DoT responder
        # this is not a mistake!

        BrokenResponseResponder = threading.Thread(
            name="Broken response Responder",
            target=cls.TCPResponder,
            args=[
                cls._svcBrokenDNSResponseBackendPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.BrokenResponseCallback,
            ],
        )
        BrokenResponseResponder.daemon = True
        BrokenResponseResponder.start()

        DOHMissingPathResponder = threading.Thread(
            name="DoH missing path Responder",
            target=cls.TCPResponder,
            args=[
                cls._svcUpgradeDoHBackendWithoutPathPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.UpgradeDoHMissingPathCallback,
            ],
        )
        DOHMissingPathResponder.daemon = True
        DOHMissingPathResponder.start()

        EOFResponder = threading.Thread(
            name="EOF Responder",
            target=cls.TCPResponder,
            args=[cls._eofBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, cls.EOFCallback],
        )
        EOFResponder.daemon = True
        EOFResponder.start()

        ServFailResponder = threading.Thread(
            name="ServFail Responder",
            target=cls.TCPResponder,
            args=[
                cls._servfailBackendPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.ServFailCallback,
            ],
        )
        ServFailResponder.daemon = True
        ServFailResponder.start()

        WrongNameResponder = threading.Thread(
            name="Wrong Name Responder",
            target=cls.TCPResponder,
            args=[
                cls._wrongNameBackendPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.WrongNameCallback,
            ],
        )
        WrongNameResponder.daemon = True
        WrongNameResponder.start()

        WrongIDResponder = threading.Thread(
            name="Wrong ID Responder",
            target=cls.TCPResponder,
            args=[
                cls._wrongIDBackendPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.WrongIDCallback,
            ],
        )
        WrongIDResponder.daemon = True
        WrongIDResponder.start()

        TooManyQuestionsResponder = threading.Thread(
            name="Too many questions Responder",
            target=cls.TCPResponder,
            args=[
                cls._tooManyQuestionsBackendPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.TooManyQuestionsCallback,
            ],
        )
        TooManyQuestionsResponder.daemon = True
        TooManyQuestionsResponder.start()

        badQNameResponder = threading.Thread(
            name="Bad QName Responder",
            target=cls.TCPResponder,
            args=[
                cls._badQNameBackendPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.BadQNameCallback,
            ],
        )
        badQNameResponder.daemon = True
        badQNameResponder.start()

        TCPUpgradeToDoTNoPortResponder = threading.Thread(
            name="TCP upgrade to DoT (no port) Responder",
            target=cls.TCPResponder,
            args=[
                cls._svcUpgradeDoTNoPortBackendPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.UpgradeDoTNoPortCallback,
            ],
        )
        TCPUpgradeToDoTNoPortResponder.daemon = True
        TCPUpgradeToDoTNoPortResponder.start()

        TCPUpgradeToDoHNoPortResponder = threading.Thread(
            name="TCP upgrade to DoH (no port) Responder",
            target=cls.TCPResponder,
            args=[
                cls._svcUpgradeDoHNoPortBackendPort,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.UpgradeDoHNoPortCallback,
            ],
        )
        TCPUpgradeToDoHNoPortResponder.daemon = True
        TCPUpgradeToDoHNoPortResponder.start()

        UpgradeToRedirectResponder = threading.Thread(
            name="upgrade to DoT redirection Responder",
            target=cls.TCPResponder,
            args=[
                cls._svcUpgradeDoTThenRedirect,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.UpgradeDoTToRedirectCallback,
                None,
                False,
                "127.0.0.1",
                True,
            ],
        )
        UpgradeToRedirectResponder.daemon = True
        UpgradeToRedirectResponder.start()
        RedirectionResponder = threading.Thread(
            name="DoT Redirection Responder",
            target=cls.TCPResponder,
            args=[
                10657,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.RedirectDoTCallback,
                tlsContext,
            ],
        )
        RedirectionResponder.daemon = True
        RedirectionResponder.start()
        # and the corresponding redirected responder
        RedirectedResponder = threading.Thread(
            name="DoT Redirected responder",
            target=cls.TCPResponder,
            args=[
                10658,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.RedirectDoTCallback,
                tlsContext,
            ],
        )
        RedirectedResponder.daemon = True
        RedirectedResponder.start()

        UpgradeToDoHRedirectResponder = threading.Thread(
            name="upgrade to redirection Responder",
            target=cls.TCPResponder,
            args=[
                cls._svcUpgradeDoHThenRedirect,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.UpgradeDoHToRedirectCallback,
            ],
        )
        UpgradeToDoHRedirectResponder.daemon = True
        UpgradeToDoHRedirectResponder.start()
        DoHRedirectionResponder = threading.Thread(
            name="DoH Redirection Responder",
            target=cls.DOHResponder,
            args=[
                10659,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.RedirectDoHCallback,
                tlsContext,
            ],
        )
        DoHRedirectionResponder.daemon = True
        DoHRedirectionResponder.start()
        # and the corresponding redirected responder
        DoHRedirectedResponder = threading.Thread(
            name="DoH upgraded different addr 2 Responder",
            target=cls.DOHResponder,
            args=[
                10660,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.RedirectDoHCallback,
                tlsContext,
            ],
        )
        DoHRedirectedResponder.daemon = True
        DoHRedirectedResponder.start()

        UpgradeToDoHRedirectIntoFailureResponder = threading.Thread(
            name="upgrade to redirection Responder into failure",
            target=cls.TCPResponder,
            args=[
                cls._svcUpgradeDoHThenRedirectIntoFailure,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.UpgradeDoHToRedirectIntoFailureCallback,
            ],
        )
        UpgradeToDoHRedirectIntoFailureResponder.daemon = True
        UpgradeToDoHRedirectIntoFailureResponder.start()
        DoHRedirectionFailureResponder = threading.Thread(
            name="DoH Redirection failure Responder",
            target=cls.DOHResponder,
            args=[
                10661,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.RedirectDoHFailureCallback,
                tlsContext,
            ],
        )
        DoHRedirectionFailureResponder.daemon = True
        DoHRedirectionFailureResponder.start()

        UpgradeToDoTRedirectIntoLoopResponder = threading.Thread(
            name="upgrade to redirection Responder into loop",
            target=cls.TCPResponder,
            args=[
                cls._svcUpgradeDoTThenRedirectLoop,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.UpgradeDoTToRedirectLoopCallback,
            ],
        )
        UpgradeToDoTRedirectIntoLoopResponder.daemon = True
        UpgradeToDoTRedirectIntoLoopResponder.start()
        DoTRedirectionLoop1Responder = threading.Thread(
            name="DoT Redirection loop Responder 1",
            target=cls.TCPResponder,
            args=[
                10662,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.RedirectLoop1Callback,
                tlsContext,
            ],
        )
        DoTRedirectionLoop1Responder.daemon = True
        DoTRedirectionLoop1Responder.start()
        DoTRedirectionLoop2Responder = threading.Thread(
            name="DoT Redirection loop Responder 2",
            target=cls.TCPResponder,
            args=[
                10663,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.RedirectLoop2Callback,
                tlsContext,
            ],
        )
        DoTRedirectionLoop2Responder.daemon = True
        DoTRedirectionLoop2Responder.start()

        UpgradeToRedirectAndKeepResponder = threading.Thread(
            name="upgrade to DoT redirection and keep Responder",
            target=cls.TCPResponder,
            args=[
                cls._svcUpgradeDoTRedirectAndKeep,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.UpgradeDoTThenKeepCallback,
                None,
                False,
                "127.0.0.1",
                True,
            ],
        )
        UpgradeToRedirectAndKeepResponder.daemon = True
        UpgradeToRedirectAndKeepResponder.start()
        RedirectAndKeepResponder = threading.Thread(
            name="DoT Redirection and keep Responder",
            target=cls.TCPResponder,
            args=[
                10664,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.RedirectDoTThenKeepCallback,
                tlsContext,
            ],
        )
        RedirectAndKeepResponder.daemon = True
        RedirectAndKeepResponder.start()
        # and the corresponding redirected responder
        RedirectedAndKeepResponder = threading.Thread(
            name="DoT Redirected and keep responder",
            target=cls.TCPResponder,
            args=[
                10665,
                cls._toResponderQueue,
                cls._fromResponderQueue,
                False,
                False,
                cls.RedirectDoTThenKeepCallback,
                tlsContext,
            ],
        )
        RedirectedAndKeepResponder.daemon = True
        RedirectedAndKeepResponder.start()

    def checkBackendsUpgraded(self):
        output = self.sendConsoleCommand("showServers()")
        print(output)

        backends = {}
        for line in output.splitlines(False):
            if line.startswith("#") or line.startswith("All"):
                continue
            tokens = line.split()
            self.assertTrue(len(tokens) == 13 or len(tokens) == 14)
            if tokens[1] == "127.0.0.1:10652" or tokens[1] == "127.0.0.1:10665":
                # in this particular case, the upgraded backend
                # does not replace the existing one and thus
                # the health-check is forced to auto (or lazy auto)
                self.assertEqual(tokens[2], "up")
            else:
                self.assertEqual(tokens[2], "UP")
            pool = ""
            if len(tokens) == 14:
                pool = tokens[13]
            backends[tokens[1]] = pool

        expected = {
            "127.0.0.1:10600": "",
            "127.0.0.1:10601": "",
            "127.0.0.1:10602": "another-pool",
            # 10603 has been upgraded to 10653 and removed
            # 10604 has been upgraded to 10654 and removed
            "127.0.0.2:10605": "",
            "127.0.0.1:10606": "",
            "127.0.0.1:10607": "",
            "127.0.0.1:10608": "",
            "127.0.0.1:10609": "other-pool",
            "127.0.0.1:10610": "",
            "127.0.0.1:10611": "",
            "127.0.0.1:10612": "",
            "127.0.0.1:10613": "",
            "127.0.0.1:10614": "",
            "127.0.0.1:10615": "",
            # these two are not upgraded because there is no backend listening on the default ports (443 and 853)
            "127.0.0.1:10616": "",
            "127.0.0.1:10617": "",
            "127.0.0.1:10652": "upgraded",
            "127.0.0.1:10653": "another-pool",
            "127.0.0.2:10654": "",
            "127.0.0.1:10661": "",
            "127.0.0.1:10658": "",
            "127.0.0.1:10660": "",
            "127.0.0.1:10662": "",
            "127.0.0.1:10664": "",
            "127.0.0.1:10665": "",
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
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")
    _consolePort = pickAvailablePort()
    _config_params = ["_consoleKeyB64", "_consolePort"]
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
        output = self.sendConsoleCommand("showServers()")
        print(output)
        backends = {}
        for line in output.splitlines(False):
            if line.startswith("#") or line.startswith("All"):
                continue
            tokens = line.split()
            self.assertTrue(len(tokens) == 13 or len(tokens) == 14)
            backends[tokens[1]] = tokens[2]

        if len(backends) == 4:
            for expected in ["9.9.9.9:53", "149.112.112.112:53", "[2620:fe::9]:53", "[2620:fe::fe]:53"]:
                self.assertIn(expected, backends)
        elif len(backends) == 2:
            # looks like we are not getting the IPv6 addresses, thanks GitHub!
            for expected in ["9.9.9.9:53", "149.112.112.112:53"]:
                self.assertIn(expected, backends)
        else:
            return False

        for backend in backends:
            if str(backend) in ["2620:fe::9]:53", "[2620:fe::fe]:53"]:
                # IPv6 is very flaky on GH actions these days (202505),
                # let's not require these to be up
                continue
            if backends[backend] != "up":
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
