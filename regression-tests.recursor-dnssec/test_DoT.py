import pytest
import dns
import os
import subprocess
import ssl
import threading
from queue import Queue


from recursortests import RecursorTest

class SimpleDoTTest(RecursorTest):
    """
    This tests DoT to auth server in a very basic way and is dependent on powerdns.com nameservers having DoT enabled.
    """

    _confdir = 'SimpleDoT'
    _config_template = """
dnssec=validate
dot-to-auth-names=powerdns.com
devonly-regression-test-mode
    """

    _roothints = None

    @pytest.mark.external
    def testTXT(self):
        query = dns.message.make_query('.', 'DNSKEY', want_dnssec=True)
        query.flags |= dns.flags.AD

        # As this test uses external servers, be more generous wrt timeouts than the default 2.0s
        res = self.sendUDPQuery(query, timeout=5.0)

        self.assertMessageIsAuthenticated(res)
        self.assertRcodeEqual(res, 0);
        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % 'configs/' + self._confdir,
                          'get tcp-outqueries']
        try:
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
            tcpcount = ret

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

        expected = dns.rrset.from_text('dot-test-target.powerdns.org.', 0, dns.rdataclass.IN, 'TXT', 'https://github.com/PowerDNS/pdns/pull/12825')
        query = dns.message.make_query('dot-test-target.powerdns.org', 'TXT', want_dnssec=True)
        query.flags |= dns.flags.AD

        # As this test uses external servers, be a more generous wrt timeouts than the default 2.0s
        res = self.sendUDPQuery(query, timeout=5.0)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)

        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % 'configs/' + self._confdir,
                          'get dot-outqueries']
        try:
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
            self.assertNotEqual(ret, b'UNKNOWN\n')
            self.assertNotEqual(ret, b'0\n')

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % 'configs/' + self._confdir,
                          'get tcp-outqueries']
        try:
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
            self.assertEqual(ret, tcpcount)

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

class DoTTest(RecursorTest):
    """
    This tests DoT to auth server with validation and is dependent on powerdns.com nameservers having DoT enabled.
    """

    _confdir = 'DoT'
    _config_template = """
dnssec:
    validation: validate
outgoing:
    dot_to_auth_names: [powerdns.com]
    tls_configurations:
    - name: dotwithverify
      suffixes: [powerdns.com]
      validate_certificate: true
      verbose_logging: true
recursor:
    devonly_regression_test_mode: true
    """

    _roothints = None

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(DoTTest, cls).generateRecursorYamlConfig(confdir, False)

    @pytest.mark.external
    def testTXT(self):
        query = dns.message.make_query('.', 'DNSKEY', want_dnssec=True)
        query.flags |= dns.flags.AD

        # As this test uses external servers, be more generous wrt timeouts than the default 2.0s
        res = self.sendUDPQuery(query, timeout=5.0)

        self.assertMessageIsAuthenticated(res)
        self.assertRcodeEqual(res, 0);
        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % 'configs/' + self._confdir,
                          'get tcp-outqueries']
        try:
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
            tcpcount = ret

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

        expected = dns.rrset.from_text('dot-test-target.powerdns.org.', 0, dns.rdataclass.IN, 'TXT', 'https://github.com/PowerDNS/pdns/pull/12825')
        query = dns.message.make_query('dot-test-target.powerdns.org', 'TXT', want_dnssec=True)
        query.flags |= dns.flags.AD

        # As this test uses external servers, be a more generous wrt timeouts than the default 2.0s
        res = self.sendUDPQuery(query, timeout=5.0)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)

        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % 'configs/' + self._confdir,
                          'get dot-outqueries']
        try:
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
            self.assertNotEqual(ret, b'UNKNOWN\n')
            self.assertNotEqual(ret, b'0\n')

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % 'configs/' + self._confdir,
                          'get tcp-outqueries']
        try:
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
            self.assertEqual(ret, tcpcount)

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

class DoTWithGNUTLSTest(RecursorTest):
    """
    This tests DoT to auth server with validation and is dependent on powerdns.com nameservers having DoT enabled.
    """

    _confdir = 'DoTWithGNUTLS'
    _config_template = """
dnssec:
    validation: validate
outgoing:
    dot_to_auth_names: [powerdns.com]
    tls_configurations:
    - name: dotwithverifygnu
      provider: gnutls
      suffixes: [powerdns.com]
      validate_certificate: true
      verbose_logging: true
recursor:
    devonly_regression_test_mode: true
    """

    _roothints = None

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(DoTWithGNUTLSTest, cls).generateRecursorYamlConfig(confdir, False)

    @pytest.mark.external
    def testTXT(self):
        query = dns.message.make_query('.', 'DNSKEY', want_dnssec=True)
        query.flags |= dns.flags.AD

        # As this test uses external servers, be more generous wrt timeouts than the default 2.0s
        res = self.sendUDPQuery(query, timeout=5.0)

        self.assertMessageIsAuthenticated(res)
        self.assertRcodeEqual(res, 0);
        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % 'configs/' + self._confdir,
                          'get tcp-outqueries']
        try:
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
            tcpcount = ret

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

        expected = dns.rrset.from_text('dot-test-target.powerdns.org.', 0, dns.rdataclass.IN, 'TXT', 'https://github.com/PowerDNS/pdns/pull/12825')
        query = dns.message.make_query('dot-test-target.powerdns.org', 'TXT', want_dnssec=True)
        query.flags |= dns.flags.AD

        # As this test uses external servers, be a more generous wrt timeouts than the default 2.0s
        res = self.sendUDPQuery(query, timeout=5.0)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)

        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % 'configs/' + self._confdir,
                          'get dot-outqueries']
        try:
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
            self.assertNotEqual(ret, b'UNKNOWN\n')
            self.assertNotEqual(ret, b'0\n')

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % 'configs/' + self._confdir,
                          'get tcp-outqueries']
        try:
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
            self.assertEqual(ret, tcpcount)

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

class DoTWithLocalResponderTests(RecursorTest):
    """
    This tests DoT to responder with validation"
    """

    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _tlsBackendPort = 853 # If binding to this port fails, add an empty !853 file to /etc/authbind/byport with execute permissons for you
    _queueTimeout = 1
    _toResponderQueue = Queue()
    _fromResponderQueue = Queue()
    _backgroundThreads = {}
    _responsesCounter = {}
    _answerUnexpected = True
    _roothints = None

    @staticmethod
    def sniCallback(sslSocket, sni, sslContext):
        assert(sni == 'tls.tests.powerdns.com')
        return None

    @classmethod
    def sendUDPQuery(cls, query, response, useQueue=True, timeout=2.0, rawQuery=False):
        if useQueue and response is not None:
            cls._toResponderQueue.put(response, True, timeout)

        if timeout:
            cls._sock.settimeout(timeout)

        try:
            if not rawQuery:
                query = query.to_wire()
            cls._sock.send(query)
            data = cls._sock.recv(4096)
        except socket.timeout:
            data = None
        finally:
            if timeout:
                cls._sock.settimeout(None)

        receivedQuery = None
        message = None
        if useQueue and not cls._fromResponderQueue.empty():
            receivedQuery = cls._fromResponderQueue.get(True, timeout)
        if data:
            message = dns.message.from_wire(data)
        return (receivedQuery, message)

    @classmethod
    def startResponders(cls):
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain('server.chain', 'server.key')
        # requires Python 3.7+
        if hasattr(tlsContext, 'sni_callback'):
            tlsContext.sni_callback = cls.sniCallback

        print("Launching TLS responder..")
        cls._TLSResponder = threading.Thread(name='TLS Responder', target=cls.TCPResponder, args=[cls._tlsBackendPort, cls._toResponderQueue, cls._fromResponderQueue, False, False, None, tlsContext])
        cls._TLSResponder.daemon = True
        cls._TLSResponder.start()

    def checkOnlyTLSResponderHit(self, numberOfTLSQueries=1):
        self.assertNotIn('UDP Responder', self._responsesCounter)
        self.assertNotIn('TCP Responder', self._responsesCounter)
        self.assertEqual(self._responsesCounter['TLS Responder'], numberOfTLSQueries)

class DoTOKOpenSSLTest(DoTWithLocalResponderTests):
    """
    This tests DoT to responder with openssl validation using a proper CA store for the locally generated cert"
    """

    _confdir = 'DoTOKOpenSSL'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _config_template = """
dnssec:
    validation: off
outgoing:
    dot_to_auth_names: [powerdns.com]
    tls_configurations:
    - name: dotwithverifygnu
      ca_store: 'ca.pem'
      subject_name: tls.tests.powerdns.com
      subnets: ['127.0.0.1']
      validate_certificate: true
      verbose_logging: true
recursor:
    forward_zones_recurse:
      - zone: powerdns.com
        forwarders: ['127.0.0.1:853']
    devonly_regression_test_mode: true
webservice:
    webserver: true
    port: %d
    address: 127.0.0.1
    password: %s
    api_key: %s
    """ % (_wsPort, _wsPassword, _apiKey)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(DoTOKOpenSSLTest, cls).generateRecursorYamlConfig(confdir, False)

    def testUDP(self):
        """
        Outgoing TLS: UDP query is sent via TLS
        """
        name = 'udp.outgoing-tls.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query, True)
        rrset = dns.rrset.from_text(name,
                                    15,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        currentCount = 0
        if 'TLS Responder' in self._responsesCounter:
            currentCount = self._responsesCounter['TLS Responder'] 
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, expectedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, expectedResponse)

        # there was one TCP query
        self.checkOnlyTLSResponderHit(currentCount + 1)
        self.checkMetrics({
            'dot-outqueries': 1
        })


class DoTOKGnuTLSTest(DoTWithLocalResponderTests):
    """
    This tests DoT to responder with gnutls validation using a proper CA store for the locally generated cert"
    """

    _confdir = 'DoTOKGnuTLS'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _config_template = """
dnssec:
    validation: off
outgoing:
    dot_to_auth_names: [powerdns.com]
    tls_configurations:
    - name: dotwithverifygnu
      provider: gnutls
      ca_store: 'ca.pem'
      subject_name: tls.tests.powerdns.com
      subnets: ['127.0.0.1']
      validate_certificate: true
      verbose_logging: true
recursor:
    forward_zones_recurse:
      - zone: powerdns.com
        forwarders: ['127.0.0.1:853']
    devonly_regression_test_mode: true
webservice:
    webserver: true
    port: %d
    address: 127.0.0.1
    password: %s
    api_key: %s
    """ % (_wsPort, _wsPassword, _apiKey)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(DoTOKGnuTLSTest, cls).generateRecursorYamlConfig(confdir, False)

    def testUDP(self):
        """
        Outgoing TLS: UDP query is sent via TLS
        """
        name = 'udp.outgoing-tls.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query, True)
        rrset = dns.rrset.from_text(name,
                                    15,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        currentCount = 0
        if 'TLS Responder' in self._responsesCounter:
            currentCount = self._responsesCounter['TLS Responder'] 
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, expectedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, expectedResponse)

        # there was one TCP query
        self.checkOnlyTLSResponderHit(currentCount + 1)
        self.checkMetrics({
            'dot-outqueries': 1
        })

class DoTNOKOpenSSLTest(DoTWithLocalResponderTests):
    """
    This tests DoT to responder with openssl validation using a missing CA store for the locally generated cert"
    """

    _confdir = 'DoTNOKOpenSSL'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _config_template = """
dnssec:
    validation: off
outgoing:
    dot_to_auth_names: [powerdns.com]
    tls_configurations:
    - name: dotwithverifygnu
      subject_name: tls.tests.powerdns.com
      subnets: ['127.0.0.1']
      validate_certificate: true
      verbose_logging: true
recursor:
    forward_zones_recurse:
      - zone: powerdns.com
        forwarders: ['127.0.0.1:853']
    devonly_regression_test_mode: true
webservice:
    webserver: true
    port: %d
    address: 127.0.0.1
    password: %s
    api_key: %s
    """ % (_wsPort, _wsPassword, _apiKey)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(DoTNOKOpenSSLTest, cls).generateRecursorYamlConfig(confdir, False)

    def testUDP(self):
        """
        Outgoing TLS: UDP query is sent via TLS
        """
        name = 'udp.outgoing-tls.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query, True)
        rrset = dns.rrset.from_text(name,
                                    15,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        currentCount = 0
        if 'TLS Responder' in self._responsesCounter:
            currentCount = self._responsesCounter['TLS Responder'] 
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, expectedResponse)

        self.assertRcodeEqual(receivedResponse, dns.rcode.SERVFAIL)

        # there was no succesfull DoT query
        self.checkOnlyTLSResponderHit(currentCount)
        self.checkMetrics({
            'dot-outqueries': 1
        })


class DoTNOKGnuTLSTest(DoTWithLocalResponderTests):
    """
    This tests DoT to responder with gnutls validation using a missing CA store for the locally generated cert"
    """

    _confdir = 'DoTNOKGnuTLS'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _config_template = """
dnssec:
    validation: off
outgoing:
    dot_to_auth_names: [powerdns.com]
    tls_configurations:
    - name: dotwithverifygnu
      provider: gnutls
      subject_name: tls.tests.powerdns.com
      subnets: ['127.0.0.1']
      validate_certificate: true
      verbose_logging: true
recursor:
    forward_zones_recurse:
      - zone: powerdns.com
        forwarders: ['127.0.0.1:853']
    devonly_regression_test_mode: true
webservice:
    webserver: true
    port: %d
    address: 127.0.0.1
    password: %s
    api_key: %s
    """ % (_wsPort, _wsPassword, _apiKey)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(DoTNOKGnuTLSTest, cls).generateRecursorYamlConfig(confdir, False)

    def testUDP(self):
        """
        Outgoing TLS: UDP query is sent via TLS
        """
        name = 'udp.outgoing-tls.test.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        expectedResponse = dns.message.make_response(query, True)
        rrset = dns.rrset.from_text(name,
                                    15,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        expectedResponse.answer.append(rrset)

        currentCount = 0
        if 'TLS Responder' in self._responsesCounter:
            currentCount = self._responsesCounter['TLS Responder']
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, expectedResponse)

        self.assertRcodeEqual(receivedResponse, dns.rcode.SERVFAIL)

        # there was no succesful DoT query
        self.checkOnlyTLSResponderHit(currentCount)
        self.checkMetrics({
            'dot-outqueries': 1
        })

