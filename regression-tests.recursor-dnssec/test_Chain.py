import dns
import clientsubnetoption
from recursortests import RecursorTest

class ChainTest(RecursorTest):
    """
    These regression tests test the chaining of outgoing requests.
    """
    _auth_zones = RecursorTest._default_auth_zones
    _chainSize = 200
    _confdir = 'Chain'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'

    _config_template = """dnssec=validate
    trace=no
    devonly-regression-test-mode
    webserver=yes
    webserver-port=%d
    webserver-address=127.0.0.1
    webserver-password=%s
    api-key=%s
    max-concurrent-requests-per-tcp-connection=%s
""" % (_wsPort, _wsPassword, _apiKey, _chainSize)

    # @pytest.mark.unreliable_on_gh Not any more?
    def testBasic(self):
        """
        Tests the case of #14624. Sending many equal requests could lead to ServFail because of
        clashing waiter ids.
        """
        count = self._chainSize
        name = '9.delay1.example.'
        exp = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'TXT', 'a')
        queries = []
        for i in range(count):
            query = dns.message.make_query(name, 'TXT', want_dnssec=True)
            query.flags |= dns.flags.AD
            queries.append(query)

        answers = self.sendTCPQueries(queries)
        self.assertEqual(len(answers), count)

        for i in range(count):
            res = answers[i]
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertMessageIsAuthenticated(res)
            self.assertRRsetInAnswer(res, exp)
            self.assertMatchingRRSIGInAnswer(res, exp)

        self.checkMetrics({
            'max-chain-length': count - 1, # first request has count - 1 requests chained to it
            'servfail-answers': 0,
            'noerror-answers': count,
        })

class ChainECSTest(RecursorTest):
    """
    These regression tests test the chaining of outgoing requests with ECS
    """
    _auth_zones = RecursorTest._default_auth_zones
    _chainSize = 200
    _confdir = 'ChainECS'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'

    _config_template = """dnssec=validate
    trace=no
    edns-subnet-allow-list=0.0.0.0/0
    use-incoming-edns-subnet=yes
    edns-subnet-allow-list=0.0.0.0/0
    devonly-regression-test-mode
    webserver=yes
    webserver-port=%d
    webserver-address=127.0.0.1
    webserver-password=%s
    api-key=%s
    max-concurrent-requests-per-tcp-connection=%s
""" % (_wsPort, _wsPassword, _apiKey, _chainSize)

    def testBasic(self):
        """
        Tests the case of #14624. Sending many equal requests could lead to ServFail because of
        clashing waiter ids.
        """
        count = self._chainSize
        name1 = '1.delay1.example.'
        name2 = '2.delay1.example.'
        exp1 = dns.rrset.from_text(name1, 0, dns.rdataclass.IN, 'TXT', 'a')
        exp2 = dns.rrset.from_text(name2, 0, dns.rdataclass.IN, 'TXT', 'a')
        queries = []
        for i in range(count):
            if i % 3 == 0:
                name = name1
            else:
               name = name2
            if i % 2 == 0:
                ecso = clientsubnetoption.ClientSubnetOption('192.0.2.0', 24)
            else:
                ecso = clientsubnetoption.ClientSubnetOption('192.0.3.0', 24)
            query = dns.message.make_query(name, 'TXT', use_edns=True, options=[ecso], want_dnssec=True)
            query.flags |= dns.flags.AD
            queries.append(query)

        answers = self.sendTCPQueries(queries)
        self.assertEqual(len(answers), count)

        for i in range(count):
            res = answers[i]
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertMessageIsAuthenticated(res)
            if res.question[0].name.to_text() == name1:
                self.assertRRsetInAnswer(res, exp1)
                self.assertMatchingRRSIGInAnswer(res, exp1)
            elif res.question[0].name.to_text() == name2:
                self.assertRRsetInAnswer(res, exp2)
                self.assertMatchingRRSIGInAnswer(res, exp2)
            else:
                print("?? " + res.question[0].name.to_text())
                self.assertEqual(0, 1)

        self.checkMetrics({
            'servfail-answers': 0,
            'noerror-answers': count,
        })

class ChainECSHardenedTest(RecursorTest):
    """
    These regression tests test the chaining of outgoing requests with ECS
    """
    _auth_zones = RecursorTest._default_auth_zones
    _chainSize = 200
    _confdir = 'ChainECSHardened'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'

    _config_template = """dnssec=validate
    trace=no
    edns-subnet-allow-list=0.0.0.0/0
    use-incoming-edns-subnet=yes
    edns-subnet-allow-list=0.0.0.0/0
    edns-subnet-harden=yes
    devonly-regression-test-mode
    webserver=yes
    webserver-port=%d
    webserver-address=127.0.0.1
    webserver-password=%s
    api-key=%s
    max-concurrent-requests-per-tcp-connection=%s
""" % (_wsPort, _wsPassword, _apiKey, _chainSize)

    def testBasic(self):
        """
        Tests the case of #14624. Sending many equal requests could lead to ServFail because of
        clashing waiter ids.
        """
        count = self._chainSize
        name1 = '1.delay1.example.'
        name2 = '2.delay1.example.'
        exp1 = dns.rrset.from_text(name1, 0, dns.rdataclass.IN, 'TXT', 'a')
        exp2 = dns.rrset.from_text(name2, 0, dns.rdataclass.IN, 'TXT', 'a')
        queries = []
        for i in range(count):
            if i % 3 == 0:
                name = name1
            else:
               name = name2
            if i % 2 == 0:
                ecso = clientsubnetoption.ClientSubnetOption('192.0.2.0', 24)
            else:
                ecso = clientsubnetoption.ClientSubnetOption('192.0.3.0', 24)
            query = dns.message.make_query(name, 'TXT', use_edns=True, options=[ecso], want_dnssec=True)
            query.flags |= dns.flags.AD
            queries.append(query)

        answers = self.sendTCPQueries(queries)
        self.assertEqual(len(answers), count)

        for i in range(count):
            res = answers[i]
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertMessageIsAuthenticated(res)
            if res.question[0].name.to_text() == name1:
                self.assertRRsetInAnswer(res, exp1)
                self.assertMatchingRRSIGInAnswer(res, exp1)
            elif res.question[0].name.to_text() == name2:
                self.assertRRsetInAnswer(res, exp2)
                self.assertMatchingRRSIGInAnswer(res, exp2)
            else:
                print("?? " + res.question[0].name.to_text())
                self.assertEqual(0, 1)

        self.checkMetrics({
            'servfail-answers': 0,
            'noerror-answers': count,
        })

