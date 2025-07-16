import dns
import os
import time
import requests
import clientsubnetoption
from recursortests import RecursorTest

class ChainTest(RecursorTest):
    """
    These regression tests test the chaining of outgoing requests.
    """
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
""" % (_wsPort, _wsPassword, _apiKey)

    def checkMetrics(self, map):
        self.waitForTCPSocket("127.0.0.1", self._wsPort)
        headers = {'x-api-key': self._apiKey}
        url = 'http://127.0.0.1:' + str(self._wsPort) + '/api/v1/servers/localhost/statistics'
        r = requests.get(url, headers=headers, timeout=self._wsTimeout)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        count = 0
        for entry in content:
            for key, expected in map.items():
                if entry['name'] == key:
                    value = int(entry['value'])
                    if callable(expected):
                        self.assertTrue(expected(value))
                    else:
                        self.assertEqual(value, expected)
                    count += 1
        self.assertEqual(count, len(map))

    def testBasic(self):
        """
        Tests the case of #14624. Sending many equal requests could lead to ServFail because of clashing
        waiter ids.
        """
        # We actually do not check all responses, as experience show that packets may be dropped by the OS
        # Instead, we check if a few counters in rec have the expected values.
        count = 200
        name = '9.delay1.example.'
        exp = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'TXT', 'a')
        for i in range(count):
            query = dns.message.make_query(name, 'TXT', want_dnssec=True)
            query.flags |= dns.flags.AD
            self._sock.send(query.to_wire())

        # Just check one, as OS emptying of socket buffers can work against us
        data = self._sock.recv(4096)
        res = dns.message.from_wire(data)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, exp)
        self.assertMatchingRRSIGInAnswer(res, exp)
        time.sleep(1)

        self.checkMetrics({
            'max-chain-length': (lambda x: x <= count-1), # first request has count - 1 requests chained to it
            'servfail-answers': 0,
            'noerror-answers': (lambda x: x <= count),
        })

class ChainECSTest(RecursorTest):
    """
    These regression tests test the chaining of outgoing requests with ECS
    """
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

