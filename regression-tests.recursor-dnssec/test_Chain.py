import dns
import os
import time
import requests
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
