import pytest
import dns
import os
import time
from recursortests import RecursorTest

class ChainTest(RecursorTest):
    """
    These regression tests test the chaining of outgoing requests.
    """
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
