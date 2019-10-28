import dns
import os
import time
from recursortests import RecursorTest

class testOOOTCP(RecursorTest):
    _confdir = 'OOOTCP'

    _config_template = """dnssec=validate
"""

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(testOOOTCP, cls).generateRecursorConfig(confdir)

    def testOOOVeryBasic(self):
        expected = {}
        queries = []
        for zone in ['5.delay1.example.', '0.delay2.example.']:
            expected[zone] = dns.rrset.from_text(zone, 0, dns.rdataclass.IN, 'TXT', 'a')
            query = dns.message.make_query(zone, 'TXT', want_dnssec=True)
            query.flags |= dns.flags.AD
            queries.append(query)

        ress = self.sendTCPQueries(queries)

        self.assertEqual(len(ress), len(expected))

        i = 0
        for exp in [expected['0.delay2.example.'], expected['5.delay1.example.']]:
            print('ress0')
            print(ress[i].answer[0].to_text())
            print('exp')
            print(exp.to_text())
            self.assertMessageIsAuthenticated(ress[i])
            self.assertRRsetInAnswer(ress[i], exp)
            self.assertMatchingRRSIGInAnswer(ress[i], exp)
            i = i + 1

    def testOOOTimeout(self):
        expected = {}
        queries = []
        for zone in ['25.delay1.example.', '1.delay2.example.']:
            query = dns.message.make_query(zone, 'TXT', want_dnssec=True)
            query.flags |= dns.flags.AD
            queries.append(query)

        ress = self.sendTCPQueries(queries)

        self.assertEqual(len(ress), 2)
        exp = dns.rrset.from_text('1.delay2.example.', 0, dns.rdataclass.IN, 'TXT', 'a')
        self.assertRRsetInAnswer(ress[0], exp)
        self.assertMatchingRRSIGInAnswer(ress[0], exp)
        self.assertRcodeEqual(ress[1], dns.rcode.SERVFAIL)

        # Let the auth timeout happen to not disturb other tests
        # this can happen if the auth is single-threaded
        time.sleep(1)

