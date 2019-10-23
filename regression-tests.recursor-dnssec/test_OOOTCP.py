import dns
import os
import time
from recursortests import RecursorTest

class testOOOTCP(RecursorTest):
    _confdir = 'OOOTCP'

    _config_template = """dnssec=off
"""

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(testOOOTCP, cls).generateRecursorConfig(confdir)

    def primeNS(self):
        query = dns.message.make_query('delay.example.', 'NS', want_dnssec=False)
        self.sendUDPQuery(query)
        
    def testOOOVeryBasic(self):
        self.primeNS()
        expected = {}
        queries = []
        for zone in ['5.delay.example.', '0.delay.example.']:
            expected[zone] = dns.rrset.from_text(zone, 0, dns.rdataclass.IN, 'TXT', 'a')
            query = dns.message.make_query(zone, 'TXT', want_dnssec=False)
            query.flags |= dns.flags.AD
            queries.append(query)

        ress = self.sendTCPQueries(queries)

        self.assertEqual(len(ress), len(expected))

        i = 0
        for exp in [expected['0.delay.example.'], expected['5.delay.example.']]:
            print('ress0')
            print(ress[i].answer[0].to_text())
            print('exp')
            print(exp.to_text())
            #self.assertMessageIsAuthenticated(ress[i])
            self.assertRRsetInAnswer(ress[i], exp)
            #self.assertMatchingRRSIGInAnswer(ress[i], exp)
            i = i + 1

    def testOOOTimeout(self):
        self.primeNS()
        expected = {}
        queries = []
        for zone in ['25.delay.example.', '1.delay.example.']:
            query = dns.message.make_query(zone, 'TXT', want_dnssec=False)
            query.flags |= dns.flags.AD
            queries.append(query)

        ress = self.sendTCPQueries(queries)
        
        self.assertEqual(len(ress), 2)
        exp = dns.rrset.from_text(zone, 0, dns.rdataclass.IN, 'TXT', 'a')
        self.assertRRsetInAnswer(ress[0], exp)
        self.assertRcodeEqual(ress[1], dns.rcode.SERVFAIL)

        # Let the auth timeout happen to not disturb other tests
        time.sleep(1)

