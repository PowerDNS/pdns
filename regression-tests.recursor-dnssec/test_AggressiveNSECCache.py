import dns
from recursortests import RecursorTest
import os
import requests
import subprocess

class AggressiveNSECCacheBase(RecursorTest):
    __test__ = False
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _config_template = """
    dnssec=validate
    aggressive-nsec-cache-size=10000
    webserver=yes
    webserver-port=%d
    webserver-address=127.0.0.1
    webserver-password=%s
    api-key=%s
    """ % (_wsPort, _wsPassword, _apiKey)

    @classmethod
    def setUp(cls):
        confdir = os.path.join('configs', cls._confdir)
        cls.wipeRecursorCache(confdir)

    def getMetric(self, name):
        headers = {'x-api-key': self._apiKey}
        url = 'http://127.0.0.1:' + str(self._wsPort) + '/api/v1/servers/localhost/statistics'
        r = requests.get(url, headers=headers, timeout=self._wsTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()

        for entry in content:
            if entry['name'] == name:
                return int(entry['value'])

        self.assertTrue(False)

    def testNoData(self):

        # first we query a non-existent type, to get the NSEC in our cache
        entries = self.getMetric('aggressive-nsec-cache-entries')
        res = self.sendQuery('host1.secure.example.', 'TXT')
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnswerEmpty(res)
        self.assertAuthorityHasSOA(res)
        self.assertMessageIsAuthenticated(res)
        self.assertGreater(self.getMetric('aggressive-nsec-cache-entries'), entries)

        # now we ask for a different type, we should generate the answer from the NSEC,
        # and no outgoing query should be made
        nbQueries = self.getMetric('all-outqueries')
        entries = self.getMetric('aggressive-nsec-cache-entries')
        res = self.sendQuery('host1.secure.example.', 'AAAA')
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnswerEmpty(res)
        self.assertAuthorityHasSOA(res)
        self.assertMessageIsAuthenticated(res)
        self.assertEqual(nbQueries, self.getMetric('all-outqueries'))
        self.assertEqual(self.getMetric('aggressive-nsec-cache-entries'), entries)

class AggressiveNSECCacheNSEC(AggressiveNSECCacheBase):
    _confdir = 'AggressiveNSECCacheNSEC'
    __test__ = True

    # we can't use the same tests for NSEC and NSEC3 because the hashed NSEC3s
    # do not deny the same names than the non-hashed NSECs do
    def testNXD(self):

        # first we query a non-existent name, to get the needed NSECs (name + widcard) in our cache
        entries = self.getMetric('aggressive-nsec-cache-entries')
        hits = self.getMetric('aggressive-nsec-cache-nsec-hits')
        res = self.sendQuery('host2.secure.example.', 'TXT')
        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertAnswerEmpty(res)
        self.assertAuthorityHasSOA(res)
        self.assertMessageIsAuthenticated(res)
        self.assertGreater(self.getMetric('aggressive-nsec-cache-entries'), entries)
        self.assertEqual(self.getMetric('aggressive-nsec-cache-nsec-hits'), hits)

        # now we ask for a different name that is covered by the NSEC,
        # we should generate the answer from the NSEC and no outgoing query should be made
        nbQueries = self.getMetric('all-outqueries')
        entries = self.getMetric('aggressive-nsec-cache-entries')
        hits = self.getMetric('aggressive-nsec-cache-nsec-hits')
        res = self.sendQuery('host3.secure.example.', 'AAAA')
        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertAnswerEmpty(res)
        self.assertAuthorityHasSOA(res)
        self.assertMessageIsAuthenticated(res)
        self.assertEqual(nbQueries, self.getMetric('all-outqueries'))
        self.assertEqual(self.getMetric('aggressive-nsec-cache-entries'), entries)
        self.assertGreater(self.getMetric('aggressive-nsec-cache-nsec-hits'), hits)

    def testWildcard(self):

        # first we query a non-existent name, but for which a wildcard matches,
        # to get the NSEC in our cache
        res = self.sendQuery('test1.wildcard.secure.example.', 'A')
        expected = dns.rrset.from_text('test1.wildcard.secure.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMatchingRRSIGInAnswer(res, expected)
        self.assertMessageIsAuthenticated(res)

        # now we ask for a different name, we should generate the answer from the NSEC and the wildcard,
        # and no outgoing query should be made
        hits = self.getMetric('aggressive-nsec-cache-nsec-wc-hits')
        nbQueries = self.getMetric('all-outqueries')
        res = self.sendQuery('test2.wildcard.secure.example.', 'A')
        expected = dns.rrset.from_text('test2.wildcard.secure.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMatchingRRSIGInAnswer(res, expected)
        self.assertMessageIsAuthenticated(res)
        self.assertEqual(nbQueries, self.getMetric('all-outqueries'))
        self.assertGreater(self.getMetric('aggressive-nsec-cache-nsec-wc-hits'), hits)

        # now we ask for a type that does not exist at the wildcard
        hits = self.getMetric('aggressive-nsec-cache-nsec-hits')
        nbQueries = self.getMetric('all-outqueries')
        res = self.sendQuery('test1.wildcard.secure.example.', 'AAAA')
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnswerEmpty(res)
        self.assertAuthorityHasSOA(res)
        self.assertMessageIsAuthenticated(res)
        self.assertEqual(nbQueries, self.getMetric('all-outqueries'))
        self.assertGreater(self.getMetric('aggressive-nsec-cache-nsec-hits'), hits)

        # we can also ask a different type, for a different name that is covered
        # by the NSEC and matches the wildcard (but the type does not exist)
        hits = self.getMetric('aggressive-nsec-cache-nsec-wc-hits')
        nbQueries = self.getMetric('all-outqueries')
        res = self.sendQuery('test3.wildcard.secure.example.', 'TXT')
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnswerEmpty(res)
        self.assertAuthorityHasSOA(res)
        self.assertMessageIsAuthenticated(res)
        self.assertEqual(nbQueries, self.getMetric('all-outqueries'))
        self.assertGreater(self.getMetric('aggressive-nsec-cache-nsec-hits'), hits)

    def test_Bogus(self):
        # query a name in a Bogus zone
        entries = self.getMetric('aggressive-nsec-cache-entries')
        res = self.sendQuery('ted1.bogus.example.', 'A')
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.assertAnswerEmpty(res)

        # disable validation
        msg = dns.message.make_query('ted1.bogus.example.', 'A', want_dnssec=True)
        msg.flags |= dns.flags.CD

        res = self.sendUDPQuery(msg)
        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertAnswerEmpty(res)
        self.assertAuthorityHasSOA(res)

        # check that we _do not_ use the aggressive NSEC cache
        nbQueries = self.getMetric('all-outqueries')
        msg = dns.message.make_query('ted2.bogus.example.', 'A', want_dnssec=True)
        msg.flags |= dns.flags.CD

        res = self.sendUDPQuery(msg)
        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertAnswerEmpty(res)
        self.assertAuthorityHasSOA(res)
        self.assertGreater(self.getMetric('all-outqueries'), nbQueries)
        # we will accept a NSEC for root, which is secure..
        self.assertEqual(entries + 1, self.getMetric('aggressive-nsec-cache-entries'))

class AggressiveNSECCacheNSEC3(AggressiveNSECCacheBase):
    _confdir = 'AggressiveNSECCacheNSEC3'
    __test__ = True

    @classmethod
    def secureZone(cls, confdir, zonename, key=None):
        zone = '.' if zonename == 'ROOT' else zonename
        if not key:
            pdnsutilCmd = [os.environ['PDNSUTIL'],
                           '--config-dir=%s' % confdir,
                           'secure-zone',
                           zone]
        else:
            keyfile = os.path.join(confdir, 'dnssec.key')
            with open(keyfile, 'w') as fdKeyfile:
                fdKeyfile.write(key)

            pdnsutilCmd = [os.environ['PDNSUTIL'],
                           '--config-dir=%s' % confdir,
                           'import-zone-key',
                           zone,
                           keyfile,
                           'active',
                           'ksk']

        print(' '.join(pdnsutilCmd))
        try:
            subprocess.check_output(pdnsutilCmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise AssertionError('%s failed (%d): %s' % (pdnsutilCmd, e.returncode, e.output))

        params = "1 0 100 AABBCCDDEEFF112233"

        if zone == "optout.example":
            params = "1 1 100 AABBCCDDEEFF112233"

        pdnsutilCmd = [os.environ['PDNSUTIL'],
                       '--config-dir=%s' % confdir,
                       'set-nsec3',
                       zone,
                       params]

        print(' '.join(pdnsutilCmd))
        try:
            subprocess.check_output(pdnsutilCmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise AssertionError('%s failed (%d): %s' % (pdnsutilCmd, e.returncode, e.output))

    def testNXD(self):

        # first we query a non-existent name, to get the needed NSEC3s in our cache
        res = self.sendQuery('host2.secure.example.', 'TXT')
        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertAnswerEmpty(res)
        self.assertAuthorityHasSOA(res)
        self.assertMessageIsAuthenticated(res)

        # now we ask for a different name that is covered by the NSEC3s,
        # we should generate the answer from the NSEC3s and no outgoing query should be made
        nbQueries = self.getMetric('all-outqueries')
        res = self.sendQuery('host6.secure.example.', 'AAAA')
        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertAnswerEmpty(res)
        self.assertAuthorityHasSOA(res)
        self.assertMessageIsAuthenticated(res)
        self.assertEqual(nbQueries, self.getMetric('all-outqueries'))

    def testWildcard(self):

        # first let's get the SOA and wildcard NSEC in our cache by asking a name that matches the wildcard
        # but a type that does not exist
        res = self.sendQuery('test1.wildcard.secure.example.', 'AAAA')
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnswerEmpty(res)
        self.assertAuthorityHasSOA(res)
        self.assertMessageIsAuthenticated(res)

        # we query a non-existent name, but for which a wildcard matches,
        # to get the NSEC3 in our cache
        res = self.sendQuery('test5.wildcard.secure.example.', 'A')
        expected = dns.rrset.from_text('test5.wildcard.secure.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMatchingRRSIGInAnswer(res, expected)
        self.assertMessageIsAuthenticated(res)

        # now we ask for a different name, we should generate the answer from the NSEC3s and the wildcard,
        # and no outgoing query should be made
        nbQueries = self.getMetric('all-outqueries')
        res = self.sendQuery('test6.wildcard.secure.example.', 'A')
        expected = dns.rrset.from_text('test6.wildcard.secure.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMatchingRRSIGInAnswer(res, expected)
        self.assertMessageIsAuthenticated(res)
        self.assertEqual(nbQueries, self.getMetric('all-outqueries'))

        # now we ask for a type that does not exist at the wildcard
        nbQueries = self.getMetric('all-outqueries')
        res = self.sendQuery('test5.wildcard.secure.example.', 'AAAA')
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnswerEmpty(res)
        self.assertAuthorityHasSOA(res)
        self.assertMessageIsAuthenticated(res)
        self.assertEqual(nbQueries, self.getMetric('all-outqueries'))

        # we can also ask a different type, for a different name that is covered
        # by the NSEC3s and matches the wildcard (but the type does not exist)
        nbQueries = self.getMetric('all-outqueries')
        res = self.sendQuery('test6.wildcard.secure.example.', 'TXT')
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnswerEmpty(res)
        self.assertAuthorityHasSOA(res)
        self.assertMessageIsAuthenticated(res)
        self.assertEqual(nbQueries, self.getMetric('all-outqueries'))

    def test_OptOut(self):
        # query a name in an opt-out zone
        res = self.sendQuery('ns2.optout.example.', 'A')
        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertAnswerEmpty(res)
        self.assertAuthorityHasSOA(res)

        # check that we _do not_ use the aggressive NSEC cache
        nbQueries = self.getMetric('all-outqueries')
        res = self.sendQuery('ns3.optout.example.', 'A')
        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertAnswerEmpty(res)
        self.assertAuthorityHasSOA(res)
        self.assertGreater(self.getMetric('all-outqueries'), nbQueries)
