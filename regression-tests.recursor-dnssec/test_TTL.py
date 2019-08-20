import dns
import os
from recursortests import RecursorTest

class testBogusMaxTTL(RecursorTest):
    _confdir = 'BogusMaxTTL'

    _config_template = """dnssec=validate
max-cache-bogus-ttl=5"""

    @classmethod
    def setUp(cls):
        confdir = os.path.join('configs', cls._confdir)
        cls.wipeRecursorCache(confdir)

    def testBogusCheckDisabled(self):
        # first query with CD=0, so we should get a ServFail
        query = self.createQuery('ted.bogus.example.', 'A', 'AD', 'DO')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        # then with CD=1 so we should get the A + RRSIG
        # check that we correctly applied the maximum TTL when caching Bogus entries
        query = self.createQuery('ted.bogus.example.', 'A', 'AD CD', 'DO')
        res = self.sendUDPQuery(query)
        self.assertMessageHasFlags(res, ['CD', 'QR', 'RA', 'RD'], ['DO'])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEquals(len(res.answer), 2)
        for ans in res.answer:
            self.assertLessEqual(ans.ttl, 5)
