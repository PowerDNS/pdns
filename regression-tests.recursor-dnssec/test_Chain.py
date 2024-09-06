import dns
import os
import time
from recursortests import RecursorTest

class ChainTest(RecursorTest):
    """
    These regression tests test the chaining of outgoing requests.
    """
    _confdir = 'Chain'

    _config_template = """dnssec=validate
"""

    def testBasic(self):
        """
        Tests the case of #14624. Sending many equal requests could lead to ServFail because of clashing
        waiter ids.
        """
        count = 500
        name = '1.delay1.example.'
        exp = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'TXT', 'a')
        for i in range(count):
            query = dns.message.make_query(name, 'TXT', want_dnssec=True)
            query.flags |= dns.flags.AD
            self._sock.send(query.to_wire())

        for i in range(count):
            print(i)
            self._sock.settimeout(5.0)
            data = self._sock.recv(4096)
            res = dns.message.from_wire(data)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertMessageIsAuthenticated(res)
            self.assertRRsetInAnswer(res, exp)
            self.assertMatchingRRSIGInAnswer(res, exp)
        self._sock.settimeout(None)
