import os
import dns
import pytest
from recursortests import RecursorTest


@pytest.mark.skip(reason="changes auth config")
class NotYetValidTest(RecursorTest):
    """This regression test starts the authoritative servers with a clock that is
    set 15 days into the future. Hence, the recursor must reject the signatures
    because they are not yet valid.
    """
    _confdir = 'NotYetValid'

    _config_template = """dnssec=validate"""

    _auth_env = {'LD_PRELOAD':os.environ.get('LIBFAKETIME'),
                 'FAKETIME':'+15d'}

    def testA(self):
        query = dns.message.make_query('host1.secure.example', 'A')
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
