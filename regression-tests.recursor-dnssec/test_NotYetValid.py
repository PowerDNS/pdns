import os
import dns
import pytest
import shutil
from recursortests import RecursorTest


class NotYetValidTest(RecursorTest):
    """This regression test starts the authoritative servers with a clock that is
    set 15 days into the future. Hence, the recursor must reject the signatures
    because they are not yet valid.
    """
    _confdir = 'NotYetValid'

    _config_template = """dnssec=validate"""

    _auth_env = {'LD_PRELOAD':os.environ.get('LIBFAKETIME'),
                 'FAKETIME':'+15d'}

    @classmethod
    def setUpClass(cls):
        cls.setUpClassSpecialAuths()
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        confdir = os.path.join('configs', 'auths')
        print("Specialized auth teardown " + confdir)
        # tear down specialized auths, and then start standard ones
        super().tearDownClass(True)
        print("Starting default auths")
        #confdir = 'configs/auths'
        shutil.rmtree(confdir, True)
        os.mkdir(confdir)
        # Be careful here, we don't want the overridden secureZone(), so call RecursorTest explicitly
        RecursorTest.generateAllAuthConfig(confdir)
        RecursorTest.startAllAuth(confdir)

    def testA(self):
        query = dns.message.make_query('host1.secure.example', 'A')
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
