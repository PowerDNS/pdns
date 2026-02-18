import os

import dns
import extendederrors
import pytest
import shutil
from recursortests import RecursorTest

class ExpiredTest(RecursorTest):
    """This regression test starts the authoritative servers with a clock that is
    set 15 days into the past. Hence, the recursor must reject the signatures
    because they are expired.
    """
    _confdir = 'Expired'
    _auth_zones = RecursorTest._default_auth_zones

    _config_template = """dnssec=validate"""

    _auth_env = {'LD_PRELOAD':os.environ.get('LIBFAKETIME'),
                 'FAKETIME':'-15d'}

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

class ExpiredWithEDETest(RecursorTest):
    """This regression test starts the authoritative servers with a clock that is
    set 15 days into the past. Hence, the recursor must reject the signatures
    because they are expired.
    """
    _confdir = 'ExpiredWithEDE'
    _auth_zones = RecursorTest._default_auth_zones

    _config_template = """
    dnssec=validate
    extended-resolution-errors=yes
    """

    _auth_env = {'LD_PRELOAD':os.environ.get('LIBFAKETIME'),
                 'FAKETIME':'-15d'}
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
        qname = 'host1.secure.example'
        query = dns.message.make_query(qname, 'A', want_dnssec=True)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query, timeout=5.0)
            self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
            self.assertEqual(res.edns, 0)
            self.assertEqual(len(res.options), 1)
            self.assertEqual(res.options[0].otype, 15)
            self.assertEqual(res.options[0], extendederrors.ExtendedErrorOption(7, b''))
