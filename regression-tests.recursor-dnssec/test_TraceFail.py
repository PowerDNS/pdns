import dns
import os
import time
import subprocess
from recursortests import RecursorTest

class testTraceFail(RecursorTest):
    _confdir = 'TraceFail'

    _config_template = """
trace=fail
forward-zones-recurse=.=127.0.0.1:9999
"""

    @classmethod
    def setUpClass(cls):

        # we don't need all the auth stuff
        cls.setUpSockets()
        cls.startResponders()

        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)

        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

    @classmethod
    def tearDownClass(cls):
        cls.tearDownRecursor()

    def testA(self):
        query = dns.message.make_query('example', 'A', want_dnssec=False)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        grepCmd = ['grep', 'END OF FAIL TRACE', 'configs/' + self._confdir + '/recursor.log']
        ret = b''
        for i in range(10):
            time.sleep(1)
            try:
                ret = subprocess.check_output(grepCmd, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                continue
            print(b'A' + ret)
            break
        print(ret)
        self.assertNotEqual(ret, b'')
