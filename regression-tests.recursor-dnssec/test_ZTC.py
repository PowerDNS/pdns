import dns
import time
import os
import subprocess

from recursortests import RecursorTest

class testZTC(RecursorTest):

    _confdir = 'ZTC'
    _config_template = """
dnssec=validate
"""
    _lua_config_file = """
zoneToCache(".", "axfr", "193.0.14.129") -- k-root
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

    def testZTC(self):
        grepCmd = ['grep', 'validationStatus="Secure"', 'configs/' + self._confdir + '/recursor.log']
        ret = b''
        for i in range(30):
            time.sleep(1)
            try:
                ret = subprocess.check_output(grepCmd, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                continue
            print(b'A' + ret)
            break
        print(ret)
        self.assertNotEqual(ret, b'')

