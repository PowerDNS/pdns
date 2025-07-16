import dns
import os
import time
import subprocess
from recursortests import RecursorTest

class TraceFailTest(RecursorTest):
    _confdir = 'TraceFail'

    _config_template = """
trace=fail
forward-zones-recurse=.=127.0.0.1:9999
"""

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
