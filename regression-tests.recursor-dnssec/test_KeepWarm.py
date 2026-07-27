import dns
import os
import time
from recursortests import RecursorTest


class KeepWarmTest(RecursorTest):
    _confdir = "KeepWarm"
    _auth_zones = RecursorTest._default_auth_zones

    _config_template = """
recursor:
    taskthreads: 2 # not actually needed, but just to cover the non-default case
recordcache:
  keepwarm:
    - qname: secure.example
    - qname: cname-to-secure.insecure.example.
    - qname: nonexistent.secure.example
"""

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(KeepWarmTest, cls).generateRecursorYamlConfig(confdir)

    @classmethod
    def startRecursor(cls, confdir, port):
        super(KeepWarmTest, cls).startRecursor(confdir, port)
        # we want to delay a bit, as the tasks are run asynchronously. This is a race of course...
        time.sleep(2)

    def testCacheContent(self):
        confdir = os.path.join("configs", self._confdir)
        ret = self.recControl(confdir, "dump-cache", "-", "r")
        found = 0
        for i in ret.splitlines():
            pieces = i.split(" ")
            if len(pieces) == 14:
                # print(pieces)
                if pieces[0] == "secure.example." and pieces[4] == "A":
                    found += 1
                elif pieces[0] == "cname-to-secure.insecure.example." and pieces[4] == "CNAME":
                    found += 1
                elif pieces[0] == "host1.secure.example." and pieces[4] == "A":
                    found += 1

        self.assertEqual(found, 3)

    def testNegCacheContent(self):
        confdir = os.path.join("configs", self._confdir)
        ret = self.recControl(confdir, "dump-cache", "-", "n")
        found = 0
        for i in ret.splitlines():
            pieces = i.split(" ")
            if len(pieces) == 10:
                print(pieces)
                if pieces[0] == "nonexistent.secure.example." and pieces[3] == "TYPE0":
                    found += 1

        self.assertEqual(found, 1)
