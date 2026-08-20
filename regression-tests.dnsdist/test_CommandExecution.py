#!/usr/bin/env python
import base64
import json
import os
import subprocess
from dnsdisttests import DNSDistTest


class TestSingleCommandExecution(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")

    _config_params = ["_consoleKeyB64", "_consolePort", "_testServerPort"]
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}

    pc = newPacketCache(100)
    getPool(""):setCache(pc)
    """

    def testSingleCommandExecution(self):
        """
        Single command execution
        """
        confFile = os.path.join("configs", "dnsdist_%s.conf" % (self.__class__.__name__))
        testcmd = [os.environ["DNSDISTBIN"], "-C", confFile, "-e", "getPool(''):getCache():getStats()"]
        result = subprocess.run(testcmd, capture_output=True, timeout=2, check=True)
        if result.returncode != 0:
            raise AssertionError("%s failed (%d): %s / %s" % (testcmd, result.returncode, result.stdout, result.stderr))

        values = json.loads(result.stdout)
        for key in ["hits", "misses", "entries"]:
            self.assertIn(key, values)
