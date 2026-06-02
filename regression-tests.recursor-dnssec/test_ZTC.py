import time
import os
import subprocess

from recursortests import RecursorTest


class ZTCTest(RecursorTest):
    _confdir = "ZTC"
    _config_template = """
dnssec:
    validation: validate
    trustanchors:
        - name: .
          dsrecords:
              - %s
recordcache:
    zonetocaches:
    - zone: .
      method: axfr
      sources:
          - %s.8
"""
    _config_params = ["_root_DS", "_PREFIX"]

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(ZTCTest, cls).generateRecursorYamlConfig(confdir, False)

    def testZTC(self):
        grepCmd = ["grep", 'validationStatus="Secure"', "configs/" + self._confdir + "/recursor.log"]
        ret = b""
        for i in range(3000):
            time.sleep(0.01)
            try:
                ret = subprocess.check_output(grepCmd, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                continue
            print(b"A" + ret)
            break
        print(ret)
        self.assertNotEqual(ret, b"")


class ZTCIgnoreZoneMDTest(ZTCTest):
    _confdir = "ZTCIgnoreZoneMD"
    _config_template = """
dnssec:
    validation: validate
    trustanchors:
        - name: .
          dsrecords:
              - %s
recordcache:
    zonetocaches:
    - zone: .
      method: axfr
      zonemd: ignore
      sources:
          - %s.8
"""
    _config_params = ["_root_DS", "_PREFIX"]

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(ZTCTest, cls).generateRecursorYamlConfig(confdir, False)
