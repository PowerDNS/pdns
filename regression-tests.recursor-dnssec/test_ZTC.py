import time
import os
import subprocess
import threading
import http.server
import socketserver

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


class ZTCHTTPTest(RecursorTest):
    _confdir = "ZTCHTTP"
    _config_template = """
dnssec:
    validation: off
recordcache:
    zonetocaches:
    - zone: .
      method: url
      sources:
          - http://127.0.0.1:4247/root.zone
      retry_on_error_period: 1
"""

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(ZTCHTTPTest, cls).generateRecursorYamlConfig(confdir, False)

    @classmethod
    def runServer(cls):
        port = 4247
        socketserver.TCPServer.allow_reuse_address = True
        handler = http.server.SimpleHTTPRequestHandler
        cls._httpd = socketserver.TCPServer(("127.0.0.1", port), handler)
        cls._httpd.serve_forever()

    @classmethod
    def startResponders(cls):
        cls._listener = threading.Thread(name="HTTP Listener", target=cls.runServer)
        cls._listener.daemon = True
        cls._listener.start()

    @classmethod
    def tearDownResponders(cls):
        cls._httpd.shutdown()
        cls._httpd.server_close()

    def reloadConfig(self, config):
        confdir = os.path.join("configs", ZTCHTTPTest._confdir)
        ZTCHTTPTest._config_template = config
        ZTCHTTPTest.generateRecursorYamlConfig(confdir, False)
        ZTCHTTPTest.recControl(confdir, "reload-yaml")

    def testZTC(self):
        grepCmd = ["grep", 'msg="Loaded zone into cache"', "configs/" + self._confdir + "/recursor.log"]
        ret = b""
        for i in range(3000):
            time.sleep(0.01)
            try:
                ret = subprocess.check_output(grepCmd, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                continue
            print(b"A" + ret)
            break
        self.assertNotEqual(ret, b"")


class ZTCHTTPFailedTest(RecursorTest):
    _confdir = "ZTCHTTPFailed"
    _config_template = """
dnssec:
    validation: off
recordcache:
    zonetocaches:
    - zone: .
      method: url
      sources:
          - http://127.0.0.1:4247/root.zone
      retry_on_error_period: 1
      max_received_mbytes: 2
"""

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(ZTCHTTPFailedTest, cls).generateRecursorYamlConfig(confdir, False)

    @classmethod
    def runServer(cls):
        port = 4247
        socketserver.TCPServer.allow_reuse_address = True
        handler = http.server.SimpleHTTPRequestHandler
        cls._httpd = socketserver.TCPServer(("127.0.0.1", port), handler)
        cls._httpd.serve_forever()

    @classmethod
    def startResponders(cls):
        cls._listener = threading.Thread(name="HTTP Listener", target=cls.runServer)
        cls._listener.daemon = True
        cls._listener.start()

    @classmethod
    def tearDownResponders(cls):
        cls._httpd.shutdown()
        cls._httpd.server_close()

    def testZTC(self):
        grepCmd = [
            "grep",
            'error="Retrieved data exceeds maxReceivedBytes"',
            "configs/" + self._confdir + "/recursor.log",
        ]
        ret = b""
        for i in range(3000):
            time.sleep(0.01)
            try:
                ret = subprocess.check_output(grepCmd, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                continue
            print(b"A" + ret)
            break
        self.assertNotEqual(ret, b"")
