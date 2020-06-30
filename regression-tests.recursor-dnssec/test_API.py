import os
import requests

from recursortests import RecursorTest

class APIRecursorTest(RecursorTest):

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

class APIAllowedRecursorTest(APIRecursorTest):
    _confdir = 'API'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'

    _config_template = """
webserver=yes
webserver-port=%d
webserver-address=127.0.0.1
webserver-password=%s
webserver-allow-from=127.0.0.1
api-key=%s
""" % (_wsPort, _wsPassword, _apiKey)

    def testAPI(self):
        headers = {'x-api-key': self._apiKey}
        url = 'http://127.0.0.1:' + str(self._wsPort) + '/api/v1/servers/localhost/statistics'
        r = requests.get(url, headers=headers, timeout=self._wsTimeout)
        self.assertTrue(r)
        self.assertEquals(r.status_code, 200)
        self.assertTrue(r.json())

class APIDeniedRecursorTest(APIRecursorTest):
    _confdir = 'API'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'

    _config_template = """
webserver=yes
webserver-port=%d
webserver-address=127.0.0.1
webserver-password=%s
webserver-allow-from=192.0.2.1
api-key=%s
""" % (_wsPort, _wsPassword, _apiKey)

    def testAPI(self):
        headers = {'x-api-key': self._apiKey}
        url = 'http://127.0.0.1:' + str(self._wsPort) + '/api/v1/servers/localhost/statistics'
        try:
            r = requests.get(url, headers=headers, timeout=self._wsTimeout)
            self.assertTrue(False)
        except requests.exceptions.ConnectionError as exp:
            pass
