import os
import requests

from recursortests import RecursorTest

class APIAllowedRecursorTest(RecursorTest):
    _confdir = 'APIAllowedRecursor'
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
        self.waitForTCPSocket("127.0.0.1", self._wsPort)
        headers = {'x-api-key': self._apiKey}
        url = 'http://127.0.0.1:' + str(self._wsPort) + '/api/v1/servers/localhost/statistics'
        r = requests.get(url, headers=headers, timeout=self._wsTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())

class APIDeniedRecursorTest(RecursorTest):
    _confdir = 'APIDeniedRecursor'
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
        self.waitForTCPSocket("127.0.0.1", self._wsPort)
        headers = {'x-api-key': self._apiKey}
        url = 'http://127.0.0.1:' + str(self._wsPort) + '/api/v1/servers/localhost/statistics'
        try:
            requests.get(url, headers=headers, timeout=self._wsTimeout)
            self.fail()
        except requests.exceptions.ConnectionError as exp:
            pass
