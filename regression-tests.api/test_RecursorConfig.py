import json
import requests
import unittest
from test_helper import ApiTestCase, isRecursor


@unittest.skipIf(not isRecursor(), "Only applicable to recursors")
class RecursorConfig(ApiTestCase):

    def test_ConfigAllowFromGet(self):
        r = self.session.get(self.url("/servers/localhost/config/allow-from"))
        self.assertSuccessJson(r)

    def test_ConfigAllowFromReplace(self):
        payload = ["127.0.0.1"]
        r = self.session.put(
            self.url("/servers/localhost/config/allow-from"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        data = r.json()
        self.assertEquals("127.0.0.1/32", data[0])
