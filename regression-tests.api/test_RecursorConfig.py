import json
import unittest
from test_helper import ApiTestCase, is_recursor


@unittest.skipIf(not is_recursor(), "Only applicable to recursors")
class RecursorConfig(ApiTestCase):

    def test_config_allow_from_get(self):
        r = self.session.get(self.url("/api/v1/servers/localhost/config/allow-from"))
        self.assert_success_json(r)

    def test_config_allow_from_replace(self):
        payload = {'value': ["127.0.0.1"]}
        r = self.session.put(
            self.url("/api/v1/servers/localhost/config/allow-from"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        data = r.json()
        self.assertIn("value", data)
        self.assertEquals(len(data["value"]), 1)
        self.assertEquals("127.0.0.1/32", data["value"][0])

    def test_config_allow_from_replace_error(self):
        """Test the error case, should return 422."""
        payload = {'value': ["abcdefgh"]}
        r = self.session.put(
            self.url("/api/v1/servers/localhost/config/allow-from"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEquals(r.status_code, 422)
        data = r.json()
        self.assertIn('Unable to convert', data['error'])
