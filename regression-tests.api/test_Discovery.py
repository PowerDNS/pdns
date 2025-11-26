from test_helper import ApiTestCase


class DiscoveryTest(ApiTestCase):
    def test_discovery(self):
        r = self.session.get(self.url("/api"))
        self.assert_success_json(r)
        lst = r.json()
        self.assertEqual(lst, [{"version": 1, "url": "/api/v1"}])

        r = self.session.get(self.url("/api/v1"))
        self.assert_success_json(r)
        lst = r.json()
        self.assertEqual(lst, [{"api_features": [], "server_url": "/api/v1/servers{/server}"}])
