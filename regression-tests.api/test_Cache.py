from test_helper import ApiTestCase, is_auth, is_recursor


class Servers(ApiTestCase):

    def test_flush(self):
        r = self.session.put(self.url("/api/v1/servers/localhost/cache/flush?domain=example.org."))
        self.assert_success_json(r)
        data = r.json()
        self.assertIn('count', data)

    def test_flush_root(self):
        r = self.session.put(self.url("/api/v1/servers/localhost/cache/flush?domain=."))
        self.assert_success_json(r)
        data = r.json()
        self.assertIn('count', data)
        self.assertEqual(data['result'], 'Flushed cache.')

    def test_flush_no_domain(self):
        r = self.session.put(
            self.url("/api/v1/servers/localhost/cache/flush"))
        self.assertEquals(r.status_code, 422)

    def test_flush_unqualified(self):
        r = self.session.put(
            self.url("/api/v1/servers/localhost/cache/flush?domain=bar"))
        self.assertEquals(r.status_code, 422)
