from test_helper import ApiTestCase, is_auth, is_recursor, sdig
import unittest


class Servers(ApiTestCase):

    def test_flush(self):
        r = self.session.put(self.url("/api/v1/servers/localhost/cache/flush?domain=example.org."))
        self.assert_success_json(r)
        data = r.json()
        self.assertIn('count', data)

    @unittest.skipIf(not is_recursor(), "Not applicable")
    def test_flush_count(self):
        sdig("ns1.example.com", 'A')
        r = self.session.put(self.url("/api/v1/servers/localhost/cache/flush?domain=ns1.example.com."))
        self.assert_success_json(r)
        data = r.json()
        self.assertIn('count', data)
        self.assertEquals(1, data['count'])

    @unittest.skipIf(not is_recursor(), "Not applicable")
    def test_flush_subtree(self):
        sdig("ns1.example.com", 'A')
        sdig("ns2.example.com", 'A')
        r = self.session.put(self.url("/api/v1/servers/localhost/cache/flush?domain=example.com.&subtree=false"))
        self.assert_success_json(r)
        data = r.json()
        self.assertIn('count', data)
        self.assertEquals(1, data['count'])
        r = self.session.put(self.url("/api/v1/servers/localhost/cache/flush?domain=example.com.&subtree=true"))
        self.assert_success_json(r)
        data = r.json()
        self.assertIn('count', data)
        self.assertEquals(2, data['count'])

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
