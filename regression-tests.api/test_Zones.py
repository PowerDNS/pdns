import unittest
import requests
from test_helper import ApiTestCase


class Servers(ApiTestCase):

    def test_ListZones(self):
        r = self.session.get(self.url("/servers/localhost/zones"))
        self.assertSuccessJson(r)
        data = r.json()
        self.assertIn('domains', data)
        domains = data['domains']
        example_com = [domain for domain in domains if domain['name'] == u'example.com']
        self.assertEquals(len(example_com), 1)
        example_com = example_com[0]
        for k in ('name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial'):
            self.assertIn(k, example_com)
