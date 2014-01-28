import json
import requests
import unittest
from test_helper import ApiTestCase, unique_zone_name


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

    def test_CreateZone(self):
        payload = {
            'name': unique_zone_name(),
            'kind': 'Native',
            'nameservers': ['ns1.foo.com', 'ns2.foo.com']
        }
        r = self.session.post(
            self.url("/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        data = r.json()
        for k in ('name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEquals(data[k], payload[k])
