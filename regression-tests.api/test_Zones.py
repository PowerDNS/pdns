import json
import requests
import unittest
from test_helper import ApiTestCase, unique_zone_name


class Servers(ApiTestCase):

    def test_ListZones(self):
        r = self.session.get(self.url("/servers/localhost/zones"))
        self.assertSuccessJson(r)
        domains = r.json()
        example_com = [domain for domain in domains if domain['name'] == u'example.com']
        self.assertEquals(len(example_com), 1)
        example_com = example_com[0]
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial'):
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
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEquals(data[k], payload[k])

    @unittest.expectedFailure
    def test_CreateZoneWithSymbols(self):
        payload = {
            'name': 'foo/bar.'+unique_zone_name(),
            'kind': 'Native',
            'nameservers': ['ns1.foo.com', 'ns2.foo.com']
        }
        expected_id = payload['name']
        expected_id.replace('/', '\047')
        r = self.session.post(
            self.url("/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        data = r.json()
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEquals(data[k], payload[k])
        self.assertEquals(data[k], expected_id)

    def test_GetZone(self):
        r = self.session.get(self.url("/servers/localhost/zones"))
        domains = r.json()
        example_com = [domain for domain in domains if domain['name'] == u'example.com'][0]
        r = self.session.get(self.url("/servers/localhost/zones/" + example_com['id']))
        self.assertSuccessJson(r)
        data = r.json()
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial'):
            self.assertIn(k, data)
        self.assertEquals(data['name'], 'example.com')
