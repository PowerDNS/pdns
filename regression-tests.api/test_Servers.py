import unittest
import requests
from test_helper import ApiTestCase, isAuth, isRecursor


class Servers(ApiTestCase):

    def test_ListServers(self):
        r = self.session.get(self.url("/servers"))
        self.assertSuccessJson(r)
        lst = r.json()
        self.assertEquals(len(lst), 1)  # only localhost allowed in there
        data = lst[0]
        for k in ('id', 'daemon_type', 'url'):
            self.assertIn(k, data)
        self.assertEquals(data['id'], 'localhost')

    def test_ServersLocalhost(self):
        r = self.session.get(self.url("/servers/localhost"))
        self.assertSuccessJson(r)
        data = r.json()
        for k in ('id', 'type', 'version', 'daemon_type', 'url', 'zones_url', 'config_url'):
            self.assertIn(k, data)
        self.assertEquals(data['id'], 'localhost')
        self.assertEquals(data['type'], 'Server')
        # or 'recursor' for recursors
        if isAuth():
            daemon_type = 'authoritative'
        elif isRecursor():
            daemon_type = 'recursor'
        self.assertEquals(data['daemon_type'], daemon_type)

    def test_ReadConfig(self):
        r = self.session.get(self.url("/servers/localhost/config"))
        self.assertSuccessJson(r)
        data = dict([(r['name'], r['value']) for r in r.json()])
        self.assertIn('daemon', data)

    def test_ReadStatistics(self):
        r = self.session.get(self.url("/servers/localhost/statistics"))
        self.assertSuccessJson(r)
        data = dict([(r['name'], r['value']) for r in r.json()])
        self.assertIn('uptime', data)
