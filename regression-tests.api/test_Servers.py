import requests
import unittest
from test_helper import ApiTestCase, is_auth, is_recursor


class Servers(ApiTestCase):

    def test_list_servers(self):
        r = self.session.get(self.url("/api/v1/servers"))
        self.assert_success_json(r)
        lst = r.json()
        self.assertEquals(len(lst), 1)  # only localhost allowed in there
        data = lst[0]
        for k in ('id', 'daemon_type', 'url'):
            self.assertIn(k, data)
        self.assertEquals(data['id'], 'localhost')

    def test_servers_localhost(self):
        r = self.session.get(self.url("/api/v1/servers/localhost"))
        self.assert_success_json(r)
        data = r.json()
        for k in ('id', 'type', 'version', 'daemon_type', 'url', 'zones_url', 'config_url'):
            self.assertIn(k, data)
        self.assertEquals(data['id'], 'localhost')
        self.assertEquals(data['type'], 'Server')
        # or 'recursor' for recursors
        if is_auth():
            daemon_type = 'authoritative'
        elif is_recursor():
            daemon_type = 'recursor'
        else:
            raise RuntimeError('Unknown daemon type')
        self.assertEquals(data['daemon_type'], daemon_type)

    def test_read_config(self):
        r = self.session.get(self.url("/api/v1/servers/localhost/config"))
        self.assert_success_json(r)
        data = dict([(r['name'], r['value']) for r in r.json()])
        self.assertIn('daemon', data)

    def test_read_statistics(self):
        r = self.session.get(self.url("/api/v1/servers/localhost/statistics"))
        self.assert_success_json(r)
        data = r.json()
        self.assertIn('uptime', [e['name'] for e in data])
        if is_auth():
            print(data)
            qtype_stats, respsize_stats, queries_stats, rcode_stats = None, None, None, None
            for elem in data:
                if elem['type'] == 'MapStatisticItem' and elem['name'] == 'response-by-qtype':
                    qtype_stats = elem['value']
                elif elem['type'] == 'MapStatisticItem' and elem['name'] == 'response-sizes':
                    respsize_stats = elem['value']
                elif elem['type'] == 'RingStatisticItem' and elem['name'] == 'queries':
                    queries_stats = elem['value']
                elif elem['type'] == 'MapStatisticItem' and elem['name'] == 'response-by-rcode':
                    rcode_stats = elem['value']
            self.assertIn('A', [e['name'] for e in qtype_stats])
            self.assertIn('60', [e['name'] for e in respsize_stats])
            self.assertIn('example.com/A', [e['name'] for e in queries_stats])
            self.assertIn('No Error', [e['name'] for e in rcode_stats])

    def test_read_one_statistic(self):
        r = self.session.get(self.url("/api/v1/servers/localhost/statistics?statistic=uptime"))
        self.assert_success_json(r)
        data = r.json()
        self.assertIn('uptime', [e['name'] for e in data])

    def test_read_one_non_existent_statistic(self):
        r = self.session.get(self.url("/api/v1/servers/localhost/statistics?statistic=uptimeAAAA"))
        self.assertEquals(r.status_code, 422)
        self.assertIn("Unknown statistic name", r.json()['error'])

    def test_read_metrics(self):
        if is_recursor():
            res = self.session.get(self.url("/metrics"), auth=('whatever', self.webServerBasicAuthPassword), timeout=2.0)
            self.assertEqual(res.status_code, 200)
            # print(res.text)
            found = False
            for line in res.text.splitlines():
                if line[0] == "#":
                    continue
                if line.split(" ")[0] == "pdns_recursor_uptime":
                    found = True
            self.assertTrue(found,"pdns_recursor_uptime is missing")
            
    @unittest.skipIf(is_auth(), "Not applicable")
    def test_read_statistics_using_password(self):
        r = requests.get(self.url("/api/v1/servers/localhost/statistics"), auth=('admin', self.server_web_password))
        self.assertEquals(r.status_code, requests.codes.ok)
        self.assert_success_json(r)
