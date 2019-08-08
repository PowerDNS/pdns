from ixfrdisttests import IXFRDistTest
import time
import requests

xfrServerPort = 4244

class IXFRDistStatsTest(IXFRDistTest):
    """
    This test makes sure we have statistics in ixfrdist
    """

    webserver_address = '127.0.0.1:8080'

    _config_params = ['_ixfrDistPort', 'webserver_address']

    _config_template = """
listen:
  - '127.0.0.1:%d'
acl:
  - '127.0.0.0/8'
axfr-timeout: 20
keep: 20
tcp-in-threads: 1
work-dir: 'ixfrdist.dir'
failed-soa-retry: 3
webserver-address: %s
"""

    _config_domains = {'example': '127.0.0.1:' + str(xfrServerPort)}

    metric_prog_stats = ["ixfrdist_uptime_seconds", "ixfrdist_domains"]
    metric_domain_stats = ["ixfrdist_soa_serial", "ixfrdist_soa_checks",
                           "ixfrdist_soa_checks_failed",
                           "ixfrdist_soa_inqueries",
                           "ixfrdist_axfr_inqueries", "ixfrdist_axfr_failures",
                           "ixfrdist_ixfr_inqueries", "ixfrdist_ixfr_failures"]

    @classmethod
    def setUpClass(cls):
        cls.startIXFRDist()
        cls.setUpSockets()
        time.sleep(3)

    @classmethod
    def tearDownClass(cls):
        cls.tearDownIXFRDist()

    def test_program_stats_exist(self):
        res = requests.get('http://{}/metrics'.format(self.webserver_address))
        self.assertEqual(res.status_code, 200)
        for line in res.text.splitlines():
            if line[0] == "#":
                continue
            if "{" in line:
                continue
            self.assertIn(line.split(" ")[0],
                          self.metric_prog_stats + self.metric_domain_stats)

    def test_registered(self):
        res = requests.get('http://{}/metrics'.format(self.webserver_address))
        self.assertEqual(res.status_code, 200)
        for line in res.text.splitlines():
            if line.startswith('ixfrdist_domains'):
                self.assertEqual(line, 'ixfrdist_domains 1')
                continue
            if line[0] == "#":
                continue
            if "{" not in line:
                continue
            self.assertIn('{domain=example}', line)
            self.assertIn(line.split("{")[0], self.metric_domain_stats)

    def test_metrics_have_help(self):
        res = requests.get('http://{}/metrics'.format(self.webserver_address))
        self.assertEqual(res.status_code, 200)
        for s in self.metric_prog_stats + self.metric_domain_stats:
            self.assertIn('# HELP {}'.format(s), res.text)

    def test_metrics_have_type(self):
        res = requests.get('http://{}/metrics'.format(self.webserver_address))
        self.assertEqual(res.status_code, 200)
        for s in self.metric_prog_stats + self.metric_domain_stats:
            self.assertIn('# TYPE {}'.format(s), res.text)

    def test_missing_metrics(self):
        all_metrics = set()

        res = requests.get('http://{}/metrics'.format(self.webserver_address))
        self.assertEqual(res.status_code, 200)

        for line in res.text.splitlines():
            if line[0] == "#":
                all_metrics.add(line.split(" ")[2])
                continue
            if "{" in line:
                all_metrics.add(line.split("{")[0])
                continue
            all_metrics.add(line.split(" ")[0])

        should_have_metrics = set(self.metric_prog_stats +
                                  self.metric_domain_stats)

        unknown_metrics = all_metrics - should_have_metrics

        self.assertSetEqual(unknown_metrics, set())
