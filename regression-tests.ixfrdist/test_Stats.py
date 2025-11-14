from ixfrdisttests import IXFRDistTest
import time
import requests
import subprocess

xfrServerPort = 4244


class IXFRDistStatsTest(IXFRDistTest):
    """
    This test makes sure we have statistics in ixfrdist
    """

    webserver_address = "127.0.0.1:8080"

    _config_params = ["_ixfrDistPort", "webserver_address"]

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

    _config_domains = [{"domain": "example", "master": "127.0.0.1:" + str(xfrServerPort)}]

    metric_prog_stats = [
        "ixfrdist_uptime_seconds",
        "ixfrdist_domains",
        "ixfrdist_unknown_domain_inqueries_total",
        "ixfrdist_sys_msec",
        "ixfrdist_user_msec",
        "ixfrdist_real_memory_usage",
        "ixfrdist_fd_usage",
        "ixfrdist_notimp",
    ]
    metric_domain_stats = [
        "ixfrdist_soa_serial",
        "ixfrdist_soa_checks_total",
        "ixfrdist_soa_checks_failed_total",
        "ixfrdist_soa_inqueries_total",
        "ixfrdist_axfr_inqueries_total",
        "ixfrdist_axfr_failures_total",
        "ixfrdist_ixfr_inqueries_total",
        "ixfrdist_ixfr_failures_total",
    ]

    @classmethod
    def setUpClass(cls):
        cls.startIXFRDist()
        cls.setUpSockets()
        time.sleep(3)

    @classmethod
    def tearDownClass(cls):
        cls.tearDownIXFRDist()

    def checkPrometheusContentPromtool(self, content):
        output = None
        try:
            testcmd = ["promtool", "check", "metrics"]
            process = subprocess.Popen(
                testcmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True
            )
            output = process.communicate(input=content)
        except subprocess.CalledProcessError as exc:
            raise AssertionError("%s failed (%d): %s" % (testcmd, process.returncode, process.output))

        # commented out because promtool returns 3 because of the "_total" suffix warnings
        # if process.returncode != 0:
        #    raise AssertionError('%s failed (%d): %s' % (testcmd, process.returncode, output))

        for line in output[0].splitlines():
            if line.endswith(b'should have "_total" suffix'):
                continue
            raise AssertionError(
                '%s returned an unexpected output. Faulty line is "%s", complete content is "%s"'
                % (testcmd, line, output)
            )

    def test_program_stats_exist(self):
        res = requests.get("http://{}/metrics".format(self.webserver_address))
        self.assertEqual(res.status_code, 200)
        for line in res.text.splitlines():
            if line[0] == "#":
                continue
            if "{" in line:
                continue
            tokens = line.split(" ")
            self.assertIn(tokens[0], self.metric_prog_stats + self.metric_domain_stats)
            if tokens[0] == "ixfrdist_unknown_domain_inqueries_total":
                self.assertEqual(int(tokens[1]), 0)

        self.checkPrometheusContentPromtool(res.content)

    def test_registered(self):
        res = requests.get("http://{}/metrics".format(self.webserver_address))
        self.assertEqual(res.status_code, 200)
        for line in res.text.splitlines():
            if line.startswith("ixfrdist_domains"):
                self.assertEqual(line, "ixfrdist_domains 1")
                continue
            if line[0] == "#":
                continue
            if "{" not in line:
                continue
            self.assertIn('{domain="example"}', line)
            self.assertIn(line.split("{")[0], self.metric_domain_stats)

    def test_metrics_have_help(self):
        res = requests.get("http://{}/metrics".format(self.webserver_address))
        self.assertEqual(res.status_code, 200)
        for s in self.metric_prog_stats + self.metric_domain_stats:
            self.assertIn("# HELP {}".format(s), res.text)

    def test_metrics_have_type(self):
        res = requests.get("http://{}/metrics".format(self.webserver_address))
        self.assertEqual(res.status_code, 200)
        for s in self.metric_prog_stats + self.metric_domain_stats:
            self.assertIn("# TYPE {}".format(s), res.text)

    def test_missing_metrics(self):
        all_metrics = set()

        res = requests.get("http://{}/metrics".format(self.webserver_address))
        self.assertEqual(res.status_code, 200)

        for line in res.text.splitlines():
            if line[0] == "#":
                all_metrics.add(line.split(" ")[2])
                continue
            if "{" in line:
                all_metrics.add(line.split("{")[0])
                continue
            all_metrics.add(line.split(" ")[0])

        should_have_metrics = set(self.metric_prog_stats + self.metric_domain_stats)

        unknown_metrics = all_metrics - should_have_metrics

        self.assertSetEqual(unknown_metrics, set())
