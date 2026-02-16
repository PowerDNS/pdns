#!/usr/bin/env python
import os
import requests
import subprocess
import unittest
from dnsdisttests import DNSDistTest, pickAvailablePort

@unittest.skipIf('SKIP_PROMETHEUS_TESTS' in os.environ, 'Prometheus tests are disabled')
class TestPrometheus(DNSDistTest):

    _webTimeout = 2.0
    _webServerPort = pickAvailablePort()
    _webServerBasicAuthPassword = 'secret'
    _webServerBasicAuthPasswordHashed = '$scrypt$ln=10,p=1,r=8$6DKLnvUYEeXWh3JNOd3iwg==$kSrhdHaRbZ7R74q3lGBqO1xetgxRxhmWzYJ2Qvfm7JM='
    _webServerAPIKey = 'apisecret'
    _webServerAPIKeyHashed = '$scrypt$ln=10,p=1,r=8$9v8JxDfzQVyTpBkTbkUqYg==$bDQzAOHeK1G9UvTPypNhrX48w974ZXbFPtRKS34+aso='
    _config_params = ['_testServerPort', '_webServerPort', '_webServerBasicAuthPasswordHashed', '_webServerAPIKeyHashed']
    _config_template = """
    newServer{address="127.0.0.1:%s"}
    webserver("127.0.0.1:%s")
    setWebserverConfig({password="%s", apiKey="%s"})
    pc = newPacketCache(100, {maxTTL=86400, minTTL=1})
    getPool(""):setCache(pc)

    -- test custom metrics as well
    declareMetric('custom-metric1', 'counter', 'Custom counter')
    incMetric('custom-metric1')
    declareMetric('custom-metric2', 'gauge', 'Custom gauge')
    -- and custom names
    declareMetric('custom-metric3', 'counter', 'Custom counter', 'custom_prometheus_name')

    -- test prometheus labels in custom metrics
    declareMetric('custom-metric-foo', 'counter', 'Custom counter with labels', { withLabels = true })
    incMetric('custom-metric-foo', { labels = { x = 'bar', y = 'xyz' } })
    incMetric('custom-metric-foo', { labels = { x = 'baz', y = 'abc' } })
    """

    def checkPrometheusContentBasic(self, content):
        linesSeen = {}
        keysSeen = {}
        for line in content.splitlines():
            if line in linesSeen:
                raise AssertionError(f"Duplicate line in prometheus output: '{line}'")
            linesSeen[line] = True
            if line.startswith('# HELP'):
                tokens = line.split(' ')
                self.assertGreaterEqual(len(tokens), 4)
            elif line.startswith('# TYPE'):
                tokens = line.split(' ')
                self.assertEqual(len(tokens), 4)
                self.assertIn(tokens[3], ['counter', 'gauge', 'histogram'])
            elif not line.startswith('#'):
                tokens = line.split(' ')
                self.assertEqual(len(tokens), 2)
                if not line.startswith('dnsdist_') and not line.startswith('custom_'):
                    raise AssertionError(
                        'Expecting prometheus metric to be prefixed by \'dnsdist_\', got: "%s"' % (line))
                key = tokens[0]
                if key in keysSeen:
                    raise AssertionError(f"Duplicate prometheus key: '{key}'")
                keysSeen[key] = True

    def checkMetric(self, content, name, expectedType, expectedValue, expectedLabels=""):
        typeFound = False
        helpFound = False
        valueFound = False
        labelsFound = False
        if expectedLabels == "":
            labelsFound = True
        for line in content.splitlines():
            if name in str(line):
                tokens = line.split(' ')
                if line.startswith('# HELP'):
                    self.assertGreaterEqual(len(tokens), 4)
                    if tokens[2] == name:
                        helpFound = True
                elif line.startswith('# TYPE'):
                    self.assertEqual(len(tokens), 4)
                    if tokens[2] == name:
                        typeFound = True
                        self.assertEqual(tokens[3], expectedType)
                elif not line.startswith('#'):
                    self.assertEqual(len(tokens), 2)
                    if tokens[0] == name:
                        valueFound = True
                        self.assertEqual(int(tokens[1]), expectedValue)
                    elif tokens[0] == name + expectedLabels:
                        valueFound = True
                        labelsFound = True
                        self.assertEqual(int(tokens[1]), expectedValue)

        self.assertTrue(typeFound)
        self.assertTrue(helpFound)
        self.assertTrue(valueFound)
        self.assertTrue(labelsFound)

    def checkPrometheusContentPromtool(self, content):
        output = None
        try:
            testcmd = ['promtool', 'check', 'metrics']
            process = subprocess.Popen(testcmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
            output = process.communicate(input=content)
        except subprocess.CalledProcessError as exc:
            raise AssertionError('%s failed (%d): %s' % (testcmd, process.returncode, process.output))

        # commented out because promtool returns 3 because of the "_total" suffix warnings
        #if process.returncode != 0:
        #  raise AssertionError('%s failed (%d): %s' % (testcmd, process.returncode, output))

        for line in output[0].splitlines():
            if line.endswith(b"should have \"_total\" suffix"):
                continue
            raise AssertionError('%s returned an unexpected output. Faulty line is "%s", complete content is "%s"' % (testcmd, line, output))

    def testMetrics(self):
        """
        Prometheus: Retrieve metrics
        """
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/metrics'
        r = requests.get(url, auth=('whatever', self._webServerBasicAuthPassword), timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.checkPrometheusContentBasic(r.text)
        self.checkPrometheusContentPromtool(r.content)
        self.checkMetric(r.text, 'dnsdist_custom_metric1', 'counter', 1)
        self.checkMetric(r.text, 'dnsdist_custom_metric2', 'gauge', 0)
        self.checkMetric(r.text, 'custom_prometheus_name', 'counter', 0)
        self.checkMetric(r.text, 'dnsdist_custom_metric_foo', 'counter', 1, '{x="bar",y="xyz"}')
        self.checkMetric(r.text, 'dnsdist_custom_metric_foo', 'counter', 1, '{x="baz",y="abc"}')
