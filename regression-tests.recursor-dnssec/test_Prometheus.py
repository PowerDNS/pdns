import requests
import subprocess

from recursortests import RecursorTest

class RecPrometheusTest(RecursorTest):
 
    def checkPrometheusContentBasic(self, content):
        for line in content.splitlines():
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
                if not line.startswith('pdns_recursor_'):
                    raise AssertionError('Expecting prometheus metric to be prefixed by \'pdns_recursor_\', got: "%s"' % (line))

    def checkPrometheusContentPromtool(self, content):
        output = None
        try:
            testcmd = ['promtool', 'check', 'metrics']
            process = subprocess.Popen(testcmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
            output = process.communicate(input=content)
        except subprocess.CalledProcessError as exc:
            raise AssertionError('%s failed (%d): %s' % (testcmd, process.returncode, process.output))

        # promtool returns 3 because of the "_total" suffix warnings
        if not process.returncode in [0, 3]:
          raise AssertionError('%s failed (%d): %s' % (testcmd, process.returncode, output))

        for line in output[0].splitlines():
            if line.endswith(b"should have \"_total\" suffix"):
                continue
            raise AssertionError('%s returned an unexpected output. Faulty line is "%s", complete content is "%s"' % (testcmd, line, output))

class BasicPrometheusTest(RecPrometheusTest):
    _confdir = 'BasicPrometheus'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'

    _lua_dns_script_file = """
    getMetric('metric_just_a_name')
    getMetric('metric_wpn', 'pdns_recursor_metric_with_name')
    getMetric('metric_extra', {prometheusName = 'pdns_recursor_metric_with_name2', type = 'gauge', description = 'desc'})
"""

    _config_template = """
webserver=yes
webserver-port=%d
webserver-address=127.0.0.1
webserver-password=%s
webserver-allow-from=127.0.0.1
api-key=%s
""" % (_wsPort, _wsPassword, _apiKey)

    def testPrometheus(self):
        self.waitForTCPSocket("127.0.0.1", self._wsPort)
        url = 'http://user:' + self._wsPassword + '@127.0.0.1:' + str(self._wsPort) + '/metrics'
        r = requests.get(url, timeout=self._wsTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.checkPrometheusContentBasic(r.text)
        self.checkPrometheusContentPromtool(r.content)

class HttpsPrometheusTest(RecPrometheusTest):
    _confdir = 'HttpsPrometheus'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'

    _lua_dns_script_file = """
    getMetric('metric_just_a_name')
    getMetric('metric_wpn', 'pdns_recursor_metric_with_name')
    getMetric('metric_extra', {prometheusName = 'pdns_recursor_metric_with_name2', type = 'gauge', description = 'desc'})
"""

    _config_template = """
webservice:
  webserver: true
  listen:
   - addresses: [127.0.0.1:%s]
     tls:
       certificate: server.chain
       key: server.key
  password: %s
  allow_from: [127.0.0.1]
  api_key: %s
""" % (_wsPort, _wsPassword, _apiKey)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(HttpsPrometheusTest, cls).generateRecursorYamlConfig(confdir)

    def testPrometheus(self):
        self.waitForTCPSocket("127.0.0.1", self._wsPort)
        url = 'https://user:' + self._wsPassword + '@127.0.0.1:' + str(self._wsPort) + '/metrics'
        r = requests.get(url, timeout=self._wsTimeout, verify='ca.pem')
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.checkPrometheusContentBasic(r.text)
        self.checkPrometheusContentPromtool(r.content)
