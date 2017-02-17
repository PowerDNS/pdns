#!/usr/bin/env python
import os.path

import json
import requests
from dnsdisttests import DNSDistTest

class TestAPIBasics(DNSDistTest):

    _webTimeout = 2.0
    _webServerPort = 8083
    _webServerBasicAuthPassword = 'secret'
    _webServerAPIKey = 'apisecret'
    # paths accessible using the API key
    _apiPaths = ['/api/v1/servers/localhost', '/api/v1/servers/localhost/config', '/api/v1/servers/localhost/config/allow-from', '/api/v1/servers/localhost/statistics', '/jsonstat?command=stats', '/jsonstat?command=dynblocklist']
    # paths accessible using basic auth only (list not exhaustive)
    _basicOnlyPaths = ['/', '/index.html']
    _config_params = ['_testServerPort', '_webServerPort', '_webServerBasicAuthPassword', '_webServerAPIKey']
    _config_template = """
    setACL({"127.0.0.1/32", "::1/128"})
    newServer{address="127.0.0.1:%s"}
    webserver("127.0.0.1:%s", "%s", "%s")
    """

    def testBasicAuth(self):
        """
        API: Basic Authentication
        """
        for path in self._basicOnlyPaths + self._apiPaths:
            url = 'http://127.0.0.1:' + str(self._webServerPort) + path
            r = requests.get(url, auth=('whatever', self._webServerBasicAuthPassword), timeout=self._webTimeout)
            self.assertTrue(r)
            self.assertEquals(r.status_code, 200)

    def testXAPIKey(self):
        """
        API: X-Api-Key
        """
        headers = {'x-api-key': self._webServerAPIKey}
        for path in self._apiPaths:
            url = 'http://127.0.0.1:' + str(self._webServerPort) + path
            r = requests.get(url, headers=headers, timeout=self._webTimeout)
            self.assertTrue(r)
            self.assertEquals(r.status_code, 200)

    def testBasicAuthOnly(self):
        """
        API: Basic Authentication Only
        """
        headers = {'x-api-key': self._webServerAPIKey}
        for path in self._basicOnlyPaths:
            url = 'http://127.0.0.1:' + str(self._webServerPort) + path
            r = requests.get(url, headers=headers, timeout=self._webTimeout)
            self.assertEquals(r.status_code, 401)

    def testServersLocalhost(self):
        """
        API: /api/v1/servers/localhost
        """
        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/api/v1/servers/localhost'
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEquals(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()

        self.assertEquals(content['daemon_type'], 'dnsdist')

        for key in ['version', 'acl', 'local', 'rules', 'response-rules', 'servers', 'frontends']:
            self.assertIn(key, content)

        for rule in content['rules']:
            for key in ['id', 'matches', 'rule', 'action']:
                self.assertIn(key, rule)
            for key in ['id', 'matches']:
                self.assertTrue(rule[key] >= 0)

        for rule in content['response-rules']:
            for key in ['id', 'matches', 'rule', 'action']:
                self.assertIn(key, rule)
            for key in ['id', 'matches']:
                self.assertTrue(rule[key] >= 0)

        for server in content['servers']:
            for key in ['id', 'latency', 'name', 'weight', 'outstanding', 'qpsLimit',
                        'reuseds', 'state', 'address', 'pools', 'qps', 'queries', 'order']:
                self.assertIn(key, server)

            for key in ['id', 'latency', 'weight', 'outstanding', 'qpsLimit', 'reuseds',
                        'qps', 'queries', 'order']:
                self.assertTrue(server[key] >= 0)

            self.assertTrue(server['state'] in ['up', 'down', 'UP', 'DOWN'])

        for frontend in content['frontends']:
            for key in ['id', 'address', 'udp', 'tcp', 'queries']:
                self.assertIn(key, frontend)

            for key in ['id', 'queries']:
                self.assertTrue(frontend[key] >= 0)

    def testServersLocalhostConfig(self):
        """
        API: /api/v1/servers/localhost/config
        """
        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/api/v1/servers/localhost/config'
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEquals(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        values = {}
        for entry in content:
            for key in ['type', 'name', 'value']:
                self.assertIn(key, entry)

            self.assertEquals(entry['type'], 'ConfigSetting')
            values[entry['name']] = entry['value']

        for key in ['acl', 'control-socket', 'ecs-override', 'ecs-source-prefix-v4',
                    'ecs-source-prefix-v6', 'fixup-case', 'max-outstanding', 'server-policy',
                    'stale-cache-entries-ttl', 'tcp-recv-timeout', 'tcp-send-timeout',
                    'truncate-tc', 'verbose', 'verbose-health-checks']:
            self.assertIn(key, values)

        for key in ['max-outstanding', 'stale-cache-entries-ttl', 'tcp-recv-timeout',
                    'tcp-send-timeout']:
            self.assertTrue(values[key] >= 0)

        self.assertTrue(values['ecs-source-prefix-v4'] >= 0 and values['ecs-source-prefix-v4'] <= 32)
        self.assertTrue(values['ecs-source-prefix-v6'] >= 0 and values['ecs-source-prefix-v6'] <= 128)

    def testServersLocalhostConfigAllowFrom(self):
        """
        API: /api/v1/servers/localhost/config/allow-from
        """
        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/api/v1/servers/localhost/config/allow-from'
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEquals(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        for key in ['type', 'name', 'value']:
            self.assertIn(key, content)

        self.assertEquals(content['name'], 'allow-from')
        self.assertEquals(content['type'], 'ConfigSetting')
        self.assertEquals(content['value'], ["127.0.0.1/32", "::1/128"])

    def testServersLocalhostConfigAllowFromPut(self):
        """
        API: PUT /api/v1/servers/localhost/config/allow-from (should be refused)

        The API is read-only by default, so this should be refused
        """
        newACL = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]
        payload = json.dumps({"name": "allow-from",
                              "type": "ConfigSetting",
                              "value": newACL})
        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/api/v1/servers/localhost/config/allow-from'
        r = requests.put(url, headers=headers, timeout=self._webTimeout, data=payload)
        self.assertFalse(r)
        self.assertEquals(r.status_code, 405)

    def testServersLocalhostStatistics(self):
        """
        API: /api/v1/servers/localhost/statistics
        """
        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/api/v1/servers/localhost/statistics'
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEquals(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        values = {}
        for entry in content:
            self.assertIn('type', entry)
            self.assertIn('name', entry)
            self.assertIn('value', entry)
            self.assertEquals(entry['type'], 'StatisticItem')
            values[entry['name']] = entry['value']

        expected = ['responses', 'servfail-responses', 'queries', 'acl-drops', 'block-filter',
                    'rule-drop', 'rule-nxdomain', 'rule-refused', 'self-answered', 'downstream-timeouts',
                    'downstream-send-errors', 'trunc-failures', 'no-policy', 'latency0-1',
                    'latency1-10', 'latency10-50', 'latency50-100', 'latency100-1000',
                    'latency-slow', 'latency-avg100', 'latency-avg1000', 'latency-avg10000',
                    'latency-avg1000000', 'uptime', 'real-memory-usage', 'noncompliant-queries',
                    'noncompliant-responses', 'rdqueries', 'empty-queries', 'cache-hits',
                    'cache-misses', 'cpu-user-msec', 'cpu-sys-msec', 'fd-usage', 'dyn-blocked',
                    'dyn-block-nmg-size']

        for key in expected:
            self.assertIn(key, values)
            self.assertTrue(values[key] >= 0)

        for key in values:
            self.assertIn(key, expected)

    def testJsonstatStats(self):
        """
        API: /jsonstat?command=stats
        """
        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/jsonstat?command=stats'
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEquals(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()

        expected = ['responses', 'servfail-responses', 'queries', 'acl-drops', 'block-filter',
                    'rule-drop', 'rule-nxdomain', 'rule-refused', 'self-answered', 'downstream-timeouts',
                    'downstream-send-errors', 'trunc-failures', 'no-policy', 'latency0-1',
                    'latency1-10', 'latency10-50', 'latency50-100', 'latency100-1000',
                    'latency-slow', 'latency-avg100', 'latency-avg1000', 'latency-avg10000',
                    'latency-avg1000000', 'uptime', 'real-memory-usage', 'noncompliant-queries',
                    'noncompliant-responses', 'rdqueries', 'empty-queries', 'cache-hits',
                    'cache-misses', 'cpu-user-msec', 'cpu-sys-msec', 'fd-usage', 'dyn-blocked',
                    'dyn-block-nmg-size', 'packetcache-hits', 'packetcache-misses', 'over-capacity-drops',
                    'too-old-drops']

        for key in expected:
            self.assertIn(key, content)
            self.assertTrue(content[key] >= 0)

    def testJsonstatDynblocklist(self):
        """
        API: /jsonstat?command=dynblocklist
        """
        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/jsonstat?command=dynblocklist'
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEquals(r.status_code, 200)

        content = r.json()

        if content:
            for key in ['reason', 'seconds', 'blocks']:
                self.assertIn(key, content)

            for key in ['blocks']:
                self.assertTrue(content[key] >= 0)

class TestAPIServerDown(DNSDistTest):

    _webTimeout = 2.0
    _webServerPort = 8083
    _webServerBasicAuthPassword = 'secret'
    _webServerAPIKey = 'apisecret'
    # paths accessible using the API key
    _config_params = ['_testServerPort', '_webServerPort', '_webServerBasicAuthPassword', '_webServerAPIKey']
    _config_template = """
    setACL({"127.0.0.1/32", "::1/128"})
    newServer{address="127.0.0.1:%s"}
    getServer(0):setDown()
    webserver("127.0.0.1:%s", "%s", "%s")
    """

    def testServerDownNoLatencyLocalhost(self):
        """
        API: /api/v1/servers/localhost, no latency for a down server
        """
        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/api/v1/servers/localhost'
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEquals(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()

        self.assertEquals(content['servers'][0]['latency'], None)

class TestAPIWritable(DNSDistTest):

    _webTimeout = 2.0
    _webServerPort = 8083
    _webServerBasicAuthPassword = 'secret'
    _webServerAPIKey = 'apisecret'
    _APIWriteDir = '/tmp'
    _config_params = ['_testServerPort', '_webServerPort', '_webServerBasicAuthPassword', '_webServerAPIKey', '_APIWriteDir']
    _config_template = """
    setACL({"127.0.0.1/32", "::1/128"})
    newServer{address="127.0.0.1:%s"}
    webserver("127.0.0.1:%s", "%s", "%s")
    setAPIWritable(true, "%s")
    """

    def testSetACL(self):
        """
        API: Set ACL
        """
        headers = {'x-api-key': self._webServerAPIKey}
        url = 'http://127.0.0.1:' + str(self._webServerPort) + '/api/v1/servers/localhost/config/allow-from'
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEquals(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        self.assertEquals(content['value'], ["127.0.0.1/32", "::1/128"])

        newACL = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]
        payload = json.dumps({"name": "allow-from",
                              "type": "ConfigSetting",
                              "value": newACL})
        r = requests.put(url, headers=headers, timeout=self._webTimeout, data=payload)
        self.assertTrue(r)
        self.assertEquals(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        self.assertEquals(content['value'], newACL)

        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEquals(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        self.assertEquals(content['value'], newACL)

        configFile = self._APIWriteDir + '/' + 'acl.conf'
        self.assertTrue(os.path.isfile(configFile))
        fileContent = None
        with file(configFile) as f:
            fileContent = f.read()

        self.assertEquals(fileContent, """-- Generated by the REST API, DO NOT EDIT
setACL({"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"})
""")
