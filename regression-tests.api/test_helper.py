import requests
import urlparse
import unittest
import os

class ApiTestCase(unittest.TestCase):

    def setUp(self):
        # TODO: config
        self.server_url = 'http://127.0.0.1:%s/' % (os.environ.get('WEBPORT','5580'))
        self.session = requests.Session()
        self.session.auth = ('admin', os.environ.get('WEBPASSWORD','changeme'))

    def url(self, relative_url):
        return urlparse.urljoin(self.server_url, relative_url)

    def assertSuccessJson(self, result):
        result.raise_for_status()
        self.assertEquals(result.headers['Content-Type'], 'application/json')
