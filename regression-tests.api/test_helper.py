from datetime import datetime
import os
import requests
import urlparse
import unittest

DAEMON = os.environ.get('DAEMON', 'authoritative')


class ApiTestCase(unittest.TestCase):

    def setUp(self):
        # TODO: config
        self.server_address = '127.0.0.1'
        self.server_port = int(os.environ.get('WEBPORT', '5580'))
        self.server_url = 'http://%s:%s/' % (self.server_address, self.server_port)
        self.session = requests.Session()
        self.session.auth = ('admin', os.environ.get('WEBPASSWORD', 'changeme'))

    def url(self, relative_url):
        return urlparse.urljoin(self.server_url, relative_url)

    def assert_success_json(self, result):
        try:
            result.raise_for_status()
        except:
            print result.content
            raise
        self.assertEquals(result.headers['Content-Type'], 'application/json')


def unique_zone_name():
    return 'test-' + datetime.now().strftime('%d%H%S%M%f') + '.org'


def is_auth():
    return DAEMON == 'authoritative'


def is_recursor():
    return DAEMON == 'recursor'
