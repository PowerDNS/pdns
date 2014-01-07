import unittest
import requests
from test_helper import ApiTestCase


class TestBasics(ApiTestCase):

    def test_Unauth(self):
        r = requests.get(self.url("/servers/localhost"))
        self.assertEquals(r.status_code, requests.codes.unauthorized)
