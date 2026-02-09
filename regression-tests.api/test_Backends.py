from __future__ import print_function
import json
import operator
import unittest
import requests.exceptions
from test_helper import ApiTestCase, is_auth, is_auth_lmdb, BACKEND

@unittest.skipIf(not is_auth(), "Not applicable")
class AuthBackends(ApiTestCase):

    def test_storage_version(self):
        # Require a json answer to GET
        self.session.headers['Content-Type'] = 'application/json'
        r = self.session.get(self.url("/api/v1/servers/localhost/backends/" + BACKEND + "/storageversion"))
        if is_auth_lmdb():
            self.assertEqual(r.status_code, 200)
            self.assertGreater(r.json()['storageversion'], 5)
        else:
            self.assertEqual(r.status_code, 422)

