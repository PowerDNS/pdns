# this tests Networks

import subprocess
import json
import unittest
import os

from test_helper import ApiTestCase, is_auth, is_auth_lmdb, pdnsutil

@unittest.skipIf(not is_auth(), "Not applicable")
@unittest.skipIf(not is_auth_lmdb(), "Views require the LMDB backend")
class Networks(ApiTestCase):
    def setUp(self):
        super(Networks, self).setUp()

    def tearDown(self):
        super(Networks, self).tearDown()

    def test_networks(self):
        r = self.set_network('192.0.2.0/24', view='view1')
        self.assertEqual(r.status_code, 204)
        self.assertEqual(r.content, b"")

        # Check network presence
        nets = self.get_networks()
        self.assertEqual(nets['192.0.2.0/24'], 'view1')

        # Check individual fetch
        r = self.get_network('192.0.2.0/24')
        print(r.content)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['networks'][0], dict(network='192.0.2.0/24', view='view1'))  # FIXME: should this really be wrapped inside `networks:`?

        # empty view name is equivalent to delete
        r = self.set_network('192.0.2.0/24', view='')
        print(r.content)
        self.assertEqual(r.status_code, 204)
        self.assertEqual(r.content, b"")

        # Check network absence
        nets = self.get_networks()
        self.assertNotIn('192.0.2.0/24', nets)

        # Check individual fetch
        r = self.get_network('192.0.2.0/24')
        print(r.content)
        self.assertEqual(r.status_code, 404)

    def set_network(self, prefix, **content):
        r = self.session.put(
            self.url("/api/v1/servers/localhost/networks/"+prefix),
            data=json.dumps(content),
            headers={'content-type': 'application/json'})

        return r

    def get_network(self, prefix):
        r = self.session.get(
            self.url("/api/v1/servers/localhost/networks/"+prefix),
            headers={'content-type': 'application/json'})

        return r

    def get_networks(self):
        r = self.session.get(
            self.url("/api/v1/servers/localhost/networks"),
            headers={'content-type': 'application/json'})

        ret = {}

        for netview in r.json()['networks']:
            net = netview['network']
            view = netview['view']
            self.assertNotIn(net, ret)
            ret[net] = view

        return ret
