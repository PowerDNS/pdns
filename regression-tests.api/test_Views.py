# this tests Networks and Views

import json
import unittest

from test_helper import ApiTestCase, is_auth, is_auth_lmdb
from test_Zones import AuthZonesHelperMixin


@unittest.skipIf(not is_auth(), "Not applicable")
@unittest.skipIf(not is_auth_lmdb(), "Views require the LMDB backend")
class Networks(ApiTestCase):
    def setUp(self):
        super(Networks, self).setUp()

    def tearDown(self):
        super(Networks, self).tearDown()

    def test_networks(self):
        r = self.set_network("192.0.2.0/24", view="view1")
        self.assertEqual(r.status_code, 204)
        self.assertEqual(r.content, b"")

        # Check network presence
        nets = self.get_networks()
        self.assertEqual(nets["192.0.2.0/24"], "view1")

        # Check individual fetch
        r = self.get_network("192.0.2.0/24")
        print(r.content)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), dict(network="192.0.2.0/24", view="view1"))

        # empty view name is equivalent to delete
        r = self.set_network("192.0.2.0/24", view="")
        print(r.content)
        self.assertEqual(r.status_code, 204)
        self.assertEqual(r.content, b"")

        # Check network absence
        nets = self.get_networks()
        self.assertNotIn("192.0.2.0/24", nets)

        # Check individual fetch
        r = self.get_network("192.0.2.0/24")
        print(r.content)
        self.assertEqual(r.status_code, 404)

    def set_network(self, prefix, **content):
        r = self.session.put(
            self.url("/api/v1/servers/localhost/networks/" + prefix),
            data=json.dumps(content),
            headers={"content-type": "application/json"},
        )

        return r

    def get_network(self, prefix):
        r = self.session.get(
            self.url("/api/v1/servers/localhost/networks/" + prefix), headers={"content-type": "application/json"}
        )

        return r

    def get_networks(self):
        r = self.session.get(
            self.url("/api/v1/servers/localhost/networks"), headers={"content-type": "application/json"}
        )

        ret = {}

        for netview in r.json()["networks"]:
            net = netview["network"]
            view = netview["view"]
            self.assertNotIn(net, ret)
            ret[net] = view

        return ret


@unittest.skipIf(not is_auth(), "Not applicable")
@unittest.skipIf(not is_auth_lmdb(), "Views require the LMDB backend")
class Views(ApiTestCase, AuthZonesHelperMixin):
    def setUp(self):
        super(Views, self).setUp()
        self.create_zone("example.com..spiceoflife")

    def tearDown(self):
        super(Views, self).tearDown()
        self.session.delete(self.url("/api/v1/servers/localhost/zones/example.com..spiceoflife"))

    def _test_views(self, variant=""):
        zone = "example.com." + variant
        r = self.set_view_zone("view1", zone)
        self.assertEqual(r.status_code, 204)
        self.assertEqual(r.content, b"")

        # Check view presence
        r = self.get_views()
        self.assertEqual(r.status_code, 200)
        self.assertIn("view1", r.json()["views"])

        # Check individual fetch
        r = self.get_view("view1")
        print(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["zones"], [zone])

        r = self.del_view_zone("view1", zone)
        print(r.content)
        self.assertEqual(r.status_code, 204)
        self.assertEqual(r.content, b"")

        # Check view absence
        r = self.get_views()
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("view1", r.json()["views"])

        # Check individual fetch
        r = self.get_view("view1")
        print(r.content)
        self.assertEqual(r.status_code, 404)

    def test_zonelist_variant(self):
        r = self.session.get(self.url("/api/v1/servers/localhost/zones"), headers={"content-type": "application/json"})

        self.assertEqual(r.status_code, 200)
        self.assertIn("example.com..spiceoflife", [obj["name"] for obj in r.json()])

    def test_views_novariant(self):
        return self._test_views()

    def test_views_variant(self):
        return self._test_views(".spiceoflife")

    def set_view_zone(self, view, zone):
        r = self.session.post(
            self.url("/api/v1/servers/localhost/views/" + view),
            data=json.dumps(dict(name=zone)),
            headers={"content-type": "application/json"},
        )

        self.assertEqual(r.status_code, 204)

        return r

    def del_view_zone(self, view, zone):
        r = self.session.delete(
            self.url("/api/v1/servers/localhost/views/" + view + "/" + zone),
            data=json.dumps(dict(name=zone)),
            headers={"content-type": "application/json"},
        )

        self.assertEqual(r.status_code, 204)

        return r

    def get_view(self, view):
        r = self.session.get(
            self.url("/api/v1/servers/localhost/views/" + view), headers={"content-type": "application/json"}
        )

        return r

    def get_views(self):
        r = self.session.get(self.url("/api/v1/servers/localhost/views"), headers={"content-type": "application/json"})

        self.assertEqual(r.status_code, 200)

        return r
