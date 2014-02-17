import json
import requests
import unittest
from test_helper import ApiTestCase, unique_zone_name, isAuth, isRecursor


class Zones(ApiTestCase):

    def test_ListZones(self):
        r = self.session.get(self.url("/servers/localhost/zones"))
        self.assertSuccessJson(r)
        domains = r.json()
        example_com = [domain for domain in domains if domain['name'] in ('example.com', 'example.com.')]
        self.assertEquals(len(example_com), 1)
        example_com = example_com[0]
        required_fields = ['id', 'url', 'name', 'kind']
        if isAuth():
            required_fields = required_fields + ['masters', 'last_check', 'notified_serial', 'serial']
        elif isRecursor():
            required_fields = required_fields + ['recursion_desired', 'servers']
        for field in required_fields:
            self.assertIn(field, example_com)


@unittest.skipIf(not isAuth(), "Not applicable")
class AuthZones(ApiTestCase):

    def create_zone(self, name=None, nameservers=None):
        if name is None:
            name = unique_zone_name()
        payload = {
            'name': name,
            'kind': 'Native',
            'nameservers': ['ns1.example.com', 'ns2.example.com']
        }
        if nameservers is not None:
            payload['nameservers'] = nameservers
        r = self.session.post(
            self.url("/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        return (payload, r.json())

    def test_CreateZone(self):
        payload, data = self.create_zone()
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEquals(data[k], payload[k])

    def test_CreateZoneWithSymbols(self):
        payload, data = self.create_zone(name='foo/bar.'+unique_zone_name())
        name = payload['name']
        expected_id = (name.replace('/', '=47')) + '.'
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEquals(data[k], payload[k])
        self.assertEquals(data['id'], expected_id)

    def test_GetZoneWithSymbols(self):
        payload, data = self.create_zone(name='foo/bar.'+unique_zone_name())
        name = payload['name']
        zone_id = (name.replace('/', '=47')) + '.'
        r = self.session.get(self.url("/servers/localhost/zones/" + zone_id))
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEquals(data[k], payload[k])

    def test_GetZone(self):
        r = self.session.get(self.url("/servers/localhost/zones"))
        domains = r.json()
        example_com = [domain for domain in domains if domain['name'] == u'example.com'][0]
        r = self.session.get(self.url("/servers/localhost/zones/" + example_com['id']))
        self.assertSuccessJson(r)
        data = r.json()
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial'):
            self.assertIn(k, data)
        self.assertEquals(data['name'], 'example.com')

    def test_UpdateZone(self):
        payload, zone = self.create_zone()
        name = payload['name']
        # update, set as Master
        payload = {
            'kind': 'Master',
            'masters': ['192.0.2.1','192.0.2.2']
        }
        r = self.session.put(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        data = r.json()
        for k in payload.keys():
            self.assertIn(k, data)
            self.assertEquals(data[k], payload[k])
        # update, back to Native
        payload = {
            'kind': 'Native'
        }
        r = self.session.put(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        data = r.json()
        for k in payload.keys():
            self.assertIn(k, data)
            self.assertEquals(data[k], payload[k])

    def test_ZoneRRUpdate(self):
        payload, zone = self.create_zone()
        name = payload['name']
        # do a replace (= update)
        payload = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'records': [
                {
                    "name": name,
                    "type": "NS",
                    "priority": 0,
                    "ttl": 3600,
                    "content": "ns1.bar.com",
                    "disabled": False
                },
                {
                    "name": name,
                    "type": "NS",
                    "priority": 0,
                    "ttl": 1800,
                    "content": "ns2-disabled.bar.com",
                    "disabled": True
                }
            ]
        }
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name + "/rrset"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        # verify that (only) the new record is there
        r = self.session.get(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        data = r.json()['records']
        recs = [rec for rec in data if rec['type'] == payload['type'] and rec['name'] == payload['name']]
        self.assertEquals(recs, payload['records'])

    def test_ZoneRRDelete(self):
        payload, zone = self.create_zone()
        name = payload['name']
        # do a delete of all NS records (these are created with the zone)
        payload = {
            'changetype': 'delete',
            'name': name,
            'type': 'NS'
        }
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name + "/rrset"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        # verify that the records are gone
        r = self.session.get(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        data = r.json()['records']
        recs = [rec for rec in data if rec['type'] == payload['type'] and rec['name'] == payload['name']]
        self.assertEquals(recs, [])

    def test_ZoneDisableReenable(self):
        payload, zone = self.create_zone()
        name = payload['name']
        # disable zone by disabling SOA
        payload = {
            'changetype': 'replace',
            'name': name,
            'type': 'SOA',
            'records': [
                {
                    "name": name,
                    "type": "SOA",
                    "priority": 0,
                    "ttl": 3600,
                    "content": "ns1.bar.com hostmaster.foo.org 1 1 1 1 1",
                    "disabled": True
                }
            ]
        }
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name + "/rrset"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        # make sure it's still in zone list
        r = self.session.get(self.url("/servers/localhost/zones"))
        domains = r.json()
        self.assertEquals(len([domain for domain in domains if domain['name'] == name]), 1)
        # verify that modifying it still works
        payload['records'][0]['disabled'] = False
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name + "/rrset"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)

    def test_ZoneRRUpdateQTypeMismatch(self):
        payload, zone = self.create_zone()
        name = payload['name']
        # replace with qtype mismatch
        payload = {
            'changetype': 'replace',
            'name': name,
            'type': 'A',
            'records': [
                {
                    "name": name,
                    "type": "NS",
                    "priority": 0,
                    "ttl": 3600,
                    "content": "ns1.bar.com",
                    "disabled": False
                }
            ]
        }
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name + "/rrset"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEquals(r.status_code, 422)

    def test_ZoneRRUpdateQNameMismatch(self):
        payload, zone = self.create_zone()
        name = payload['name']
        # replace with qname mismatch
        payload = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'records': [
                {
                    "name": 'blah.'+name,
                    "type": "NS",
                    "priority": 0,
                    "ttl": 3600,
                    "content": "ns1.bar.com",
                    "disabled": False
                }
            ]
        }
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name + "/rrset"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEquals(r.status_code, 422)

    def test_ZoneRRUpdateOutOfZone(self):
        payload, zone = self.create_zone()
        name = payload['name']
        # replace with qname mismatch
        payload = {
            'changetype': 'replace',
            'name': 'not-in-zone',
            'type': 'NS',
            'records': [
                {
                    "name": name,
                    "type": "NS",
                    "priority": 0,
                    "ttl": 3600,
                    "content": "ns1.bar.com",
                    "disabled": False
                }
            ]
        }
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name + "/rrset"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEquals(r.status_code, 422)
        self.assertIn('out of zone', r.json()['error'])

    def test_ZoneRRDeleteOutOfZone(self):
        payload, zone = self.create_zone()
        name = payload['name']
        # replace with qname mismatch
        payload = {
            'changetype': 'delete',
            'name': 'not-in-zone',
            'type': 'NS'
        }
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name + "/rrset"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEquals(r.status_code, 422)
        self.assertIn('out of zone', r.json()['error'])


@unittest.skipIf(not isRecursor(), "Not applicable")
class RecursorZones(ApiTestCase):

    def test_CreateAuthZone(self):
        payload = {
            'name': unique_zone_name(),
            'kind': 'Native',
            'recursion_desired': False
        }
        r = self.session.post(
            self.url("/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        data = r.json()
        # return values are normalized
        payload['name'] += '.'
        for k in payload.keys():
            self.assertEquals(data[k], payload[k])

    def test_CreateForwardedZone(self):
        payload = {
            'name': unique_zone_name(),
            'kind': 'Forwarded',
            'servers': ['8.8.8.8'],
            'recursion_desired': False
        }
        r = self.session.post(
            self.url("/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        data = r.json()
        # return values are normalized
        payload['servers'][0] += ':53'
        payload['name'] += '.'
        for k in payload.keys():
            self.assertEquals(data[k], payload[k])

    def test_CreateForwardedRDZone(self):
        payload = {
            'name': 'google.com',
            'kind': 'Forwarded',
            'servers': ['8.8.8.8'],
            'recursion_desired': True
        }
        r = self.session.post(
            self.url("/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        data = r.json()
        # return values are normalized
        payload['servers'][0] += ':53'
        payload['name'] += '.'
        for k in payload.keys():
            self.assertEquals(data[k], payload[k])

    def test_CreateAuthZoneWithSymbols(self):
        payload = {
            'name': 'foo/bar.'+unique_zone_name(),
            'kind': 'Native',
            'recursion_desired': False
        }
        r = self.session.post(
            self.url("/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        data = r.json()
        # return values are normalized
        payload['name'] += '.'
        expected_id = (payload['name'].replace('/', '=47'))
        for k in payload.keys():
            self.assertEquals(data[k], payload[k])
        self.assertEquals(data['id'], expected_id)

    def test_RenameAuthZone(self):
        name = unique_zone_name()+'.'
        payload = {
            'name': name,
            'kind': 'Native',
            'recursion_desired': False
        }
        r = self.session.post(
            self.url("/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        # now rename it
        payload = {
            'name': 'renamed-'+name,
            'kind': 'Native',
            'recursion_desired': False
        }
        r = self.session.put(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        data = r.json()
        for k in payload.keys():
            self.assertEquals(data[k], payload[k])
