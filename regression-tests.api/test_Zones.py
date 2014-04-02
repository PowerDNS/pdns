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
        self.assertEquals(data['comments'], [])

    def test_CreateZoneTrailingDot(self):
        # Trailing dots should not end up in the zone name.
        basename = unique_zone_name()
        payload, data = self.create_zone(name=basename+'.')
        self.assertEquals(data['name'], basename)

    def test_CreateZoneWithSymbols(self):
        payload, data = self.create_zone(name='foo/bar.'+unique_zone_name())
        name = payload['name']
        expected_id = (name.replace('/', '=2F')) + '.'
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEquals(data[k], payload[k])
        self.assertEquals(data['id'], expected_id)

    def test_GetZoneWithSymbols(self):
        payload, data = self.create_zone(name='foo/bar.'+unique_zone_name())
        name = payload['name']
        zone_id = (name.replace('/', '=2F')) + '.'
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
        r = self.session.get(self.url("/servers/localhost/zones/" + name))
        data = r.json()['records']
        recs = [rec for rec in data if rec['type'] == payload['type'] and rec['name'] == payload['name']]
        self.assertEquals(recs, payload['records'])

    def test_ZoneRRUpdateMX(self):
        # Important to test with MX records, as they have a priority field, which must not end up in the content field.
        payload, zone = self.create_zone()
        name = payload['name']
        # do a replace (= update)
        payload = {
            'changetype': 'replace',
            'name': name,
            'type': 'MX',
            'records': [
                {
                    "name": name,
                    "type": "MX",
                    "priority": 10,
                    "ttl": 3600,
                    "content": "mail.example.org",
                    "disabled": False
                }
            ]
        }
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name + "/rrset"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        # verify that (only) the new record is there
        r = self.session.get(self.url("/servers/localhost/zones/" + name))
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
        r = self.session.get(self.url("/servers/localhost/zones/" + name))
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

    def test_ZoneCommentCreate(self):
        payload, zone = self.create_zone()
        name = payload['name']
        payload = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'comments': [
                {
                    'account': 'test1',
                    'content': 'blah blah',
                },
                {
                    'account': 'test2',
                    'content': 'blah blah bleh',
                }
            ]
        }
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        # make sure the comments have been set, and that the NS
        # records are still present
        r = self.session.get(self.url("/servers/localhost/zones/" + name))
        data = r.json()
        print data
        self.assertNotEquals([r for r in data['records'] if r['type'] == 'NS'], [])
        self.assertNotEquals(data['comments'], [])
        # verify that modified_at has been set by pdns
        self.assertNotEquals([c for c in data['comments']][0]['modified_at'], 0)

    def test_ZoneCommentDelete(self):
        # Test: Delete ONLY comments.
        payload, zone = self.create_zone()
        name = payload['name']
        payload = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'comments': []
        }
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        # make sure the NS records are still present
        r = self.session.get(self.url("/servers/localhost/zones/" + name))
        data = r.json()
        print data
        self.assertNotEquals([r for r in data['records'] if r['type'] == 'NS'], [])
        self.assertEquals(data['comments'], [])

    def test_ZoneCommentStayIntact(self):
        # Test if comments on an rrset stay intact if the rrset is replaced
        payload, zone = self.create_zone()
        name = payload['name']
        # create a comment
        payload = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'comments': [
                {
                    'account': 'test1',
                    'content': 'oh hi there',
                    'modified_at': 1111,
                    'name': name,  # only for assertEquals, ignored by pdns
                    'type': 'NS'   # only for assertEquals, ignored by pdns
                }
            ]
        }
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        # replace rrset records
        payload2 = {
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
                }
            ]
        }
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload2),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        # make sure the comments still exist
        r = self.session.get(self.url("/servers/localhost/zones/" + name))
        data = r.json()
        print data
        self.assertEquals([r for r in data['records'] if r['type'] == 'NS'], payload2['records'])
        self.assertEquals(data['comments'], payload['comments'])

    def test_ZoneAutoPtrIPv4(self):
        revzone = '0.2.192.in-addr.arpa'
        self.create_zone(name=revzone)
        payload, zone = self.create_zone()
        name = payload['name']
        # replace with qname mismatch
        payload = {
            'changetype': 'replace',
            'name': name,
            'type': 'A',
            'records': [
                {
                    "name": name,
                    "type": "A",
                    "priority": 0,
                    "ttl": 3600,
                    "content": '192.2.0.2',
                    "disabled": False,
                    "set-ptr": True
                }
            ]
        }
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name + "/rrset"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        r = self.session.get(self.url("/servers/localhost/zones/" + revzone))
        recs = r.json()['records']
        print recs
        revrec = [rec for rec in recs if rec['type'] == 'PTR']
        self.assertEquals(revrec, [{
            u'content': name,
            u'disabled': False,
            u'ttl': 3600,
            u'priority': 0,
            u'type': u'PTR',
            u'name': u'2.0.2.192.in-addr.arpa'
        }])

    def test_ZoneAutoPtrIPv6(self):
        # 2001:DB8::bb:aa
        revzone = '8.b.d.0.1.0.0.2.ip6.arpa'
        self.create_zone(name=revzone)
        payload, zone = self.create_zone()
        name = payload['name']
        # replace with qname mismatch
        payload = {
            'changetype': 'replace',
            'name': name,
            'type': 'AAAA',
            'records': [
                {
                    "name": name,
                    "type": "AAAA",
                    "priority": 0,
                    "ttl": 3600,
                    "content": '2001:DB8::bb:aa',
                    "disabled": False,
                    "set-ptr": True
                }
            ]
        }
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name + "/rrset"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        r = self.session.get(self.url("/servers/localhost/zones/" + revzone))
        recs = r.json()['records']
        print recs
        revrec = [rec for rec in recs if rec['type'] == 'PTR']
        self.assertEquals(revrec, [{
            u'content': name,
            u'disabled': False,
            u'ttl': 3600,
            u'priority': 0,
            u'type': u'PTR',
            u'name': u'a.a.0.0.b.b.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa'
        }])

    def test_SearchRRExactZone(self):
        name = unique_zone_name()
        self.create_zone(name=name)
        r = self.session.get(self.url("/servers/localhost/search-data?q=" + name))
        self.assertSuccessJson(r)
        print r.json()
        self.assertEquals(r.json(), [{u'type': u'zone', u'name': name, u'zone_id': name+'.'}])

    def test_SearchRRSubstring(self):
        name = 'search-rr-zone.name'
        self.create_zone(name=name)
        r = self.session.get(self.url("/servers/localhost/search-data?q=rr-zone"))
        self.assertSuccessJson(r)
        print r.json()
        # should return zone, SOA, ns1, ns2
        self.assertEquals(len(r.json()), 4)

    def test_SearchRRCaseInsensitive(self):
        name = 'search-rr-insenszone.name'
        self.create_zone(name=name)
        r = self.session.get(self.url("/servers/localhost/search-data?q=rr-insensZONE"))
        self.assertSuccessJson(r)
        print r.json()
        # should return zone, SOA, ns1, ns2
        self.assertEquals(len(r.json()), 4)


@unittest.skipIf(not isRecursor(), "Not applicable")
class RecursorZones(ApiTestCase):

    def create_zone(self, name=None, kind=None, rd=False, servers=None):
        if name is None:
            name = unique_zone_name()
        if servers is None:
            servers = []
        payload = {
            'name': name,
            'kind': kind,
            'servers': servers,
            'recursion_desired': rd
        }
        r = self.session.post(
            self.url("/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertSuccessJson(r)
        return (payload, r.json())

    def test_CreateAuthZone(self):
        payload, data = self.create_zone(kind='Native')
        # return values are normalized
        payload['name'] += '.'
        for k in payload.keys():
            self.assertEquals(data[k], payload[k])

    def test_CreateForwardedZone(self):
        payload, data = self.create_zone(kind='Forwarded', rd=False, servers=['8.8.8.8'])
        # return values are normalized
        payload['servers'][0] += ':53'
        payload['name'] += '.'
        for k in payload.keys():
            self.assertEquals(data[k], payload[k])

    def test_CreateForwardedRDZone(self):
        payload, data = self.create_zone(name='google.com', kind='Forwarded', rd=True, servers=['8.8.8.8'])
        # return values are normalized
        payload['servers'][0] += ':53'
        payload['name'] += '.'
        for k in payload.keys():
            self.assertEquals(data[k], payload[k])

    def test_CreateAuthZoneWithSymbols(self):
        payload, data = self.create_zone(name='foo/bar.'+unique_zone_name(), kind='Native')
        # return values are normalized
        payload['name'] += '.'
        expected_id = (payload['name'].replace('/', '=2F'))
        for k in payload.keys():
            self.assertEquals(data[k], payload[k])
        self.assertEquals(data['id'], expected_id)

    def test_RenameAuthZone(self):
        payload, data = self.create_zone(kind='Native')
        name = payload['name'] + '.'
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

    def test_SearchRRExactZone(self):
        name = unique_zone_name() + '.'
        self.create_zone(name=name, kind='Native')
        r = self.session.get(self.url("/servers/localhost/search-data?q=" + name))
        self.assertSuccessJson(r)
        print r.json()
        self.assertEquals(r.json(), [{u'type': u'zone', u'name': name, u'zone_id': name}])

    def test_SearchRRSubstring(self):
        name = 'search-rr-zone.name'
        self.create_zone(name=name, kind='Native')
        r = self.session.get(self.url("/servers/localhost/search-data?q=rr-zone"))
        self.assertSuccessJson(r)
        print r.json()
        # should return zone, SOA
        self.assertEquals(len(r.json()), 2)
