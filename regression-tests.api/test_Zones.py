from __future__ import print_function
import json
import operator
import time
import unittest
import requests.exceptions
from copy import deepcopy
from parameterized import parameterized
from pprint import pprint
from test_helper import ApiTestCase, unique_zone_name, is_auth, is_auth_lmdb, is_recursor, get_db_records, pdnsutil_rectify, sdig


def get_rrset(data, qname, qtype):
    for rrset in data['rrsets']:
        if rrset['name'] == qname and rrset['type'] == qtype:
            return rrset
    return None


def get_first_rec(data, qname, qtype):
    rrset = get_rrset(data, qname, qtype)
    if rrset:
        return rrset['records'][0]
    return None


def eq_zone_rrsets(rrsets, expected):
    data_got = {}
    data_expected = {}
    for type_, expected_records in expected.items():
        type_ = str(type_)
        data_got[type_] = set()
        data_expected[type_] = set()
        uses_name = any(['name' in expected_record for expected_record in expected_records])
        # minify + convert received data
        for rrset in [rrset for rrset in rrsets if rrset['type'] == type_]:
            print(rrset)
            for r in rrset['records']:
                data_got[type_].add((rrset['name'] if uses_name else '@', rrset['type'], r['content']))
        # minify expected data
        for r in expected_records:
            data_expected[type_].add((r['name'] if uses_name else '@', type_, r['content']))

    print("eq_zone_rrsets: got:")
    pprint(data_got)
    print("eq_zone_rrsets: expected:")
    pprint(data_expected)

    assert data_got == data_expected, "%r != %r" % (data_got, data_expected)


class Zones(ApiTestCase):

    def _test_list_zones(self, dnssec=True):
        path = "/api/v1/servers/localhost/zones"
        if not dnssec:
            path = path + "?dnssec=false"
        r = self.session.get(self.url(path))
        self.assert_success_json(r)
        domains = r.json()
        example_com = [domain for domain in domains if domain['name'] in ('example.com', 'example.com.')]
        self.assertEqual(len(example_com), 1)
        example_com = example_com[0]
        print(example_com)
        required_fields = ['id', 'url', 'name', 'kind']
        if is_auth():
            required_fields = required_fields + ['masters', 'last_check', 'notified_serial', 'serial', 'account']
            if dnssec:
                required_fields = required_fields = ['dnssec', 'edited_serial']
            self.assertNotEqual(example_com['serial'], 0)
            if not dnssec:
                self.assertNotIn('dnssec', example_com)
        elif is_recursor():
            required_fields = required_fields + ['recursion_desired', 'servers']
        for field in required_fields:
            self.assertIn(field, example_com)

    def test_list_zones_with_dnssec(self):
        if is_auth():
            self._test_list_zones(True)

    def test_list_zones_without_dnssec(self):
        self._test_list_zones(False)

class AuthZonesHelperMixin(object):
    def create_zone(self, name=None, **kwargs):
        if name is None:
            name = unique_zone_name()
        payload = {
            'name': name,
            'kind': 'Native',
            'nameservers': ['ns1.example.com.', 'ns2.example.com.']
        }
        for k, v in kwargs.items():
            if v is None:
                del payload[k]
            else:
                payload[k] = v
        print("sending", payload)
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        self.assertEqual(r.status_code, 201)
        reply = r.json()
        print("reply", reply)
        return name, payload, reply


@unittest.skipIf(not is_auth(), "Not applicable")
class AuthZones(ApiTestCase, AuthZonesHelperMixin):

    def test_create_zone(self):
        # soa_edit_api has a default, override with empty for this test
        name, payload, data = self.create_zone(serial=22, soa_edit_api='')
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial', 'edited_serial', 'soa_edit_api', 'soa_edit', 'account'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEqual(data[k], payload[k])
        # validate generated SOA
        expected_soa = "a.misconfigured.dns.server.invalid. hostmaster." + name + " " + \
                       str(payload['serial']) + " 10800 3600 604800 3600"
        self.assertEqual(
            get_first_rec(data, name, 'SOA')['content'],
            expected_soa
        )

        if not is_auth_lmdb():
            # Because we had confusion about dots, check that the DB is without dots.
            dbrecs = get_db_records(name, 'SOA')
            self.assertEqual(dbrecs[0]['content'], expected_soa.replace('. ', ' '))
            self.assertNotEqual(data['serial'], data['edited_serial'])

    def test_create_zone_with_soa_edit_api(self):
        # soa_edit_api wins over serial
        name, payload, data = self.create_zone(soa_edit_api='EPOCH', serial=10)
        for k in ('soa_edit_api', ):
            self.assertIn(k, data)
            if k in payload:
                self.assertEqual(data[k], payload[k])
        # generated EPOCH serial surely is > fixed serial we passed in
        print(data)
        self.assertGreater(data['serial'], payload['serial'])
        soa_serial = int(get_first_rec(data, name, 'SOA')['content'].split(' ')[2])
        self.assertGreater(soa_serial, payload['serial'])
        self.assertEqual(soa_serial, data['serial'])

    def test_create_zone_with_catalog(self):
        # soa_edit_api wins over serial
        name, payload, data = self.create_zone(catalog='catalog.invalid.', serial=10)
        print(data)
        for k in ('catalog', ):
            self.assertIn(k, data)
            if k in payload:
                self.assertEqual(data[k], payload[k])

    def test_create_zone_with_account(self):
        # soa_edit_api wins over serial
        name, payload, data = self.create_zone(account='anaccount', serial=10)
        print(data)
        for k in ('account', ):
            self.assertIn(k, data)
            if k in payload:
                self.assertEqual(data[k], payload[k])

    def test_create_zone_default_soa_edit_api(self):
        name, payload, data = self.create_zone()
        print(data)
        self.assertEqual(data['soa_edit_api'], 'DEFAULT')

    def test_create_zone_exists(self):
        name, payload, data = self.create_zone()
        print(data)
        payload = {
            'name': name,
            'kind': 'Native'
        }
        print(payload)
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 409)  # Conflict - already exists

    def test_create_zone_with_soa_edit(self):
        name, payload, data = self.create_zone(soa_edit='INCEPTION-INCREMENT', soa_edit_api='SOA-EDIT-INCREASE')
        print(data)
        self.assertEqual(data['soa_edit'], 'INCEPTION-INCREMENT')
        self.assertEqual(data['soa_edit_api'], 'SOA-EDIT-INCREASE')
        soa_serial = get_first_rec(data, name, 'SOA')['content'].split(' ')[2]
        # These particular settings lead to the first serial set to YYYYMMDD01.
        self.assertEqual(soa_serial[-2:], '01')
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'A',
            'ttl': 3600,
            'records': [
                {
                    "content": "127.0.0.1",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + data['id']),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + data['id']))
        data = r.json()
        soa_serial = get_first_rec(data, name, 'SOA')['content'].split(' ')[2]
        self.assertEqual(soa_serial[-2:], '02')

    def test_create_zone_with_records(self):
        name = unique_zone_name()
        rrset = {
            "name": name,
            "type": "A",
            "ttl": 3600,
            "records": [{
                "content": "4.3.2.1",
                "disabled": False,
            }],
        }
        name, payload, data = self.create_zone(name=name, rrsets=[rrset])
        # check our record has appeared
        self.assertEqual(get_rrset(data, name, 'A')['records'], rrset['records'])

    def test_create_zone_with_wildcard_records(self):
        name = unique_zone_name()
        rrset = {
            "name": "*."+name,
            "type": "A",
            "ttl": 3600,
            "records": [{
                "content": "4.3.2.1",
                "disabled": False,
            }],
        }
        name, payload, data = self.create_zone(name=name, rrsets=[rrset])
        # check our record has appeared
        self.assertEqual(get_rrset(data, rrset['name'], 'A')['records'], rrset['records'])

    def test_create_zone_with_comments(self):
        name = unique_zone_name()
        rrsets = [
              {
                  "name": name,
                  "type": "soa",  # test uppercasing of type, too.
                  "comments": [{
                      "account": "test1",
                      "content": "blah blah",
                      "modified_at": 11112,
                  }],
              },
              {
                  "name": name,
                  "type": "AAAA",
                  "ttl": 3600,
                  "records": [{
                      "content": "2001:DB8::1",
                      "disabled": False,
                  }],
                  "comments": [{
                      "account": "test AAAA",
                      "content": "blah blah AAAA",
                      "modified_at": 11112,
                  }],
              },
              {
                  "name": name,
                  "type": "TXT",
                  "ttl": 3600,
                  "records": [{
                      "content": "\"test TXT\"",
                      "disabled": False,
                  }],
              },
              {
                  "name": name,
                  "type": "A",
                  "ttl": 3600,
                  "records": [{
                      "content": "192.0.2.1",
                      "disabled": False,
                  }],
              },
          ]

        if is_auth_lmdb():
            with self.assertRaises(requests.exceptions.HTTPError):   # No comments in LMDB
                self.create_zone(name=name, rrsets=rrsets)
            return

        name, payload, data = self.create_zone(name=name, rrsets=rrsets)
        # NS records have been created
        self.assertEqual(len(data['rrsets']), len(rrsets) + 1)
        # check our comment has appeared
        self.assertEqual(get_rrset(data, name, 'SOA')['comments'], rrsets[0]['comments'])
        self.assertEqual(get_rrset(data, name, 'A')['comments'], [])
        self.assertEqual(get_rrset(data, name, 'TXT')['comments'], [])
        self.assertEqual(get_rrset(data, name, 'AAAA')['comments'], rrsets[1]['comments'])

    def test_create_zone_uncanonical_nameservers(self):
        name = unique_zone_name()
        payload = {
            'name': name,
            'kind': 'Native',
            'nameservers': ['uncanon.example.com']
        }
        print(payload)
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('Nameserver is not canonical', r.json()['error'])

    def test_create_auth_zone_no_name(self):
        name = unique_zone_name()
        payload = {
            'name': '',
            'kind': 'Native',
        }
        print(payload)
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('is not canonical', r.json()['error'])

    def test_create_zone_with_custom_soa(self):
        name = unique_zone_name()
        content = u"ns1.example.net. testmaster@example.net. 10 10800 3600 604800 3600"
        rrset = {
            "name": name,
            "type": "soa",  # test uppercasing of type, too.
            "ttl": 3600,
            "records": [{
                "content": content,
                "disabled": False,
            }],
        }
        name, payload, data = self.create_zone(name=name, rrsets=[rrset], soa_edit_api='')
        self.assertEqual(get_rrset(data, name, 'SOA')['records'], rrset['records'])
        if not is_auth_lmdb():
            dbrecs = get_db_records(name, 'SOA')
            self.assertEqual(dbrecs[0]['content'], content.replace('. ', ' '))

    def test_create_zone_double_dot(self):
        name = 'test..' + unique_zone_name()
        payload = {
            'name': name,
            'kind': 'Native',
            'nameservers': ['ns1.example.com.']
        }
        print(payload)
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('Unable to parse DNS Name', r.json()['error'])

    def test_create_zone_restricted_chars(self):
        name = 'test:' + unique_zone_name()  # : isn't good as a name.
        payload = {
            'name': name,
            'kind': 'Native',
            'nameservers': ['ns1.example.com']
        }
        print(payload)
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('contains unsupported characters', r.json()['error'])

    def test_create_zone_mixed_nameservers_ns_rrset_zonelevel(self):
        name = unique_zone_name()
        rrset = {
            "name": name,
            "type": "NS",
            "ttl": 3600,
            "records": [{
                "content": "ns2.example.com.",
                "disabled": False,
            }],
        }
        payload = {
            'name': name,
            'kind': 'Native',
            'nameservers': ['ns1.example.com.'],
            'rrsets': [rrset],
        }
        print(payload)
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('Nameservers list MUST NOT be mixed with zone-level NS in rrsets', r.json()['error'])

    def test_create_zone_mixed_nameservers_ns_rrset_below_zonelevel(self):
        name = unique_zone_name()
        rrset = {
            "name": 'subzone.'+name,
            "type": "NS",
            "ttl": 3600,
            "records": [{
                "content": "ns2.example.com.",
                "disabled": False,
            }],
        }
        payload = {
            'name': name,
            'kind': 'Native',
            'nameservers': ['ns1.example.com.'],
            'rrsets': [rrset],
        }
        print(payload)
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)

    def test_create_zone_with_symbols(self):
        name, payload, data = self.create_zone(name='foo/bar.'+unique_zone_name())
        name = payload['name']
        expected_id = name.replace('/', '=2F')
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEqual(data[k], payload[k])
        self.assertEqual(data['id'], expected_id)
        if not is_auth_lmdb():
            dbrecs = get_db_records(name, 'SOA')
            self.assertEqual(dbrecs[0]['name'], name.rstrip('.'))

    def test_create_zone_with_nameservers_non_string(self):
        # ensure we don't crash
        name = unique_zone_name()
        payload = {
            'name': name,
            'kind': 'Native',
            'nameservers': [{'a': 'ns1.example.com'}]  # invalid
        }
        print(payload)
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)

    def test_create_zone_with_dnssec(self):
        """
        Create a zone with "dnssec" set and see if a key was made.
        """
        name = unique_zone_name()
        name, payload, data = self.create_zone(dnssec=True)

        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name))

        for k in ('dnssec', ):
            self.assertIn(k, data)
            if k in payload:
                self.assertEqual(data[k], payload[k])

        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name + '/cryptokeys'))

        keys = r.json()

        print(keys)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]['type'], 'Cryptokey')
        self.assertEqual(keys[0]['active'], True)
        self.assertEqual(keys[0]['keytype'], 'csk')

    def test_create_zone_with_dnssec_disable_dnssec(self):
        """
        Create a zone with "dnssec", then set "dnssec" to false and see if the
        keys are gone
        """
        name = unique_zone_name()
        name, payload, data = self.create_zone(dnssec=True)

        self.session.put(self.url("/api/v1/servers/localhost/zones/" + name),
                         data=json.dumps({'dnssec': False}))
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name))

        zoneinfo = r.json()

        self.assertEqual(r.status_code, 200)
        self.assertEqual(zoneinfo['dnssec'], False)

        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name + '/cryptokeys'))

        keys = r.json()

        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(keys), 0)

    def test_create_zone_with_nsec3param(self):
        """
        Create a zone with "nsec3param" set and see if the metadata was added.
        """
        name = unique_zone_name()
        nsec3param = '1 0 100 aabbccddeeff'
        name, payload, data = self.create_zone(dnssec=True, nsec3param=nsec3param)

        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name))

        for k in ('dnssec', 'nsec3param'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEqual(data[k], payload[k])

        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name + '/metadata/NSEC3PARAM'))

        data = r.json()

        print(data)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(data['metadata']), 1)
        self.assertEqual(data['kind'], 'NSEC3PARAM')
        self.assertEqual(data['metadata'][0], nsec3param)

    def test_create_zone_with_nsec3narrow(self):
        """
        Create a zone with "nsec3narrow" set and see if the metadata was added.
        """
        name = unique_zone_name()
        nsec3param = '1 0 100 aabbccddeeff'
        name, payload, data = self.create_zone(dnssec=True, nsec3param=nsec3param,
                                               nsec3narrow=True)

        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name))

        for k in ('dnssec', 'nsec3param', 'nsec3narrow'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEqual(data[k], payload[k])

        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name + '/metadata/NSEC3NARROW'))

        data = r.json()

        print(data)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(data['metadata']), 1)
        self.assertEqual(data['kind'], 'NSEC3NARROW')
        self.assertEqual(data['metadata'][0], '1')

    def test_create_zone_with_nsec3param_switch_to_nsec(self):
        """
        Create a zone with "nsec3param", then remove the params
        """
        name, payload, data = self.create_zone(dnssec=True,
                                               nsec3param='1 0 1 ab')
        self.session.put(self.url("/api/v1/servers/localhost/zones/" + name),
                         data=json.dumps({'nsec3param': ''}))
        r = self.session.get(
            self.url("/api/v1/servers/localhost/zones/" + name))
        data = r.json()

        self.assertEqual(r.status_code, 200)
        self.assertEqual(data['nsec3param'], '')

    def test_create_zone_without_dnssec_unset_nsec3parm(self):
        """
        Create a non dnssec zone and set an empty "nsec3param"
        """
        name, payload, data = self.create_zone(dnssec=False)
        r = self.session.put(self.url("/api/v1/servers/localhost/zones/" + name),
                             data=json.dumps({'nsec3param': ''}))

        self.assertEqual(r.status_code, 204)

    def test_create_zone_without_dnssec_set_nsec3parm(self):
        """
        Create a non dnssec zone and set "nsec3param"
        """
        name, payload, data = self.create_zone(dnssec=False)
        r = self.session.put(self.url("/api/v1/servers/localhost/zones/" + name),
                             data=json.dumps({'nsec3param': '1 0 1 ab'}))

        self.assertEqual(r.status_code, 422)

    def test_create_zone_dnssec_serial(self):
        """
        Create a zone, then set and unset "dnssec", then check if the serial was increased
        after every step
        """
        name, payload, data = self.create_zone()

        soa_serial = get_first_rec(data, name, 'SOA')['content'].split(' ')[2]
        self.assertEqual(soa_serial[-2:], '01')

        self.session.put(self.url("/api/v1/servers/localhost/zones/" + name),
                         data=json.dumps({'dnssec': True}))
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name))

        data = r.json()
        soa_serial = get_first_rec(data, name, 'SOA')['content'].split(' ')[2]

        self.assertEqual(r.status_code, 200)
        self.assertEqual(soa_serial[-2:], '02')

        self.session.put(self.url("/api/v1/servers/localhost/zones/" + name),
                         data=json.dumps({'dnssec': False}))
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name))

        data = r.json()
        soa_serial = get_first_rec(data, name, 'SOA')['content'].split(' ')[2]

        self.assertEqual(r.status_code, 200)
        self.assertEqual(soa_serial[-2:], '03')

    def test_zone_absolute_url(self):
        name, payload, data = self.create_zone()
        r = self.session.get(self.url("/api/v1/servers/localhost/zones"))
        rdata = r.json()
        print(rdata[0])
        self.assertTrue(rdata[0]['url'].startswith('/api/v'))

    def test_create_zone_metadata(self):
        payload_metadata = {"type": "Metadata", "kind": "AXFR-SOURCE", "metadata": ["127.0.0.2"]}
        r = self.session.post(self.url("/api/v1/servers/localhost/zones/example.com/metadata"),
                              data=json.dumps(payload_metadata))
        rdata = r.json()
        self.assertEqual(r.status_code, 201)
        self.assertEqual(rdata["metadata"], payload_metadata["metadata"])

    def test_create_zone_metadata_kind(self):
        payload_metadata = {"metadata": ["127.0.0.2"]}
        r = self.session.put(self.url("/api/v1/servers/localhost/zones/example.com/metadata/AXFR-SOURCE"),
                             data=json.dumps(payload_metadata))
        rdata = r.json()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(rdata["metadata"], payload_metadata["metadata"])

    def test_create_protected_zone_metadata(self):
        # test whether it prevents modification of certain kinds
        for k in ("NSEC3NARROW", "NSEC3PARAM", "PRESIGNED", "LUA-AXFR-SCRIPT"):
            payload = {"metadata": ["FOO", "BAR"]}
            r = self.session.put(self.url("/api/v1/servers/localhost/zones/example.com/metadata/%s" % k),
                                 data=json.dumps(payload))
            self.assertEqual(r.status_code, 422)

    def test_retrieve_zone_metadata(self):
        payload_metadata = {"type": "Metadata", "kind": "AXFR-SOURCE", "metadata": ["127.0.0.2"]}
        self.session.post(self.url("/api/v1/servers/localhost/zones/example.com/metadata"),
                          data=json.dumps(payload_metadata))
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/example.com/metadata"))
        rdata = r.json()
        self.assertEqual(r.status_code, 200)
        self.assertIn(payload_metadata, rdata)

    def test_delete_zone_metadata(self):
        r = self.session.delete(self.url("/api/v1/servers/localhost/zones/example.com/metadata/AXFR-SOURCE"))
        self.assertEqual(r.status_code, 200)
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/example.com/metadata/AXFR-SOURCE"))
        rdata = r.json()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(rdata["metadata"], [])

    def test_create_external_zone_metadata(self):
        payload_metadata = {"metadata": ["My very important message"]}
        r = self.session.put(self.url("/api/v1/servers/localhost/zones/example.com/metadata/X-MYMETA"),
                             data=json.dumps(payload_metadata))
        self.assertEqual(r.status_code, 200)
        rdata = r.json()
        self.assertEqual(rdata["metadata"], payload_metadata["metadata"])

    def test_create_metadata_in_non_existent_zone(self):
        payload_metadata = {"type": "Metadata", "kind": "AXFR-SOURCE", "metadata": ["127.0.0.2"]}
        r = self.session.post(self.url("/api/v1/servers/localhost/zones/idonotexist.123.456.example./metadata"),
                              data=json.dumps(payload_metadata))
        self.assertEqual(r.status_code, 404)
        # Note: errors should probably contain json (see #5988)
        # self.assertIn('Could not find domain ', r.json()['error'])

    def test_create_slave_zone(self):
        # Test that nameservers can be absent for slave zones.
        name, payload, data = self.create_zone(kind='Slave', nameservers=None, masters=['127.0.0.2'])
        for k in ('name', 'masters', 'kind'):
            self.assertIn(k, data)
            self.assertEqual(data[k], payload[k])
        print("payload:", payload)
        print("data:", data)
        # Because slave zones don't get a SOA, we need to test that they'll show up in the zone list.
        r = self.session.get(self.url("/api/v1/servers/localhost/zones"))
        zonelist = r.json()
        print("zonelist:", zonelist)
        self.assertIn(payload['name'], [zone['name'] for zone in zonelist])
        # Also test that fetching the zone works.
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + data['id']))
        data = r.json()
        print("zone (fetched):", data)
        for k in ('name', 'masters', 'kind'):
            self.assertIn(k, data)
            self.assertEqual(data[k], payload[k])
        self.assertEqual(data['serial'], 0)
        self.assertEqual(data['rrsets'], [])

    def test_create_consumer_zone(self):
        # Test that nameservers can be absent for consumer zones.
        name, payload, data = self.create_zone(kind='Consumer', nameservers=None, masters=['127.0.0.2'])
        for k in ('name', 'masters', 'kind'):
            self.assertIn(k, data)
            self.assertEqual(data[k], payload[k])
        print("payload:", payload)
        print("data:", data)
        # Because consumer zones don't get a SOA, we need to test that they'll show up in the zone list.
        r = self.session.get(self.url("/api/v1/servers/localhost/zones"))
        zonelist = r.json()
        print("zonelist:", zonelist)
        self.assertIn(payload['name'], [zone['name'] for zone in zonelist])
        # Also test that fetching the zone works.
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + data['id']))
        data = r.json()
        print("zone (fetched):", data)
        for k in ('name', 'masters', 'kind'):
            self.assertIn(k, data)
            self.assertEqual(data[k], payload[k])
        self.assertEqual(data['serial'], 0)
        self.assertEqual(data['rrsets'], [])

    def test_find_zone_by_name(self):
        name = 'foo/' + unique_zone_name()
        name, payload, data = self.create_zone(name=name)
        r = self.session.get(self.url("/api/v1/servers/localhost/zones?zone=" + name))
        data = r.json()
        print(data)
        self.assertEqual(data[0]['name'], name)

    def test_delete_slave_zone(self):
        name, payload, data = self.create_zone(kind='Slave', nameservers=None, masters=['127.0.0.2'])
        r = self.session.delete(self.url("/api/v1/servers/localhost/zones/" + data['id']))
        r.raise_for_status()

    def test_delete_consumer_zone(self):
        name, payload, data = self.create_zone(kind='Consumer', nameservers=None, masters=['127.0.0.2'])
        r = self.session.delete(self.url("/api/v1/servers/localhost/zones/" + data['id']))
        r.raise_for_status()

    def test_retrieve_slave_zone(self):
        name, payload, data = self.create_zone(kind='Slave', nameservers=None, masters=['127.0.0.2'])
        print("payload:", payload)
        print("data:", data)
        r = self.session.put(self.url("/api/v1/servers/localhost/zones/" + data['id'] + "/axfr-retrieve"))
        data = r.json()
        print("status for axfr-retrieve:", data)
        self.assertEqual(data['result'], u'Added retrieval request for \'' + payload['name'] +
                         '\' from master 127.0.0.2')

    def test_notify_master_zone(self):
        name, payload, data = self.create_zone(kind='Master')
        print("payload:", payload)
        print("data:", data)
        r = self.session.put(self.url("/api/v1/servers/localhost/zones/" + data['id'] + "/notify"))
        data = r.json()
        print("status for notify:", data)
        self.assertEqual(data['result'], 'Notification queued')

    def test_get_zone_with_symbols(self):
        name, payload, data = self.create_zone(name='foo/bar.'+unique_zone_name())
        name = payload['name']
        zone_id = (name.replace('/', '=2F'))
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + zone_id))
        data = r.json()
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial', 'dnssec'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEqual(data[k], payload[k])

    def test_get_zone(self):
        r = self.session.get(self.url("/api/v1/servers/localhost/zones"))
        domains = r.json()
        example_com = [domain for domain in domains if domain['name'] == u'example.com.'][0]
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + example_com['id']))
        self.assert_success_json(r)
        data = r.json()
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial'):
            self.assertIn(k, data)
        self.assertEqual(data['name'], 'example.com.')

    def test_get_zone_rrset(self):
        rz = self.session.get(self.url("/api/v1/servers/localhost/zones"))
        domains = rz.json()
        example_com = [domain for domain in domains if domain['name'] == u'example.com.'][0]

        # verify single record from name that has a single record
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + example_com['id'] + "?rrset_name=host-18000.example.com."))
        self.assert_success_json(r)
        data = r.json()
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial', 'rrsets'):
            self.assertIn(k, data)
        self.assertEqual(data['rrsets'],
            [
                {
                    'comments': [],
                    'name': 'host-18000.example.com.',
                    'records':
                    [
                        {
                            'content': '192.168.1.80',
                            'disabled': False
                        }
                    ],
                    'ttl': 120,
                    'type': 'A'
                }
            ]
        )

        # verify two RRsets from a name that has two types with one record each
        powerdnssec_org = [domain for domain in domains if domain['name'] == u'powerdnssec.org.'][0]
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + powerdnssec_org['id'] + "?rrset_name=localhost.powerdnssec.org."))
        self.assert_success_json(r)
        data = r.json()
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial', 'rrsets'):
            self.assertIn(k, data)
        self.assertEqual(sorted(data['rrsets'], key=operator.itemgetter('type')),
            [
                {
                    'comments': [],
                    'name': 'localhost.powerdnssec.org.',
                    'records':
                    [
                        {
                            'content': '127.0.0.1',
                            'disabled': False
                        }
                    ],
                    'ttl': 3600,
                    'type': 'A'
                },
                {
                    'comments': [],
                    'name': 'localhost.powerdnssec.org.',
                    'records':
                    [
                        {
                            'content': '::1',
                            'disabled': False
                        }
                    ],
                    'ttl': 3600,
                    'type': 'AAAA'
                },
            ]
        )

        # verify one RRset with one record from a name that has two, then filtered by type
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/" + powerdnssec_org['id'] + "?rrset_name=localhost.powerdnssec.org.&rrset_type=AAAA"))
        self.assert_success_json(r)
        data = r.json()
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial', 'rrsets'):
            self.assertIn(k, data)
        self.assertEqual(data['rrsets'],
            [
                {
                    'comments': [],
                    'name': 'localhost.powerdnssec.org.',
                    'records':
                    [
                        {
                            'content': '::1',
                            'disabled': False
                        }
                    ],
                    'ttl': 3600,
                    'type': 'AAAA'
                }
            ]
        )

    def test_import_zone_broken(self):
        payload = {
            'name': 'powerdns-broken.com',
            'kind': 'Master',
            'nameservers': [],
        }
        payload['zone'] = """
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 58571
flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1680
;; QUESTION SECTION:
;powerdns.com.                  IN      SOA

;; ANSWER SECTION:
powerdns-broken.com.           86400   IN      SOA     powerdnssec1.ds9a.nl. ahu.ds9a.nl. 1343746984 10800 3600 604800 10800
powerdns-broken.com.           3600    IN      NS      powerdnssec2.ds9a.nl.
powerdns-broken.com.           3600    IN      AAAA    2001:888:2000:1d::2
powerdns-broken.com.           86400   IN      A       82.94.213.34
powerdns-broken.com.           3600    IN      MX      0 xs.powerdns.com.
powerdns-broken.com.           3600    IN      NS      powerdnssec1.ds9a.nl.
powerdns-broken.com.           86400   IN      SOA     powerdnssec1.ds9a.nl. ahu.ds9a.nl. 1343746984 10800 3600 604800 10800
"""
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)

    def test_import_zone_axfr_outofzone(self):
        # Ensure we don't create out-of-zone records
        payload = {
            'name': unique_zone_name(),
            'kind': 'Master',
            'nameservers': [],
        }
        payload['zone'] = """
%NAME%           86400   IN      SOA     powerdnssec1.ds9a.nl. ahu.ds9a.nl. 1343746984 10800 3600 604800 10800
%NAME%           3600    IN      NS      powerdnssec2.ds9a.nl.
example.org.   3600    IN      AAAA    2001:888:2000:1d::2
%NAME%           86400   IN      SOA     powerdnssec1.ds9a.nl. ahu.ds9a.nl. 1343746984 10800 3600 604800 10800
""".replace('%NAME%', payload['name'])
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertEqual(r.json()['error'], 'RRset example.org. IN AAAA: Name is out of zone')

    def test_import_zone_axfr(self):
        payload = {
            'name': 'powerdns.com.',
            'kind': 'Master',
            'nameservers': [],
            'soa_edit_api': '',  # turn off so exact SOA comparison works.
        }
        payload['zone'] = """
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 58571
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1680
;; QUESTION SECTION:
;powerdns.com.                  IN      SOA

;; ANSWER SECTION:
powerdns.com.           86400   IN      SOA     powerdnssec1.ds9a.nl. ahu.ds9a.nl. 1343746984 10800 3600 604800 10800
powerdns.com.           3600    IN      NS      powerdnssec2.ds9a.nl.
powerdns.com.           3600    IN      AAAA    2001:888:2000:1d::2
powerdns.com.           86400   IN      A       82.94.213.34
powerdns.com.           3600    IN      MX      0 xs.powerdns.com.
powerdns.com.           3600    IN      NS      powerdnssec1.ds9a.nl.
powerdns.com.           86400   IN      SOA     powerdnssec1.ds9a.nl. ahu.ds9a.nl. 1343746984 10800 3600 604800 10800
"""
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        data = r.json()
        self.assertIn('name', data)

        expected = {
            'NS': [
                {'content': 'powerdnssec1.ds9a.nl.'},
                {'content': 'powerdnssec2.ds9a.nl.'},
            ],
            'SOA': [
                {'content': 'powerdnssec1.ds9a.nl. ahu.ds9a.nl. 1343746984 10800 3600 604800 10800'},
            ],
            'MX': [
                {'content': '0 xs.powerdns.com.'},
            ],
            'A': [
                {'content': '82.94.213.34', 'name': 'powerdns.com.'},
            ],
            'AAAA': [
                {'content': '2001:888:2000:1d::2', 'name': 'powerdns.com.'},
            ],
        }

        eq_zone_rrsets(data['rrsets'], expected)

        if not is_auth_lmdb():
            # check content in DB is stored WITHOUT trailing dot.
            dbrecs = get_db_records(payload['name'], 'NS')
            dbrec = next((dbrec for dbrec in dbrecs if dbrec['content'].startswith('powerdnssec1')))
            self.assertEqual(dbrec['content'], 'powerdnssec1.ds9a.nl')

    def test_import_zone_bind(self):
        payload = {
            'name': 'example.org.',
            'kind': 'Master',
            'nameservers': [],
            'soa_edit_api': '',  # turn off so exact SOA comparison works.
        }
        payload['zone'] = """
$TTL    86400 ; 24 hours could have been written as 24h or 1d
; $TTL used for all RRs without explicit TTL value
$ORIGIN example.org.
@  1D  IN  SOA ns1.example.org. hostmaster.example.org. (
                  2002022401 ; serial
                  3H ; refresh
                  15 ; retry
                  1w ; expire
                  3h ; minimum
                 )
       IN  NS     ns1.example.org. ; in the domain
       IN  NS     ns2.smokeyjoe.com. ; external to domain
       IN MX  10 mail.another.com. ; external mail provider
; server host definitions
ns1    IN A      192.168.0.1  ;name server definition
www    IN  A      192.168.0.2  ;web server definition
ftp    IN CNAME  www.example.org.  ;ftp server definition
; non server domain hosts
bill   IN  A      192.168.0.3
fred   IN  A      192.168.0.4
"""
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        data = r.json()
        self.assertIn('name', data)

        expected = {
            'NS': [
                {'content': 'ns1.example.org.'},
                {'content': 'ns2.smokeyjoe.com.'},
            ],
            'SOA': [
                {'content': 'ns1.example.org. hostmaster.example.org. 2002022401 10800 15 604800 10800'},
            ],
            'MX': [
                {'content': '10 mail.another.com.'},
            ],
            'A': [
                {'content': '192.168.0.1', 'name': 'ns1.example.org.'},
                {'content': '192.168.0.2', 'name': 'www.example.org.'},
                {'content': '192.168.0.3', 'name': 'bill.example.org.'},
                {'content': '192.168.0.4', 'name': 'fred.example.org.'},
            ],
            'CNAME': [
                {'content': 'www.example.org.', 'name': 'ftp.example.org.'},
            ],
        }

        eq_zone_rrsets(data['rrsets'], expected)

    def test_import_zone_bind_cname_apex(self):
        payload = {
            'name': unique_zone_name(),
            'kind': 'Master',
            'nameservers': [],
        }
        payload['zone'] = """
$ORIGIN %NAME%
@ IN SOA   ns1.example.org. hostmaster.example.org. (2002022401 3H 15 1W 3H)
@ IN NS    ns1.example.org.
@ IN NS    ns2.smokeyjoe.com.
@ IN CNAME www.example.org.
""".replace('%NAME%', payload['name'])
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('Conflicts with another RRset', r.json()['error'])

    def test_export_zone_json(self):
        name, payload, zone = self.create_zone(nameservers=['ns1.foo.com.', 'ns2.foo.com.'], soa_edit_api='')
        # export it
        r = self.session.get(
            self.url("/api/v1/servers/localhost/zones/" + name + "/export"),
            headers={'accept': 'application/json;q=0.9,*/*;q=0.8'}
        )
        self.assert_success_json(r)
        data = r.json()
        self.assertIn('zone', data)
        expected_data = [name + '\t3600\tIN\tNS\tns1.foo.com.',
                         name + '\t3600\tIN\tNS\tns2.foo.com.',
                         name + '\t3600\tIN\tSOA\ta.misconfigured.dns.server.invalid. hostmaster.' + name +
                         ' 0 10800 3600 604800 3600']
        self.assertCountEqual(data['zone'].strip().split('\n'), expected_data)

    def test_export_zone_text(self):
        name, payload, zone = self.create_zone(nameservers=['ns1.foo.com.', 'ns2.foo.com.'], soa_edit_api='')
        # export it
        r = self.session.get(
            self.url("/api/v1/servers/localhost/zones/" + name + "/export"),
            headers={'accept': '*/*'}
        )
        data = r.text.strip().split("\n")
        expected_data = [name + '\t3600\tIN\tNS\tns1.foo.com.',
                         name + '\t3600\tIN\tNS\tns2.foo.com.',
                         name + '\t3600\tIN\tSOA\ta.misconfigured.dns.server.invalid. hostmaster.' + name +
                         ' 0 10800 3600 604800 3600']
        self.assertCountEqual(data, expected_data)

    def test_update_zone(self):
        name, payload, zone = self.create_zone()
        name = payload['name']
        # update, set as Master and enable SOA-EDIT-API
        payload = {
            'kind': 'Master',
            'masters': ['192.0.2.1', '192.0.2.2'],
            'catalog': 'catalog.invalid.',
            'soa_edit_api': 'EPOCH',
            'soa_edit': 'EPOCH'
        }
        r = self.session.put(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        for k in payload.keys():
            self.assertIn(k, data)
            self.assertEqual(data[k], payload[k])
        # update, back to Native and empty(off)
        payload = {
            'kind': 'Native',
            'catalog': '',
            'soa_edit_api': '',
            'soa_edit': ''
        }
        r = self.session.put(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        for k in payload.keys():
            self.assertIn(k, data)
            self.assertEqual(data[k], payload[k])

    def test_zone_rr_update(self):
        name, payload, zone = self.create_zone()
        # do a replace (= update)
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'ns',
            'ttl': 3600,
            'records': [
                {
                    "content": "ns1.bar.com.",
                    "disabled": False
                },
                {
                    "content": "ns2-disabled.bar.com.",
                    "disabled": True
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        # verify that (only) the new record is there
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        self.assertCountEqual(get_rrset(data, name, 'NS')['records'], rrset['records'])

    def test_zone_rr_update_mx(self):
        # Important to test with MX records, as they have a priority field, which must end up in the content field.
        name, payload, zone = self.create_zone()
        # do a replace (= update)
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'MX',
            'ttl': 3600,
            'records': [
                {
                    "content": "10 mail.example.org.",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        # verify that (only) the new record is there
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        self.assertEqual(get_rrset(data, name, 'MX')['records'], rrset['records'])

    def test_zone_rr_update_invalid_mx(self):
        name, payload, zone = self.create_zone()
        # do a replace (= update)
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'MX',
            'ttl': 3600,
            'records': [
                {
                    "content": "10 mail@mx.example.org.",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('non-hostname content', r.json()['error'])
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        self.assertIsNone(get_rrset(data, name, 'MX'))

    def test_zone_rr_update_opt(self):
        name, payload, zone = self.create_zone()
        # do a replace (= update)
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'OPT',
            'ttl': 3600,
            'records': [
                {
                    "content": "9",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('OPT: invalid type given', r.json()['error'])

    def test_zone_rr_update_multiple_rrsets(self):
        name, payload, zone = self.create_zone()
        rrset1 = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'ttl': 3600,
            'records': [
                {

                    "content": "ns9999.example.com.",
                    "disabled": False
                }
            ]
        }
        rrset2 = {
            'changetype': 'replace',
            'name': name,
            'type': 'MX',
            'ttl': 3600,
            'records': [
                {
                    "content": "10 mx444.example.com.",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset1, rrset2]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        # verify that all rrsets have been updated
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        self.assertEqual(get_rrset(data, name, 'NS')['records'], rrset1['records'])
        self.assertEqual(get_rrset(data, name, 'MX')['records'], rrset2['records'])

    def test_zone_rr_update_duplicate_record(self):
        name, payload, zone = self.create_zone()
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'ttl': 3600,
            'records': [
                {"content": "ns9999.example.com.", "disabled": False},
                {"content": "ns9996.example.com.", "disabled": False},
                {"content": "ns9987.example.com.", "disabled": False},
                {"content": "ns9988.example.com.", "disabled": False},
                {"content": "ns9999.example.com.", "disabled": False},
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('Duplicate record in RRset', r.json()['error'])

    def test_zone_rr_update_duplicate_rrset(self):
        name, payload, zone = self.create_zone()
        rrset1 = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'ttl': 3600,
            'records': [
                {
                    "content": "ns9999.example.com.",
                    "disabled": False
                }
            ]
        }
        rrset2 = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'ttl': 3600,
            'records': [
                {
                    "content": "ns9998.example.com.",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset1, rrset2]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('Duplicate RRset', r.json()['error'])

    def test_zone_rr_delete(self):
        name, payload, zone = self.create_zone()
        # do a delete of all NS records (these are created with the zone)
        rrset = {
            'changetype': 'delete',
            'name': name,
            'type': 'NS'
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        # verify that the records are gone
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        self.assertIsNone(get_rrset(data, name, 'NS'))

    def test_zone_rr_update_rrset_combine_replace_and_delete(self):
        name, payload, zone = self.create_zone()
        rrset1 = {
            'changetype': 'delete',
            'name': 'sub.' + name,
            'type': 'CNAME',
        }
        rrset2 = {
            'changetype': 'replace',
            'name': 'sub.' + name,
            'type': 'CNAME',
            'ttl': 500,
            'records': [
                {
                    "content": "www.example.org.",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset1, rrset2]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        # verify that (only) the new record is there
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        self.assertEqual(get_rrset(data, 'sub.' + name, 'CNAME')['records'], rrset2['records'])

    def test_zone_disable_reenable(self):
        # This also tests that SOA-EDIT-API works.
        name, payload, zone = self.create_zone(soa_edit_api='EPOCH')
        # disable zone by disabling SOA
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'SOA',
            'ttl': 3600,
            'records': [
                {
                    "content": "ns1.bar.com. hostmaster.foo.org. 1 1 1 1 1",
                    "disabled": True
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        # check SOA serial has been edited
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        soa_serial1 = get_first_rec(data, name, 'SOA')['content'].split()[2]
        self.assertNotEqual(soa_serial1, '1')
        # make sure domain is still in zone list (disabled SOA!)
        r = self.session.get(self.url("/api/v1/servers/localhost/zones"))
        domains = r.json()
        self.assertEqual(len([domain for domain in domains if domain['name'] == name]), 1)
        # sleep 1sec to ensure the EPOCH value changes for the next request
        time.sleep(1)
        # verify that modifying it still works
        rrset['records'][0]['disabled'] = False
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        # check SOA serial has been edited again
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        soa_serial2 = get_first_rec(data, name, 'SOA')['content'].split()[2]
        self.assertNotEqual(soa_serial2, '1')
        self.assertNotEqual(soa_serial2, soa_serial1)

    def test_zone_rr_update_out_of_zone(self):
        name, payload, zone = self.create_zone()
        # replace with qname mismatch
        rrset = {
            'changetype': 'replace',
            'name': 'not-in-zone.',
            'type': 'NS',
            'ttl': 3600,
            'records': [
                {
                    "content": "ns1.bar.com.",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('out of zone', r.json()['error'])

    def test_zone_rr_update_restricted_chars(self):
        name, payload, zone = self.create_zone()
        # replace with qname mismatch
        rrset = {
            'changetype': 'replace',
            'name': 'test:' + name,
            'type': 'NS',
            'ttl': 3600,
            'records': [
                {
                    "content": "ns1.bar.com.",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('contains unsupported characters', r.json()['error'])

    def test_rrset_unknown_type(self):
        name, payload, zone = self.create_zone()
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'FAFAFA',
            'ttl': 3600,
            'records': [
                {
                    "content": "4.3.2.1",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(self.url("/api/v1/servers/localhost/zones/" + name), data=json.dumps(payload),
                               headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('unknown type', r.json()['error'])

    @parameterized.expand([
        ('CNAME', ),
    ])
    def test_rrset_exclusive_and_other(self, qtype):
        name, payload, zone = self.create_zone()
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': qtype,
            'ttl': 3600,
            'records': [
                {
                    "content": "example.org.",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(self.url("/api/v1/servers/localhost/zones/" + name), data=json.dumps(payload),
                               headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('Conflicts with pre-existing RRset', r.json()['error'])

    @parameterized.expand([
        ('CNAME', ),
    ])
    def test_rrset_other_and_exclusive(self, qtype):
        name, payload, zone = self.create_zone()
        rrset = {
            'changetype': 'replace',
            'name': 'sub.'+name,
            'type': qtype,
            'ttl': 3600,
            'records': [
                {
                    "content": "example.org.",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(self.url("/api/v1/servers/localhost/zones/" + name), data=json.dumps(payload),
                               headers={'content-type': 'application/json'})
        self.assert_success(r)
        rrset = {
            'changetype': 'replace',
            'name': 'sub.'+name,
            'type': 'A',
            'ttl': 3600,
            'records': [
                {
                    "content": "1.2.3.4",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(self.url("/api/v1/servers/localhost/zones/" + name), data=json.dumps(payload),
                               headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('Conflicts with pre-existing RRset', r.json()['error'])

    @parameterized.expand([
        ('', 'SOA', ['ns1.example.org. test@example.org. 10 10800 3600 604800 3600', 'ns2.example.org. test@example.org. 10 10800 3600 604800 3600']),
        ('sub.', 'CNAME', ['01.example.org.', '02.example.org.']),
    ])
    def test_rrset_single_qtypes(self, label, qtype, contents):
        name, payload, zone = self.create_zone()
        rrset = {
            'changetype': 'replace',
            'name': label + name,
            'type': qtype,
            'ttl': 3600,
            'records': [
                {
                    "content": contents[0],
                    "disabled": False
                },
                {
                    "content": contents[1],
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(self.url("/api/v1/servers/localhost/zones/" + name), data=json.dumps(payload),
                               headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('IN ' + qtype + ' has more than one record', r.json()['error'])

    def test_rrset_zone_apex(self):
        name, payload, zone = self.create_zone()
        rrset1 = {
            'changetype': 'replace',
            'name': name,
            'type': 'SOA',
            'ttl': 3600,
            'records': [
                {
                    "content": 'ns1.example.org. test@example.org. 10 10800 3600 604800 3600',
                    "disabled": False
                },
            ]
        }
        rrset2 = {
            'changetype': 'replace',
            'name': name,
            'type': 'DNAME',
            'ttl': 3600,
            'records': [
                {
                    "content": 'example.com.',
                    "disabled": False
                },
            ]
        }

        payload = {'rrsets': [rrset1, rrset2]}
        r = self.session.patch(self.url("/api/v1/servers/localhost/zones/" + name), data=json.dumps(payload),
                               headers={'content-type': 'application/json'})
        self.assert_success(r)  # user should be able to create DNAME at APEX as per RFC 6672 section 2.3

    @parameterized.expand([
        ('SOA', 'ns1.example.org. test@example.org. 10 10800 3600 604800 1800'),
        ('DNSKEY', '257 3 8 AwEAAb/+pXOZWYQ8mv9WM5dFva8WU9jcIUdDuEjldbyfnkQ/xlrJC5zAEfhYhrea3SmIPmMTDimLqbh3/4SMTNPTUF+9+U1vpNfIRTFadqsmuU9Fddz3JqCcYwEpWbReg6DJOeyu+9oBoIQkPxFyLtIXEPGlQzrynKubn04Cx83I6NfzDTraJT3jLHKeW5PVc1ifqKzHz5TXdHHTA7NkJAa0sPcZCoNE1LpnJI/wcUpRUiuQhoLFeT1E432GuPuZ7y+agElGj0NnBxEgnHrhrnZWUbULpRa/il+Cr5Taj988HqX9Xdm6FjcP4Lbuds/44U7U8du224Q8jTrZ57Yvj4VDQKc='),
    ])
    def test_only_at_apex(self, qtype, content):
        name, payload, zone = self.create_zone(soa_edit_api='')
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': qtype,
            'ttl': 3600,
            'records': [
                {
                    "content": content,
                    "disabled": False
                },
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        # verify that the new record is there
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        self.assertEqual(get_rrset(data, name, qtype)['records'], rrset['records'])

        rrset = {
            'changetype': 'replace',
            'name': 'sub.' + name,
            'type': qtype,
            'ttl': 3600,
            'records': [
                {
                    "content": content,
                    "disabled": False
                },
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(self.url("/api/v1/servers/localhost/zones/" + name), data=json.dumps(payload),
                               headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('only allowed at apex', r.json()['error'])
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        self.assertIsNone(get_rrset(data, 'sub.' + name, qtype))

    @parameterized.expand([
        ('DS', '44030 8 2 d4c3d5552b8679faeebc317e5f048b614b2e5f607dc57f1553182d49ab2179f7'),
    ])
    def test_not_allowed_at_apex(self, qtype, content):
        name, payload, zone = self.create_zone()
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': qtype,
            'ttl': 3600,
            'records': [
                {
                    "content": content,
                    "disabled": False
                },
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(self.url("/api/v1/servers/localhost/zones/" + name), data=json.dumps(payload),
                               headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('not allowed at apex', r.json()['error'])
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        self.assertIsNone(get_rrset(data, 'sub.' + name, qtype))

        rrset = {
            'changetype': 'replace',
            'name': 'sub.' + name,
            'type': qtype,
            'ttl': 3600,
            'records': [
                {
                    "content": content,
                    "disabled": False
                },
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        # verify that the new record is there
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        self.assertEqual(get_rrset(data, 'sub.' + name, qtype)['records'], rrset['records'])

    def test_rr_svcb(self):
        name, payload, zone = self.create_zone()
        rrset = {
            'changetype': 'replace',
            'name': 'svcb.' + name,
            'type': 'SVCB',
            'ttl': 3600,
            'records': [
                {
                    "content": '40 . mandatory=alpn alpn=h2,h3 ipv4hint=192.0.2.1,192.0.2.2 ech="dG90YWxseSBib2d1cyBlY2hjb25maWcgdmFsdWU="',
                    "disabled": False
                },
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(self.url("/api/v1/servers/localhost/zones/" + name), data=json.dumps(payload),
                               headers={'content-type': 'application/json'})
        self.assert_success(r)

    def test_rrset_ns_dname_exclude(self):
        name, payload, zone = self.create_zone()
        rrset = {
            'changetype': 'replace',
            'name': 'delegation.'+name,
            'type': 'NS',
            'ttl': 3600,
            'records': [
                {
                    "content": "ns.example.org.",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(self.url("/api/v1/servers/localhost/zones/" + name), data=json.dumps(payload),
                               headers={'content-type': 'application/json'})
        self.assert_success(r)
        rrset = {
            'changetype': 'replace',
            'name': 'delegation.'+name,
            'type': 'DNAME',
            'ttl': 3600,
            'records': [
                {
                    "content": "example.com.",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(self.url("/api/v1/servers/localhost/zones/" + name), data=json.dumps(payload),
                               headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('Cannot have both NS and DNAME except in zone apex', r.json()['error'])

## FIXME: Enable this when it's time for it
#    def test_rrset_dname_nothing_under(self):
#        name, payload, zone = self.create_zone()
#        rrset = {
#            'changetype': 'replace',
#            'name': 'delegation.'+name,
#            'type': 'DNAME',
#            'ttl': 3600,
#            'records': [
#                {
#                    "content": "example.com.",
#                    "disabled": False
#                }
#            ]
#        }
#        payload = {'rrsets': [rrset]}
#        r = self.session.patch(self.url("/api/v1/servers/localhost/zones/" + name), data=json.dumps(payload),
#                               headers={'content-type': 'application/json'})
#        self.assert_success(r)
#        rrset = {
#            'changetype': 'replace',
#            'name': 'sub.delegation.'+name,
#            'type': 'A',
#            'ttl': 3600,
#            'records': [
#                {
#                    "content": "1.2.3.4",
#                    "disabled": False
#                }
#            ]
#        }
#        payload = {'rrsets': [rrset]}
#        r = self.session.patch(self.url("/api/v1/servers/localhost/zones/" + name), data=json.dumps(payload),
#                               headers={'content-type': 'application/json'})
#        self.assertEqual(r.status_code, 422)
#        self.assertIn('You cannot have record(s) under CNAME/DNAME', r.json()['error'])

    def test_create_zone_with_leading_space(self):
        # Actual regression.
        name, payload, zone = self.create_zone()
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'A',
            'ttl': 3600,
            'records': [
                {
                    "content": " 4.3.2.1",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(self.url("/api/v1/servers/localhost/zones/" + name), data=json.dumps(payload),
                               headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('Not in expected format', r.json()['error'])

    @unittest.skipIf(is_auth_lmdb(), "No out-of-zone storage in LMDB")
    def test_zone_rr_delete_out_of_zone(self):
        name, payload, zone = self.create_zone()
        rrset = {
            'changetype': 'delete',
            'name': 'not-in-zone.',
            'type': 'NS'
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        print(r.content)
        self.assert_success(r)  # succeed so users can fix their wrong, old data

    def test_zone_delete(self):
        name, payload, zone = self.create_zone()
        r = self.session.delete(self.url("/api/v1/servers/localhost/zones/" + name))
        self.assertEqual(r.status_code, 204)
        self.assertNotIn('Content-Type', r.headers)

    def test_zone_comment_create(self):
        name, payload, zone = self.create_zone()
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'ttl': 3600,
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
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        if is_auth_lmdb():
            self.assert_error_json(r)  # No comments in LMDB
            return
        else:
            self.assert_success(r)
        # make sure the comments have been set, and that the NS
        # records are still present
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        serverset = get_rrset(data, name, 'NS')
        print(serverset)
        self.assertNotEqual(serverset['records'], [])
        self.assertNotEqual(serverset['comments'], [])
        # verify that modified_at has been set by pdns
        self.assertNotEqual([c for c in serverset['comments']][0]['modified_at'], 0)
        # verify that TTL is correct (regression test)
        self.assertEqual(serverset['ttl'], 3600)

    def test_zone_comment_delete(self):
        # Test: Delete ONLY comments.
        name, payload, zone = self.create_zone()
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'comments': []
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        # make sure the NS records are still present
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        serverset = get_rrset(data, name, 'NS')
        print(serverset)
        self.assertNotEqual(serverset['records'], [])
        self.assertEqual(serverset['comments'], [])

    @unittest.skipIf(is_auth_lmdb(), "No comments in LMDB")
    def test_zone_comment_out_of_range_modified_at(self):
        # Test if comments on an rrset stay intact if the rrset is replaced
        name, payload, zone = self.create_zone()
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'comments': [
                {
                    'account': 'test1',
                    'content': 'oh hi there',
                    'modified_at': '4294967297'
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn("Value for key 'modified_at' is out of range", r.json()['error'])

    @unittest.skipIf(is_auth_lmdb(), "No comments in LMDB")
    def test_zone_comment_stay_intact(self):
        # Test if comments on an rrset stay intact if the rrset is replaced
        name, payload, zone = self.create_zone()
        # create a comment
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'comments': [
                {
                    'account': 'test1',
                    'content': 'oh hi there',
                    'modified_at': 1111
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        # replace rrset records
        rrset2 = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'ttl': 3600,
            'records': [
                {
                    "content": "ns1.bar.com.",
                    "disabled": False
                }
            ]
        }
        payload2 = {'rrsets': [rrset2]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload2),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        # make sure the comments still exist
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + name)).json()
        serverset = get_rrset(data, name, 'NS')
        print(serverset)
        self.assertEqual(serverset['records'], rrset2['records'])
        self.assertEqual(serverset['comments'], rrset['comments'])

    @unittest.skipIf(is_auth_lmdb(), "No search in LMDB")
    def test_search_rr_exact_zone(self):
        name = unique_zone_name()
        self.create_zone(name=name, serial=22, soa_edit_api='')
        r = self.session.get(self.url("/api/v1/servers/localhost/search-data?q=" + name.rstrip('.')))
        self.assert_success_json(r)
        print(r.json())
        self.assertCountEqual(r.json(), [
            {u'object_type': u'zone', u'name': name, u'zone_id': name},
            {u'content': u'ns1.example.com.',
             u'zone_id': name, u'zone': name, u'object_type': u'record', u'disabled': False,
             u'ttl': 3600, u'type': u'NS', u'name': name},
            {u'content': u'ns2.example.com.',
             u'zone_id': name, u'zone': name, u'object_type': u'record', u'disabled': False,
             u'ttl': 3600, u'type': u'NS', u'name': name},
            {u'content': u'a.misconfigured.dns.server.invalid. hostmaster.'+name+' 22 10800 3600 604800 3600',
             u'zone_id': name, u'zone': name, u'object_type': u'record', u'disabled': False,
             u'ttl': 3600, u'type': u'SOA', u'name': name},
        ])

    @unittest.skipIf(is_auth_lmdb(), "No search in LMDB")
    def test_search_rr_exact_zone_filter_type_zone(self):
        name = unique_zone_name()
        data_type = "zone"
        self.create_zone(name=name, serial=22, soa_edit_api='')
        r = self.session.get(self.url("/api/v1/servers/localhost/search-data?q=" + name.rstrip('.') + "&object_type=" + data_type))
        self.assert_success_json(r)
        print(r.json())
        self.assertEqual(r.json(), [
            {u'object_type': u'zone', u'name': name, u'zone_id': name},
        ])

    @unittest.skipIf(is_auth_lmdb(), "No search in LMDB")
    def test_search_rr_exact_zone_filter_type_record(self):
        name = unique_zone_name()
        data_type = "record"
        self.create_zone(name=name, serial=22, soa_edit_api='')
        r = self.session.get(self.url("/api/v1/servers/localhost/search-data?q=" + name.rstrip('.') + "&object_type=" + data_type))
        self.assert_success_json(r)
        print(r.json())
        self.assertCountEqual(r.json(), [
            {u'content': u'ns1.example.com.',
             u'zone_id': name, u'zone': name, u'object_type': u'record', u'disabled': False,
             u'ttl': 3600, u'type': u'NS', u'name': name},
            {u'content': u'ns2.example.com.',
             u'zone_id': name, u'zone': name, u'object_type': u'record', u'disabled': False,
             u'ttl': 3600, u'type': u'NS', u'name': name},
            {u'content': u'a.misconfigured.dns.server.invalid. hostmaster.'+name+' 22 10800 3600 604800 3600',
             u'zone_id': name, u'zone': name, u'object_type': u'record', u'disabled': False,
             u'ttl': 3600, u'type': u'SOA', u'name': name},
        ])

    @unittest.skipIf(is_auth_lmdb(), "No search in LMDB")
    def test_search_rr_substring(self):
        name = unique_zone_name()
        search = name[5:-5]
        self.create_zone(name=name)
        r = self.session.get(self.url("/api/v1/servers/localhost/search-data?q=*%s*" % search))
        self.assert_success_json(r)
        print(r.json())
        # should return zone, SOA, ns1, ns2
        self.assertEqual(len(r.json()), 4)

    @unittest.skipIf(is_auth_lmdb(), "No search in LMDB")
    def test_search_rr_case_insensitive(self):
        name = unique_zone_name()+'testsuffix.'
        self.create_zone(name=name)
        r = self.session.get(self.url("/api/v1/servers/localhost/search-data?q=*testSUFFIX*"))
        self.assert_success_json(r)
        print(r.json())
        # should return zone, SOA, ns1, ns2
        self.assertEqual(len(r.json()), 4)

    @unittest.skipIf(is_auth_lmdb(), "No search or comments in LMDB")
    def test_search_rr_comment(self):
        name = unique_zone_name()
        rrsets = [{
            "name": name,
            "type": "AAAA",
            "ttl": 3600,
            "records": [{
                "content": "2001:DB8::1",
                "disabled": False,
            }],
            "comments": [{
                "account": "test AAAA",
                "content": "blah",
                "modified_at": 11112,
            }],
        }]
        name, payload, data = self.create_zone(name=name, rrsets=rrsets)
        r = self.session.get(self.url("/api/v1/servers/localhost/search-data?q=blah"))
        self.assert_success_json(r)
        data = r.json()
        # should return the AAAA record
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['object_type'], 'comment')
        self.assertEqual(data[0]['type'], 'AAAA')
        self.assertEqual(data[0]['name'], name)
        self.assertEqual(data[0]['content'], rrsets[0]['comments'][0]['content'])

    @unittest.skipIf(is_auth_lmdb(), "No search in LMDB")
    def test_search_after_rectify_with_ent(self):
        name = unique_zone_name()
        search = name.split('.')[0]
        rrset = {
            "name": 'sub.sub.' + name,
            "type": "A",
            "ttl": 3600,
            "records": [{
                "content": "4.3.2.1",
                "disabled": False,
            }],
        }
        self.create_zone(name=name, rrsets=[rrset])
        pdnsutil_rectify(name)
        r = self.session.get(self.url("/api/v1/servers/localhost/search-data?q=*%s*" % search))
        self.assert_success_json(r)
        print(r.json())
        # should return zone, SOA, ns1, ns2, sub.sub A (but not the ENT)
        self.assertEqual(len(r.json()), 5)

    @unittest.skipIf(is_auth_lmdb(), "No get_db_records for LMDB")
    def test_default_api_rectify_dnssec(self):
        name = unique_zone_name()
        rrsets = [
            {
                "name": 'a.' + name,
                "type": "AAAA",
                "ttl": 3600,
                "records": [{
                    "content": "2001:DB8::1",
                    "disabled": False,
                }],
            },
            {
                "name": 'b.' + name,
                "type": "AAAA",
                "ttl": 3600,
                "records": [{
                    "content": "2001:DB8::2",
                    "disabled": False,
                }],
            },
        ]
        self.create_zone(name=name, rrsets=rrsets, dnssec=True, nsec3param='1 0 1 ab')
        dbrecs = get_db_records(name, 'AAAA')
        self.assertIsNotNone(dbrecs[0]['ordername'])

    def test_default_api_rectify_nodnssec(self):
        """Without any DNSSEC settings, rectify should still add ENTs. Setup the zone
        so ENTs are necessary, and check for their existence using sdig.
        """
        name = unique_zone_name()
        rrsets = [
            {
                "name": 'a.sub.' + name,
                "type": "AAAA",
                "ttl": 3600,
                "records": [{
                    "content": "2001:DB8::1",
                    "disabled": False,
                }],
            },
            {
                "name": 'b.sub.' + name,
                "type": "AAAA",
                "ttl": 3600,
                "records": [{
                    "content": "2001:DB8::2",
                    "disabled": False,
                }],
            },
        ]
        self.create_zone(name=name, rrsets=rrsets)
        # default-api-rectify is yes (by default). expect rectify to have happened.
        assert 'Rcode: 0 ' in sdig('sub.' + name, 'TXT')

    @unittest.skipIf(is_auth_lmdb(), "No get_db_records for LMDB")
    def test_override_api_rectify(self):
        name = unique_zone_name()
        search = name.split('.')[0]
        rrsets = [
            {
                "name": 'a.' + name,
                "type": "AAAA",
                "ttl": 3600,
                "records": [{
                    "content": "2001:DB8::1",
                    "disabled": False,
                }],
            },
            {
                "name": 'b.' + name,
                "type": "AAAA",
                "ttl": 3600,
                "records": [{
                    "content": "2001:DB8::2",
                    "disabled": False,
                }],
            },
        ]
        self.create_zone(name=name, rrsets=rrsets, api_rectify=False, dnssec=True, nsec3param='1 0 1 ab')
        dbrecs = get_db_records(name, 'AAAA')
        self.assertIsNone(dbrecs[0]['ordername'])

    @unittest.skipIf(is_auth_lmdb(), "No get_db_records for LMDB")
    def test_explicit_rectify_success(self):
        name, _, data = self.create_zone = self.create_zone(api_rectify=False, dnssec=True, nsec3param='1 0 1 ab')
        dbrecs = get_db_records(name, 'SOA')
        self.assertIsNone(dbrecs[0]['ordername'])
        r = self.session.put(self.url("/api/v1/servers/localhost/zones/" + data['id'] + "/rectify"))
        self.assertEqual(r.status_code, 200)
        dbrecs = get_db_records(name, 'SOA')
        self.assertIsNotNone(dbrecs[0]['ordername'])

    def test_explicit_rectify_slave(self):
        # Some users want to move a zone to kind=Slave and then rectify, without a re-transfer.
        name, _, data = self.create_zone = self.create_zone(api_rectify=False, dnssec=True, nsec3param='1 0 1 ab')
        r = self.session.put(self.url("/api/v1/servers/localhost/zones/" + data['id']),
            data=json.dumps({'kind': 'Slave'}),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 204)
        r = self.session.put(self.url("/api/v1/servers/localhost/zones/" + data['id'] + "/rectify"))
        self.assertEqual(r.status_code, 200)
        if not is_auth_lmdb():
            dbrecs = get_db_records(name, 'SOA')
            self.assertIsNotNone(dbrecs[0]['ordername'])

    def test_cname_at_ent_place(self):
        name, payload, zone = self.create_zone(dnssec=True, api_rectify=True)
        rrset = {
            'changetype': 'replace',
            'name': 'sub2.sub1.' + name,
            'type': "A",
            'ttl': 3600,
            'records': [{
                'content': "4.3.2.1",
                'disabled': False,
            }],
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + zone['id']),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 204)
        rrset = {
            'changetype': 'replace',
            'name': 'sub1.' + name,
            'type': "CNAME",
            'ttl': 3600,
            'records': [{
                'content': "www.example.org.",
                'disabled': False,
            }],
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/api/v1/servers/localhost/zones/" + zone['id']),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 204)

    def test_rrset_parameter_post_false(self):
        name = unique_zone_name()
        payload = {
            'name': name,
            'kind': 'Native',
            'nameservers': ['ns1.example.com.', 'ns2.example.com.']
        }
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones?rrsets=false"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        print(r.json())
        self.assert_success_json(r)
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json().get('rrsets'), None)

    def test_rrset_false_parameter(self):
        name = unique_zone_name()
        self.create_zone(name=name, kind='Native')
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/"+name+"?rrsets=false"))
        self.assert_success_json(r)
        print(r.json())
        self.assertEqual(r.json().get('rrsets'), None)

    def test_rrset_true_parameter(self):
        name = unique_zone_name()
        self.create_zone(name=name, kind='Native')
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/"+name+"?rrsets=true"))
        self.assert_success_json(r)
        print(r.json())
        self.assertEqual(len(r.json().get('rrsets')), 2)

    def test_wrong_rrset_parameter(self):
        name = unique_zone_name()
        self.create_zone(name=name, kind='Native')
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/"+name+"?rrsets=foobar"))
        self.assertEqual(r.status_code, 422)
        self.assertIn("'rrsets' request parameter value 'foobar' is not supported", r.json()['error'])

    def test_put_master_tsig_key_ids_non_existent(self):
        name = unique_zone_name()
        keyname = unique_zone_name().split('.')[0]
        self.create_zone(name=name, kind='Native')
        payload = {
            'master_tsig_key_ids': [keyname]
        }
        r = self.session.put(self.url('/api/v1/servers/localhost/zones/' + name),
                             data=json.dumps(payload),
                             headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('A TSIG key with the name', r.json()['error'])

    def test_put_slave_tsig_key_ids_non_existent(self):
        name = unique_zone_name()
        keyname = unique_zone_name().split('.')[0]
        self.create_zone(name=name, kind='Native')
        payload = {
            'slave_tsig_key_ids': [keyname]
        }
        r = self.session.put(self.url('/api/v1/servers/localhost/zones/' + name),
                             data=json.dumps(payload),
                             headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('A TSIG key with the name', r.json()['error'])


@unittest.skipIf(not is_auth(), "Not applicable")
class AuthRootZone(ApiTestCase, AuthZonesHelperMixin):

    def setUp(self):
        super(AuthRootZone, self).setUp()
        # zone name is not unique, so delete the zone before each individual test.
        self.session.delete(self.url("/api/v1/servers/localhost/zones/=2E"))

    def test_create_zone(self):
        name, payload, data = self.create_zone(name='.', serial=22, soa_edit_api='')
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial', 'soa_edit_api', 'soa_edit', 'account'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEqual(data[k], payload[k])
        # validate generated SOA
        rec = get_first_rec(data, '.', 'SOA')
        self.assertEqual(
            rec['content'],
            "a.misconfigured.dns.server.invalid. hostmaster. " + str(payload['serial']) +
            " 10800 3600 604800 3600"
        )
        # Regression test: verify zone list works
        zonelist = self.session.get(self.url("/api/v1/servers/localhost/zones")).json()
        print("zonelist:", zonelist)
        self.assertIn(payload['name'], [zone['name'] for zone in zonelist])
        # Also test that fetching the zone works.
        print("id:", data['id'])
        self.assertEqual(data['id'], '=2E')
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + data['id'])).json()
        print("zone (fetched):", data)
        for k in ('name', 'kind'):
            self.assertIn(k, data)
            self.assertEqual(data[k], payload[k])
        self.assertEqual(data['rrsets'][0]['name'], '.')

    def test_update_zone(self):
        name, payload, zone = self.create_zone(name='.')
        zone_id = '=2E'
        # update, set as Master and enable SOA-EDIT-API
        payload = {
            'kind': 'Master',
            'masters': ['192.0.2.1', '192.0.2.2'],
            'soa_edit_api': 'EPOCH',
            'soa_edit': 'EPOCH'
        }
        r = self.session.put(
            self.url("/api/v1/servers/localhost/zones/" + zone_id),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + zone_id)).json()
        for k in payload.keys():
            self.assertIn(k, data)
            self.assertEqual(data[k], payload[k])
        # update, back to Native and empty(off)
        payload = {
            'kind': 'Native',
            'soa_edit_api': '',
            'soa_edit': ''
        }
        r = self.session.put(
            self.url("/api/v1/servers/localhost/zones/" + zone_id),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + zone_id)).json()
        for k in payload.keys():
            self.assertIn(k, data)
            self.assertEqual(data[k], payload[k])


@unittest.skipIf(not is_recursor(), "Not applicable")
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
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        return payload, r.json()

    def test_create_auth_zone(self):
        payload, data = self.create_zone(kind='Native')
        for k in payload.keys():
            self.assertEqual(data[k], payload[k])

    def test_create_zone_no_name(self):
        payload = {
            'name': '',
            'kind': 'Native',
            'servers': ['8.8.8.8'],
            'recursion_desired': False,
        }
        print(payload)
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assertIn('is not canonical', r.json()['error'])

    def test_create_forwarded_zone(self):
        payload, data = self.create_zone(kind='Forwarded', rd=False, servers=['8.8.8.8'])
        # return values are normalized
        payload['servers'][0] += ':53'
        for k in payload.keys():
            self.assertEqual(data[k], payload[k])

    def test_create_forwarded_rd_zone(self):
        payload, data = self.create_zone(name='google.com.', kind='Forwarded', rd=True, servers=['8.8.8.8'])
        # return values are normalized
        payload['servers'][0] += ':53'
        for k in payload.keys():
            self.assertEqual(data[k], payload[k])

    def test_create_auth_zone_with_symbols(self):
        payload, data = self.create_zone(name='foo/bar.'+unique_zone_name(), kind='Native')
        expected_id = (payload['name'].replace('/', '=2F'))
        for k in payload.keys():
            self.assertEqual(data[k], payload[k])
        self.assertEqual(data['id'], expected_id)

    def test_rename_auth_zone(self):
        payload, data = self.create_zone(kind='Native')
        name = payload['name']
        # now rename it
        payload = {
            'name': 'renamed-'+name,
            'kind': 'Native',
            'recursion_desired': False
        }
        r = self.session.put(
            self.url("/api/v1/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success(r)
        data = self.session.get(self.url("/api/v1/servers/localhost/zones/" + payload['name'])).json()
        for k in payload.keys():
            self.assertEqual(data[k], payload[k])

    def test_zone_delete(self):
        payload, zone = self.create_zone(kind='Native')
        name = payload['name']
        r = self.session.delete(self.url("/api/v1/servers/localhost/zones/" + name))
        self.assertEqual(r.status_code, 204)
        self.assertNotIn('Content-Type', r.headers)

    def test_search_rr_exact_zone(self):
        name = unique_zone_name()
        self.create_zone(name=name, kind='Native')
        r = self.session.get(self.url("/api/v1/servers/localhost/search-data?q=" + name))
        self.assert_success_json(r)
        print(r.json())
        self.assertEqual(r.json(), [{u'type': u'zone', u'name': name, u'zone_id': name}])

    def test_search_rr_substring(self):
        name = 'search-rr-zone.name.'
        self.create_zone(name=name, kind='Native')
        r = self.session.get(self.url("/api/v1/servers/localhost/search-data?q=rr-zone"))
        self.assert_success_json(r)
        print(r.json())
        # should return zone, SOA
        self.assertEqual(len(r.json()), 2)

@unittest.skipIf(not is_auth(), "Not applicable")
class AuthZoneKeys(ApiTestCase, AuthZonesHelperMixin):

    def test_get_keys(self):
        r = self.session.get(
            self.url("/api/v1/servers/localhost/zones/powerdnssec.org./cryptokeys"))
        self.assert_success_json(r)
        keys = r.json()
        self.assertGreater(len(keys), 0)

        key0 = deepcopy(keys[0])
        del key0['dnskey']
        del key0['ds']
        expected = {
            u'algorithm': u'ECDSAP256SHA256',
            u'bits': 256,
            u'active': True,
            u'type': u'Cryptokey',
            u'keytype': u'csk',
            u'flags': 257,
            u'published': True,
            u'id': 1}
        self.assertEqual(key0, expected)

        keydata = keys[0]['dnskey'].split()
        self.assertEqual(len(keydata), 4)

    def test_get_keys_with_cds(self):
        payload_metadata = {"type": "Metadata", "kind": "PUBLISH-CDS", "metadata": ["4"]}
        r = self.session.post(self.url("/api/v1/servers/localhost/zones/powerdnssec.org./metadata"),
                              data=json.dumps(payload_metadata))
        rdata = r.json()
        self.assertEqual(r.status_code, 201)
        self.assertEqual(rdata["metadata"], payload_metadata["metadata"])

        r = self.session.get(
            self.url("/api/v1/servers/localhost/zones/powerdnssec.org./cryptokeys"))
        self.assert_success_json(r)
        keys = r.json()
        self.assertGreater(len(keys), 0)

        key0 = deepcopy(keys[0])
        self.assertEqual(len(key0['cds']), 1)
        self.assertIn(key0['cds'][0], key0['ds'])
        self.assertEqual(key0['cds'][0].split()[2], '4')
        del key0['dnskey']
        del key0['ds']
        del key0['cds']
        expected = {
            u'algorithm': u'ECDSAP256SHA256',
            u'bits': 256,
            u'active': True,
            u'type': u'Cryptokey',
            u'keytype': u'csk',
            u'flags': 257,
            u'published': True,
            u'id': 1}
        self.assertEqual(key0, expected)

        keydata = keys[0]['dnskey'].split()
        self.assertEqual(len(keydata), 4)

        r = self.session.delete(self.url("/api/v1/servers/localhost/zones/powerdnssec.org./metadata/PUBLISH-CDS"))
        self.assertEqual(r.status_code, 200)
