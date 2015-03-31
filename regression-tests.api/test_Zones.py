import json
import time
import unittest
from test_helper import ApiTestCase, unique_zone_name, is_auth, is_recursor


class Zones(ApiTestCase):

    def test_list_zones(self):
        r = self.session.get(self.url("/servers/localhost/zones"))
        self.assert_success_json(r)
        domains = r.json()
        example_com = [domain for domain in domains if domain['name'] in ('example.com', 'example.com.')]
        self.assertEquals(len(example_com), 1)
        example_com = example_com[0]
        required_fields = ['id', 'url', 'name', 'kind']
        if is_auth():
            required_fields = required_fields + ['masters', 'last_check', 'notified_serial', 'serial', 'account']
        elif is_recursor():
            required_fields = required_fields + ['recursion_desired', 'servers']
        for field in required_fields:
            self.assertIn(field, example_com)


class AuthZonesHelperMixin(object):
    def create_zone(self, name=None, **kwargs):
        if name is None:
            name = unique_zone_name()
        payload = {
            'name': name,
            'kind': 'Native',
            'nameservers': ['ns1.example.com', 'ns2.example.com']
        }
        for k, v in kwargs.items():
            if v is None:
                del payload[k]
            else:
                payload[k] = v
        print payload
        r = self.session.post(
            self.url("/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        self.assertEquals(r.status_code, 201)
        return payload, r.json()


@unittest.skipIf(not is_auth(), "Not applicable")
class AuthZones(ApiTestCase, AuthZonesHelperMixin):

    def test_create_zone(self):
        # soa_edit_api has a default, override with empty for this test
        payload, data = self.create_zone(serial=22, soa_edit_api='')
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial', 'soa_edit_api', 'soa_edit', 'account'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEquals(data[k], payload[k])
        self.assertEquals(data['comments'], [])
        # validate generated SOA
        self.assertEquals(
            [r['content'] for r in data['records'] if r['type'] == 'SOA'][0],
            "a.misconfigured.powerdns.server hostmaster." + payload['name'] + " " + str(payload['serial']) +
            " 10800 3600 604800 3600"
        )

    def test_create_zone_with_soa_edit_api(self):
        # soa_edit_api wins over serial
        payload, data = self.create_zone(soa_edit_api='EPOCH', serial=10)
        for k in ('soa_edit_api', ):
            self.assertIn(k, data)
            if k in payload:
                self.assertEquals(data[k], payload[k])
        # generated EPOCH serial surely is > fixed serial we passed in
        print data
        self.assertGreater(data['serial'], payload['serial'])
        soa_serial = int([r['content'].split(' ')[2] for r in data['records'] if r['type'] == 'SOA'][0])
        self.assertGreater(soa_serial, payload['serial'])
        self.assertEquals(soa_serial, data['serial'])

    def test_create_zone_with_account(self):
        # soa_edit_api wins over serial
        payload, data = self.create_zone(account='anaccount', serial=10)
        print data
        for k in ('account', ):
            self.assertIn(k, data)
            if k in payload:
                self.assertEquals(data[k], payload[k])

    def test_create_zone_with_records(self):
        name = unique_zone_name()
        records = [
            {
                "name": name,
                "type": "A",
                "ttl": 3600,
                "content": "4.3.2.1",
                "disabled": False
            }
        ]
        payload, data = self.create_zone(name=name, records=records)
        # check our record has appeared
        self.assertEquals([r for r in data['records'] if r['type'] == records[0]['type']], records)

    def test_create_zone_with_comments(self):
        name = unique_zone_name()
        comments = [
            {
                'name': name,
                'type': 'soa',  # test uppercasing of type, too.
                'account': 'test1',
                'content': 'blah blah',
                'modified_at': 11112,
            }
        ]
        payload, data = self.create_zone(name=name, comments=comments)
        comments[0]['type'] = comments[0]['type'].upper()
        # check our comment has appeared
        self.assertEquals(data['comments'], comments)

    def test_create_zone_with_custom_soa(self):
        name = unique_zone_name()
        records = [
            {
                "name": name,
                'type': 'soa',  # test uppercasing of type, too.
                "ttl": 3600,
                "content": "ns1.example.net testmaster@example.net 10 10800 3600 604800 3600",
                "disabled": False
            }
        ]
        payload, data = self.create_zone(name=name, records=records)
        records[0]['type'] = records[0]['type'].upper()
        self.assertEquals([r for r in data['records'] if r['type'] == records[0]['type']], records)

    def test_create_zone_trailing_dot(self):
        # Trailing dots should not end up in the zone name.
        basename = unique_zone_name()
        payload, data = self.create_zone(name=basename+'.')
        self.assertEquals(data['name'], basename)

    def test_create_zone_with_symbols(self):
        payload, data = self.create_zone(name='foo/bar.'+unique_zone_name())
        name = payload['name']
        expected_id = (name.replace('/', '=2F')) + '.'
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEquals(data[k], payload[k])
        self.assertEquals(data['id'], expected_id)

    def test_create_zone_with_nameservers_non_string(self):
        # ensure we don't crash
        name = unique_zone_name()
        payload = {
            'name': name,
            'kind': 'Native',
            'nameservers': [{'a': 'ns1.example.com'}]  # invalid
        }
        print payload
        r = self.session.post(
            self.url("/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEquals(r.status_code, 422)

    def test_create_slave_zone(self):
        # Test that nameservers can be absent for slave zones.
        payload, data = self.create_zone(kind='Slave', nameservers=None, masters=['127.0.0.2'])
        for k in ('name', 'masters', 'kind'):
            self.assertIn(k, data)
            self.assertEquals(data[k], payload[k])
        print "payload:", payload
        print "data:", data
        # Because slave zones don't get a SOA, we need to test that they'll show up in the zone list.
        r = self.session.get(self.url("/servers/localhost/zones"))
        zonelist = r.json()
        print "zonelist:", zonelist
        self.assertIn(payload['name'], [zone['name'] for zone in zonelist])
        # Also test that fetching the zone works.
        r = self.session.get(self.url("/servers/localhost/zones/" + data['id']))
        data = r.json()
        print "zone (fetched):", data
        for k in ('name', 'masters', 'kind'):
            self.assertIn(k, data)
            self.assertEquals(data[k], payload[k])
        self.assertEqual(data['serial'], 0)
        self.assertEqual(data['records'], [])

    def test_delete_slave_zone(self):
        payload, data = self.create_zone(kind='Slave', nameservers=None, masters=['127.0.0.2'])
        r = self.session.delete(self.url("/servers/localhost/zones/" + data['id']))
        r.raise_for_status()

    def test_retrieve_slave_zone(self):
        payload, data = self.create_zone(kind='Slave', nameservers=None, masters=['127.0.0.2'])
        print "payload:", payload
        print "data:", data
        r = self.session.put(self.url("/servers/localhost/zones/" + data['id'] + "/axfr-retrieve"))
        data = r.json()
        print "status for axfr-retrieve:", data
        self.assertEqual(data['result'], u'Added retrieval request for \'' + payload['name'] +
                         '\' from master 127.0.0.2')

    def test_notify_master_zone(self):
        payload, data = self.create_zone(kind='Master')
        print "payload:", payload
        print "data:", data
        r = self.session.put(self.url("/servers/localhost/zones/" + data['id'] + "/notify"))
        data = r.json()
        print "status for notify:", data
        self.assertEqual(data['result'], 'Notification queued')

    def test_get_zone_with_symbols(self):
        payload, data = self.create_zone(name='foo/bar.'+unique_zone_name())
        name = payload['name']
        zone_id = (name.replace('/', '=2F')) + '.'
        r = self.session.get(self.url("/servers/localhost/zones/" + zone_id))
        data = r.json()
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial', 'dnssec'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEquals(data[k], payload[k])

    def test_get_zone(self):
        r = self.session.get(self.url("/servers/localhost/zones"))
        domains = r.json()
        example_com = [domain for domain in domains if domain['name'] == u'example.com'][0]
        r = self.session.get(self.url("/servers/localhost/zones/" + example_com['id']))
        self.assert_success_json(r)
        data = r.json()
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial'):
            self.assertIn(k, data)
        self.assertEquals(data['name'], 'example.com')

    def test_import_zone_broken(self):
        payload = {}
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
        payload['name'] = 'powerdns-broken.com'
        payload['kind'] = 'Master'
        payload['nameservers'] = []
        r = self.session.post(
            self.url("/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEquals(r.status_code, 422)

    def test_import_zone_axfr(self):
        payload = {}
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
        payload['name'] = 'powerdns.com'
        payload['kind'] = 'Master'
        payload['nameservers'] = []
        r = self.session.post(
            self.url("/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        data = r.json()
        self.assertIn('name', data)
        self.assertIn('records', data)

        expected = {
            'NS': [
                { 'content': 'powerdnssec1.ds9a.nl.' },
                { 'content': 'powerdnssec2.ds9a.nl.' } ],
            'SOA': [
                { 'content': 'powerdnssec1.ds9a.nl. ahu.ds9a.nl. 1343746984 10800 3600 604800 10800' } ],
            'MX': [
                { 'content': '0 xs.powerdns.com.' } ],
            'A': [
                { 'content': '82.94.213.34', 'name': 'powerdns.com' } ],
            'AAAA': [
                { 'content': '2001:888:2000:1d::2', 'name': 'powerdns.com' } ]
        }

        counter = {}
        for et in expected.keys():
            counter[et] = len(expected[et])
            for ev in expected[et]:
                for ret in data['records']:
                    if 'name' in ev:
                        if ret['name'] == ev['name'] and ret['content'] == ev['content'].rstrip('.'):
                            counter[et] = counter[et]-1
                            continue
                    if ret['content'] == ev['content'].rstrip('.'):
                        counter[et] = counter[et]-1
            self.assertEquals(counter[et], 0)

    def test_import_zone_bind(self):
        payload = {}
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
        payload['name'] = 'example.org'
        payload['kind'] = 'Master'
        payload['nameservers'] = []
        r = self.session.post(
            self.url("/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        data = r.json()
        self.assertIn('name', data)
        self.assertIn('records', data)

        expected = {
            'NS': [
                { 'content': 'ns1.example.org.' },
                { 'content': 'ns2.smokeyjoe.com.' } ],
            'SOA': [
                { 'content': 'ns1.example.org. hostmaster.example.org. 2002022401 10800 15 604800 10800' } ],
            'MX': [
                { 'content': '10 mail.another.com.' } ],
            'A': [
                { 'content': '192.168.0.1', 'name': 'ns1.example.org' },
                { 'content': '192.168.0.2', 'name': 'www.example.org' },
                { 'content': '192.168.0.3', 'name': 'bill.example.org' },
                { 'content': '192.168.0.4', 'name': 'fred.example.org' } ],
            'CNAME': [
                { 'content': 'www.example.org', 'name': 'ftp.example.org' } ]
        }

        counter = {}
        for et in expected.keys():
            counter[et] = len(expected[et])
            for ev in expected[et]:
                for ret in data['records']:
                    if 'name' in ev:
                        if ret['name'] == ev['name'] and ret['content'] == ev['content'].rstrip('.'):
                            counter[et] = counter[et]-1
                            continue
                    if ret['content'] == ev['content'].rstrip('.'):
                        counter[et] = counter[et]-1
            self.assertEquals(counter[et], 0)

    def test_export_zone_json(self):
        payload, zone = self.create_zone(nameservers=['ns1.foo.com', 'ns2.foo.com'], soa_edit_api='')
        name = payload['name']
        # export it
        r = self.session.get(
            self.url("/servers/localhost/zones/" + name + "/export"),
            headers={'accept': 'application/json;q=0.9,*/*;q=0.8'}
        )
        self.assert_success_json(r)
        data = r.json()
        self.assertIn('zone', data)
        expected_data = [name + '.\t3600\tNS\tns1.foo.com.',
                         name + '.\t3600\tNS\tns2.foo.com.',
                         name + '.\t3600\tSOA\ta.misconfigured.powerdns.server. hostmaster.' + name +
                         '. 0 10800 3600 604800 3600']
        self.assertEquals(data['zone'].strip().split('\n'), expected_data)

    def test_export_zone_text(self):
        payload, zone = self.create_zone(nameservers=['ns1.foo.com', 'ns2.foo.com'], soa_edit_api='')
        name = payload['name']
        # export it
        r = self.session.get(
            self.url("/servers/localhost/zones/" + name + "/export"),
            headers={'accept': '*/*'}
        )
        data = r.text.strip().split("\n")
        expected_data = [name + '.\t3600\tNS\tns1.foo.com.',
                         name + '.\t3600\tNS\tns2.foo.com.',
                         name + '.\t3600\tSOA\ta.misconfigured.powerdns.server. hostmaster.' + name +
                         '. 0 10800 3600 604800 3600']
        self.assertEquals(data, expected_data)

    def test_update_zone(self):
        payload, zone = self.create_zone()
        name = payload['name']
        # update, set as Master and enable SOA-EDIT-API
        payload = {
            'kind': 'Master',
            'masters': ['192.0.2.1', '192.0.2.2'],
            'soa_edit_api': 'EPOCH',
            'soa_edit': 'EPOCH'
        }
        r = self.session.put(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        data = r.json()
        for k in payload.keys():
            self.assertIn(k, data)
            self.assertEquals(data[k], payload[k])
        # update, back to Native and empty(off)
        payload = {
            'kind': 'Native',
            'soa_edit_api': '',
            'soa_edit': ''
        }
        r = self.session.put(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        data = r.json()
        for k in payload.keys():
            self.assertIn(k, data)
            self.assertEquals(data[k], payload[k])

    def test_zone_rr_update(self):
        payload, zone = self.create_zone()
        name = payload['name']
        # do a replace (= update)
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'ns',
            'records': [
                {
                    "name": name,
                    "type": "NS",
                    "ttl": 3600,
                    "content": "ns1.bar.com",
                    "disabled": False
                },
                {
                    "name": name,
                    "type": "NS",
                    "ttl": 1800,
                    "content": "ns2-disabled.bar.com",
                    "disabled": True
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        # verify that (only) the new record is there
        r = self.session.get(self.url("/servers/localhost/zones/" + name))
        rrset['type'] = rrset['type'].upper()
        data = r.json()['records']
        recs = [rec for rec in data if rec['type'] == rrset['type'] and rec['name'] == rrset['name']]
        self.assertEquals(recs, rrset['records'])

    def test_zone_rr_update_mx(self):
        # Important to test with MX records, as they have a priority field, which must end up in the content field.
        payload, zone = self.create_zone()
        name = payload['name']
        # do a replace (= update)
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'MX',
            'records': [
                {
                    "name": name,
                    "type": "MX",
                    "ttl": 3600,
                    "content": "10 mail.example.org",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        # verify that (only) the new record is there
        r = self.session.get(self.url("/servers/localhost/zones/" + name))
        data = r.json()['records']
        recs = [rec for rec in data if rec['type'] == rrset['type'] and rec['name'] == rrset['name']]
        self.assertEquals(recs, rrset['records'])

    def test_zone_rr_update_multiple_rrsets(self):
        payload, zone = self.create_zone()
        name = payload['name']
        rrset1 = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'records': [
                {
                    "name": name,
                    "type": "NS",
                    "ttl": 3600,
                    "content": "ns9999.example.com",
                    "disabled": False
                }
            ]
        }
        rrset2 = {
            'changetype': 'replace',
            'name': name,
            'type': 'MX',
            'records': [
                {
                    "name": name,
                    "type": "MX",
                    "ttl": 3600,
                    "content": "10 mx444.example.com",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset1, rrset2]}
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        # verify that all rrsets have been updated
        r = self.session.get(self.url("/servers/localhost/zones/" + name))
        data = r.json()['records']
        recs1 = [rec for rec in data if rec['type'] == rrset1['type'] and rec['name'] == rrset1['name']]
        self.assertEquals(recs1, rrset1['records'])
        recs2 = [rec for rec in data if rec['type'] == rrset2['type'] and rec['name'] == rrset2['name']]
        self.assertEquals(recs2, rrset2['records'])

    def test_zone_rr_delete(self):
        payload, zone = self.create_zone()
        name = payload['name']
        # do a delete of all NS records (these are created with the zone)
        rrset = {
            'changetype': 'delete',
            'name': name,
            'type': 'NS'
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        # verify that the records are gone
        r = self.session.get(self.url("/servers/localhost/zones/" + name))
        data = r.json()['records']
        recs = [rec for rec in data if rec['type'] == rrset['type'] and rec['name'] == rrset['name']]
        self.assertEquals(recs, [])

    def test_zone_disable_reenable(self):
        # This also tests that SOA-EDIT-API works.
        payload, zone = self.create_zone(soa_edit_api='EPOCH')
        name = payload['name']
        # disable zone by disabling SOA
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'SOA',
            'records': [
                {
                    "name": name,
                    "type": "SOA",
                    "ttl": 3600,
                    "content": "ns1.bar.com hostmaster.foo.org 1 1 1 1 1",
                    "disabled": True
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        # check SOA serial has been edited
        print r.json()
        soa_serial1 = [rec for rec in r.json()['records'] if rec['type'] == 'SOA'][0]['content'].split()[2]
        self.assertNotEquals(soa_serial1, '1')
        # make sure domain is still in zone list (disabled SOA!)
        r = self.session.get(self.url("/servers/localhost/zones"))
        domains = r.json()
        self.assertEquals(len([domain for domain in domains if domain['name'] == name]), 1)
        # sleep 1sec to ensure the EPOCH value changes for the next request
        time.sleep(1)
        # verify that modifying it still works
        rrset['records'][0]['disabled'] = False
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        # check SOA serial has been edited again
        print r.json()
        soa_serial2 = [rec for rec in r.json()['records'] if rec['type'] == 'SOA'][0]['content'].split()[2]
        self.assertNotEquals(soa_serial2, '1')
        self.assertNotEquals(soa_serial2, soa_serial1)

    def test_zone_rr_update_qtype_mismatch(self):
        payload, zone = self.create_zone()
        name = payload['name']
        # replace with qtype mismatch
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'A',
            'records': [
                {
                    "name": name,
                    "type": "NS",
                    "ttl": 3600,
                    "content": "ns1.bar.com",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEquals(r.status_code, 422)

    def test_zone_rr_update_qname_mismatch(self):
        payload, zone = self.create_zone()
        name = payload['name']
        # replace with qname mismatch
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'records': [
                {
                    "name": 'blah.'+name,
                    "type": "NS",
                    "ttl": 3600,
                    "content": "ns1.bar.com",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEquals(r.status_code, 422)

    def test_zone_rr_update_out_of_zone(self):
        payload, zone = self.create_zone()
        name = payload['name']
        # replace with qname mismatch
        rrset = {
            'changetype': 'replace',
            'name': 'not-in-zone',
            'type': 'NS',
            'records': [
                {
                    "name": name,
                    "type": "NS",
                    "ttl": 3600,
                    "content": "ns1.bar.com",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEquals(r.status_code, 422)
        self.assertIn('out of zone', r.json()['error'])

    def test_rrset_unknown_type(self):
        payload, zone = self.create_zone()
        name = payload['name']
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'FAFAFA',
            'records': [
                {
                    "name": name,
                    "type": "FAFAFA",
                    "ttl": 3600,
                    "content": "4.3.2.1",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(self.url("/servers/localhost/zones/" + name), data=json.dumps(payload),
                               headers={'content-type': 'application/json'})
        self.assertEquals(r.status_code, 422)
        self.assertIn('unknown type', r.json()['error'])

    def test_create_zone_with_leading_space(self):
        # Actual regression.
        payload, zone = self.create_zone()
        name = payload['name']
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'A',
            'records': [
                {
                    "name": name,
                    "type": "A",
                    "ttl": 3600,
                    "content": " 4.3.2.1",
                    "disabled": False
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(self.url("/servers/localhost/zones/" + name), data=json.dumps(payload),
                               headers={'content-type': 'application/json'})
        self.assertEquals(r.status_code, 422)
        self.assertIn('Not in expected format', r.json()['error'])

    def test_zone_rr_delete_out_of_zone(self):
        payload, zone = self.create_zone()
        name = payload['name']
        rrset = {
            'changetype': 'delete',
            'name': 'not-in-zone',
            'type': 'NS'
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        print r.content
        self.assertEquals(r.status_code, 200)  # succeed so users can fix their wrong, old data

    def test_zone_delete(self):
        payload, zone = self.create_zone()
        name = payload['name']
        r = self.session.delete(self.url("/servers/localhost/zones/" + name))
        self.assertEquals(r.status_code, 204)
        self.assertNotIn('Content-Type', r.headers)

    def test_zone_comment_create(self):
        payload, zone = self.create_zone()
        name = payload['name']
        rrset = {
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
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        # make sure the comments have been set, and that the NS
        # records are still present
        r = self.session.get(self.url("/servers/localhost/zones/" + name))
        data = r.json()
        print data
        self.assertNotEquals([r for r in data['records'] if r['type'] == 'NS'], [])
        self.assertNotEquals(data['comments'], [])
        # verify that modified_at has been set by pdns
        self.assertNotEquals([c for c in data['comments']][0]['modified_at'], 0)

    def test_zone_comment_delete(self):
        # Test: Delete ONLY comments.
        payload, zone = self.create_zone()
        name = payload['name']
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'comments': []
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        # make sure the NS records are still present
        r = self.session.get(self.url("/servers/localhost/zones/" + name))
        data = r.json()
        print data
        self.assertNotEquals([r for r in data['records'] if r['type'] == 'NS'], [])
        self.assertEquals(data['comments'], [])

    def test_zone_comment_stay_intact(self):
        # Test if comments on an rrset stay intact if the rrset is replaced
        payload, zone = self.create_zone()
        name = payload['name']
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
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        # replace rrset records
        rrset2 = {
            'changetype': 'replace',
            'name': name,
            'type': 'NS',
            'records': [
                {
                    "name": name,
                    "type": "NS",
                    "ttl": 3600,
                    "content": "ns1.bar.com",
                    "disabled": False
                }
            ]
        }
        payload2 = {'rrsets': [rrset2]}
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload2),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        # make sure the comments still exist
        r = self.session.get(self.url("/servers/localhost/zones/" + name))
        data = r.json()
        print data
        # fix up input data for comparison with assertEquals.
        # the fact that we're not sending name+type is part of the API spec.
        for c in rrset['comments']:
            c['name'] = rrset['name']
            c['type'] = rrset['type']

        self.assertEquals([r for r in data['records'] if r['type'] == 'NS'], rrset2['records'])
        self.assertEquals(data['comments'], rrset['comments'])

    def test_zone_auto_ptr_ipv4(self):
        revzone = '0.2.192.in-addr.arpa'
        self.create_zone(name=revzone)
        payload, zone = self.create_zone()
        name = payload['name']
        # replace with qname mismatch
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'A',
            'records': [
                {
                    "name": name,
                    "type": "A",
                    "ttl": 3600,
                    "content": '192.2.0.2',
                    "disabled": False,
                    "set-ptr": True
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        r = self.session.get(self.url("/servers/localhost/zones/" + revzone))
        recs = r.json()['records']
        print recs
        revrec = [rec for rec in recs if rec['type'] == 'PTR']
        self.assertEquals(revrec, [{
            u'content': name,
            u'disabled': False,
            u'ttl': 3600,
            u'type': u'PTR',
            u'name': u'2.0.2.192.in-addr.arpa'
        }])

    def test_zone_auto_ptr_ipv6(self):
        # 2001:DB8::bb:aa
        revzone = '8.b.d.0.1.0.0.2.ip6.arpa'
        self.create_zone(name=revzone)
        payload, zone = self.create_zone()
        name = payload['name']
        # replace with qname mismatch
        rrset = {
            'changetype': 'replace',
            'name': name,
            'type': 'AAAA',
            'records': [
                {
                    "name": name,
                    "type": "AAAA",
                    "ttl": 3600,
                    "content": '2001:DB8::bb:aa',
                    "disabled": False,
                    "set-ptr": True
                }
            ]
        }
        payload = {'rrsets': [rrset]}
        r = self.session.patch(
            self.url("/servers/localhost/zones/" + name),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        r = self.session.get(self.url("/servers/localhost/zones/" + revzone))
        recs = r.json()['records']
        print recs
        revrec = [rec for rec in recs if rec['type'] == 'PTR']
        self.assertEquals(revrec, [{
            u'content': name,
            u'disabled': False,
            u'ttl': 3600,
            u'type': u'PTR',
            u'name': u'a.a.0.0.b.b.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa'
        }])

    def test_search_rr_exact_zone(self):
        name = unique_zone_name()
        self.create_zone(name=name)
        r = self.session.get(self.url("/servers/localhost/search-data?q=" + name))
        self.assert_success_json(r)
        print r.json()
        self.assertEquals(r.json(), [{u'type': u'zone', u'name': name, u'zone_id': name+'.'}])

    def test_search_rr_substring(self):
        name = 'search-rr-zone.name'
        self.create_zone(name=name)
        r = self.session.get(self.url("/servers/localhost/search-data?q=rr-zone"))
        self.assert_success_json(r)
        print r.json()
        # should return zone, SOA, ns1, ns2
        self.assertEquals(len(r.json()), 1)  # FIXME test disarmed for now (should be 4)

    def test_search_rr_case_insensitive(self):
        name = 'search-rr-insenszone.name'
        self.create_zone(name=name)
        r = self.session.get(self.url("/servers/localhost/search-data?q=rr-insensZONE"))
        self.assert_success_json(r)
        print r.json()
        # should return zone, SOA, ns1, ns2
        self.assertEquals(len(r.json()), 1)  # FIXME test disarmed for now (should be 4)


@unittest.skipIf(not is_auth(), "Not applicable")
class AuthRootZone(ApiTestCase, AuthZonesHelperMixin):

    def setUp(self):
        super(AuthRootZone, self).setUp()
        # zone name is not unique, so delete the zone before each individual test.
        self.session.delete(self.url("/servers/localhost/zones/=2E"))

    def test_create_zone(self):
        payload, data = self.create_zone(name='', serial=22, soa_edit_api='')
        for k in ('id', 'url', 'name', 'masters', 'kind', 'last_check', 'notified_serial', 'serial', 'soa_edit_api', 'soa_edit', 'account'):
            self.assertIn(k, data)
            if k in payload:
                self.assertEquals(data[k], payload[k])
        self.assertEquals(data['comments'], [])
        # validate generated SOA
        self.assertEquals(
            [r['content'] for r in data['records'] if r['type'] == 'SOA'][0],
            "a.misconfigured.powerdns.server hostmaster." + payload['name'] + " " + str(payload['serial']) +
            " 10800 3600 604800 3600"
        )
        # Regression test: verify zone list works
        zonelist = self.session.get(self.url("/servers/localhost/zones")).json()
        print "zonelist:", zonelist
        self.assertIn(payload['name'], [zone['name'] for zone in zonelist])
        # Also test that fetching the zone works.
        print "id:", data['id']
        self.assertEquals(data['id'], '=2E')
        data = self.session.get(self.url("/servers/localhost/zones/" + data['id'])).json()
        print "zone (fetched):", data
        for k in ('name', 'kind'):
            self.assertIn(k, data)
            self.assertEquals(data[k], payload[k])
        self.assertEqual(data['records'][0]['name'], '')

    def test_update_zone(self):
        payload, zone = self.create_zone(name='')
        name = ''
        zone_id = '=2E'
        # update, set as Master and enable SOA-EDIT-API
        payload = {
            'kind': 'Master',
            'masters': ['192.0.2.1', '192.0.2.2'],
            'soa_edit_api': 'EPOCH',
            'soa_edit': 'EPOCH'
        }
        r = self.session.put(
            self.url("/servers/localhost/zones/" + zone_id),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        data = r.json()
        for k in payload.keys():
            self.assertIn(k, data)
            self.assertEquals(data[k], payload[k])
        # update, back to Native and empty(off)
        payload = {
            'kind': 'Native',
            'soa_edit_api': '',
            'soa_edit': ''
        }
        r = self.session.put(
            self.url("/servers/localhost/zones/" + zone_id),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        data = r.json()
        for k in payload.keys():
            self.assertIn(k, data)
            self.assertEquals(data[k], payload[k])


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
            self.url("/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        return payload, r.json()

    def test_create_auth_zone(self):
        payload, data = self.create_zone(kind='Native')
        # return values are normalized
        payload['name'] += '.'
        for k in payload.keys():
            self.assertEquals(data[k], payload[k])

    def test_create_forwarded_zone(self):
        payload, data = self.create_zone(kind='Forwarded', rd=False, servers=['8.8.8.8'])
        # return values are normalized
        payload['servers'][0] += ':53'
        payload['name'] += '.'
        for k in payload.keys():
            self.assertEquals(data[k], payload[k])

    def test_create_forwarded_rd_zone(self):
        payload, data = self.create_zone(name='google.com', kind='Forwarded', rd=True, servers=['8.8.8.8'])
        # return values are normalized
        payload['servers'][0] += ':53'
        payload['name'] += '.'
        for k in payload.keys():
            self.assertEquals(data[k], payload[k])

    def test_create_auth_zone_with_symbols(self):
        payload, data = self.create_zone(name='foo/bar.'+unique_zone_name(), kind='Native')
        # return values are normalized
        payload['name'] += '.'
        expected_id = (payload['name'].replace('/', '=2F'))
        for k in payload.keys():
            self.assertEquals(data[k], payload[k])
        self.assertEquals(data['id'], expected_id)

    def test_rename_auth_zone(self):
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
        self.assert_success_json(r)
        data = r.json()
        for k in payload.keys():
            self.assertEquals(data[k], payload[k])

    def test_zone_delete(self):
        payload, zone = self.create_zone(kind='Native')
        name = payload['name']
        r = self.session.delete(self.url("/servers/localhost/zones/" + name))
        self.assertEquals(r.status_code, 204)
        self.assertNotIn('Content-Type', r.headers)

    def test_search_rr_exact_zone(self):
        name = unique_zone_name() + '.'
        self.create_zone(name=name, kind='Native')
        r = self.session.get(self.url("/servers/localhost/search-data?q=" + name))
        self.assert_success_json(r)
        print r.json()
        self.assertEquals(r.json(), [{u'type': u'zone', u'name': name, u'zone_id': name}])

    def test_search_rr_substring(self):
        name = 'search-rr-zone.name'
        self.create_zone(name=name, kind='Native')
        r = self.session.get(self.url("/servers/localhost/search-data?q=rr-zone"))
        self.assert_success_json(r)
        print r.json()
        # should return zone, SOA
        self.assertEquals(len(r.json()), 2)
