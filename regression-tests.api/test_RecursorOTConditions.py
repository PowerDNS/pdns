import json
import unittest
from test_helper import ApiTestCase, is_recursor


@unittest.skipIf(not is_recursor(), "Only applicable to recursors")
class RecursorOT(ApiTestCase):

    def assert_in_json_error(self, expected, json):
        error = json['error']
        if expected not in error:
            found = False
            if 'errors' in json:
                errors = json['errors']
                for item in errors:
                    if expected in item:
                        found = True
                assert found, "%r not found in %r" % (expected, errors)
            assert found, "%r not found in %r" % (expected, error)

    def test_basic_ot_conditions(self):
        # initial list is empty
        r = self.session.get(
            self.url("/api/v1/servers/localhost/ottraceconditions"),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), [])

        # nonexistent condition
        r = self.session.get(
            self.url("/api/v1/servers/localhost/ottraceconditions/1.2.3.4/32"),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assert_in_json_error('Could not find otcondition', r.json())

        # malformed netmask
        r = self.session.get(
            self.url("/api/v1/servers/localhost/ottraceconditions/1.2.3/32"),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assert_in_json_error('Could not parse netmask', r.json())

        # deleting non-existent netmask
        r = self.session.delete(
            self.url("/api/v1/servers/localhost/ottraceconditions/1.2.3.4/32"),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assert_in_json_error('Could not find otcondition', r.json())

        # creating, most simple case
        payload = {
            "acl": "1.2.3.4"
        }
        r = self.session.post(
            self.url("/api/v1/servers/localhost/ottraceconditions"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 201)
        data = r.json()
        self.assertIn('acl', data)
        self.assertIn('edns_option_required', data)
        self.assertIn('traceid_only', data)
        self.assertIn('type', data)
        self.assertEqual(data['acl'], '1.2.3.4/32')
        self.assertEqual(data['type'], 'OpenTelemetryTraceCondition')
        self.assertFalse(data['edns_option_required'])
        self.assertFalse(data['traceid_only'])

        # creating, error because duplicate
        payload = {
            "acl": "1.2.3.4"
        }
        r = self.session.post(
            self.url("/api/v1/servers/localhost/ottraceconditions"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assert_in_json_error('OTCondition already exists', r.json())

        # list has one element
        r = self.session.get(
            self.url("/api/v1/servers/localhost/ottraceconditions"),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()), 1)

        # creating, more general case
        payload = {
            "acl": "1.2.3.0/24"
        }
        r = self.session.post(
            self.url("/api/v1/servers/localhost/ottraceconditions"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 201)
        data = r.json()
        self.assertIn('acl', data)
        self.assertIn('edns_option_required', data)
        self.assertIn('traceid_only', data)
        self.assertEqual(data['acl'], '1.2.3.0/24')
        self.assertFalse(data['edns_option_required'])
        self.assertFalse(data['traceid_only'])

        # list has two elements
        r = self.session.get(
            self.url("/api/v1/servers/localhost/ottraceconditions"),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()), 2)

        # querying by more specific key than /24
        r = self.session.get(
            self.url("/api/v1/servers/localhost/ottraceconditions/1.2.3.4/31"),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 422)
        self.assert_in_json_error('Could not find otcondition', r.json())

        # deleting specific netmask
        r = self.session.delete(
            self.url("/api/v1/servers/localhost/ottraceconditions/1.2.3.4/32"),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 204)

        # list has one elements
        r = self.session.get(
            self.url("/api/v1/servers/localhost/ottraceconditions"),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()), 1)

        # creating, all fields filled in
        payload = {
            "acl": "::/0",
            "qid": 99,
            "qnames": ["foo.bar", "nl", "com"],
            "qtypes": ["AAAA", "TXT"],
            "traceid_only": True,
            "edns_option_required": True
        }
        r = self.session.post(
            self.url("/api/v1/servers/localhost/ottraceconditions"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 201)
        data = r.json()
        self.assertIn('acl', data)
        self.assertIn('qid', data)
        self.assertIn('qnames', data)
        self.assertIn('qtypes', data)
        self.assertIn('traceid_only', data)
        self.assertIn('edns_option_required', data)
        self.assertIn('type', data)
        self.assertEqual(data['acl'], '::/0')
        self.assertEqual(data['qid'], 99)
        self.assertEqual(len(data['qnames']), 3)
        self.assertEqual(len(data['qtypes']), 2)
        self.assertEqual(data['type'], 'OpenTelemetryTraceCondition')
        self.assertTrue(data['edns_option_required'])
        self.assertTrue(data['traceid_only'])

        # and GET the newly created one in a separate call
        r = self.session.get(
            self.url("/api/v1/servers/localhost/ottraceconditions/::/0"),
            headers={'content-type': 'application/json'})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn('acl', data)
        self.assertIn('qid', data)
        self.assertIn('qnames', data)
        self.assertIn('qtypes', data)
        self.assertIn('traceid_only', data)
        self.assertIn('edns_option_required', data)
        self.assertIn('type', data)
        self.assertEqual(data['acl'], '::/0')
        self.assertEqual(data['qid'], 99)
        self.assertEqual(len(data['qnames']), 3)
        self.assertEqual(len(data['qtypes']), 2)
        self.assertEqual(data['type'], 'OpenTelemetryTraceCondition')
        self.assertTrue(data['edns_option_required'])
        self.assertTrue(data['traceid_only'])
