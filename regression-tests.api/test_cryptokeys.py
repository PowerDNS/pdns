import subprocess
import json
import unittest
import os

from test_helper import ApiTestCase, is_auth, pdnsutil, unique_zone_name

@unittest.skipIf(not is_auth(), "Not applicable")
class Cryptokeys(ApiTestCase):

    def setUp(self):
        super(Cryptokeys, self).setUp()
        self.keyid = 0
        self.zone = unique_zone_name()
        self.zone_nodot = self.zone[:-1]
        payload = {
            'name': self.zone,
            'kind': 'Native',
            'nameservers': ['ns1.example.com.', 'ns2.example.com.']
        }
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assert_success_json(r)
        self.assertEquals(r.status_code, 201)

    def tearDown(self):
        super(Cryptokeys, self).tearDown()
        self.remove_zone_key(self.keyid)

    # Adding a key to self.zone using the pdnsutil command
    def add_zone_key(self, status='inactive'):
        return pdnsutil("add-zone-key", self.zone_nodot, "ksk", status)

    # Removes a key from self.zone by id using the pdnsutil command
    def remove_zone_key(self, key_id):
        return pdnsutil("remove-zone-key", self.zone_nodot, str(key_id))

    # This method tests the DELETE api call.
    def test_delete(self):
        self.keyid = self.add_zone_key()

        #checks the status code. I don't know how to test explicit that the backend fail removing a key.
        r = self.session.delete(self.url("/api/v1/servers/localhost/zones/"+self.zone+"/cryptokeys/"+self.keyid))
        self.assertEquals(r.status_code, 204)
        self.assertEquals(r.content, b"")

        # Check that the key is actually deleted
        out = pdnsutil("list-keys", self.zone)
        self.assertNotIn(self.zone, out)

    def test_get_wrong_zone(self):
        self.keyid = self.add_zone_key()
        r = self.session.get(self.url("/api/v1/servers/localhost/zones/"+self.zone+"fail/cryptokeys/"+self.keyid))
        self.assertEquals(r.status_code, 404)

    def test_delete_wrong_id(self):
        self.keyid = self.add_zone_key()
        r = self.session.delete(self.url("/api/v1/servers/localhost/zones/"+self.zone+"/cryptokeys/1234567"))
        self.assertEquals(r.status_code, 404)

    def test_delete_wrong_zone(self):
        self.keyid = self.add_zone_key()
        #checks for not covered zonename
        r = self.session.delete(self.url("/api/v1/servers/localhost/zones/"+self.zone+"fail/cryptokeys/"+self.keyid))
        self.assertEquals(r.status_code, 404)

    def test_delete_key_is_gone(self):
        self.keyid = self.add_zone_key()
        self.remove_zone_key(self.keyid)
        #checks for key is gone. Its ok even if no key had to be deleted. Or something went wrong with the backend.
        r = self.session.delete(self.url("/api/v1/servers/localhost/zones/"+self.zone+"/cryptokeys/"+self.keyid))
        self.assertEquals(r.status_code, 404)

    # Prepares the json object for Post and sends it to the server
    def add_key(self, content='', type='ksk', active='true', algo='', bits=None):
        payload = {
            'keytype': type,
            'active': active,
        }
        if algo:
            payload['algorithm'] = algo
        if bits is not None:
            payload['bits'] = bits
        if content != '':
            payload['content'] = content
        print("create key with payload:", payload)
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones/"+self.zone+"/cryptokeys"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})

        return r

    # Test POST for a positive result and delete the added key
    def post_helper(self, content='', algo='', bits=None):
        r = self.add_key(content=content, algo=algo, bits=bits)
        self.assert_success_json(r)
        self.assertEquals(r.status_code, 201)
        response = r.json()
        # Only a ksk added, so expected type is csk
        self.assertEquals(response['keytype'], 'csk')
        self.keyid = response['id']
        # Check if the key is actually added
        out = pdnsutil("list-keys", self.zone_nodot)
        self.assertIn(self.zone_nodot, out)

    # Test POST to add a key with default algorithm
    def test_post(self):
        self.post_helper()

    # Test POST to add a key with specific algorithm number
    def test_post_specific_number(self):
        self.post_helper(algo=10, bits=1024)

    # Test POST to add a key with specific name and bits
    def test_post_specific_name_bits(self):
        self.post_helper(algo="rsasha256", bits=2048)

    # Test POST to add a key with specific name
    def test_post_specific_name(self):
        self.post_helper(algo='ecdsa256')

    # Test POST to add a private key from external resource
    def test_post_content(self):
        self.post_helper(content="Private-key-format: v1.2\n"+
                                 "Algorithm: 8 (RSASHA256)\n"+
                                 "Modulus: 4GlYLGgDI7ohnP8SmEW8EBERbNRusDcg0VQda/EPVHU=\n"+
                                 "PublicExponent: AQAB\n"+
                                 "PrivateExponent: JBnuXF5zOtkjtSz3odV+Fk5UNUTTeCsiI16dkcM7TVU=\n"+
                                 "Prime1: /w7TM4118RoSEvP8+dgnCw==\n"+
                                 "Prime2: 4T2KhkYLa3w7rdK3Cb2ifw==\n"+
                                 "Exponent1: 3aeKj9Ct4JuhfWsgPBhGxQ==\n"+
                                 "Exponent2: tfh1OMPQKBdnU6iATjNR2w==\n"+
                                 "Coefficient: eVrHe/kauqOewSKndIImrg==)\n")

    def test_post_wrong_key_format(self):
        r = self.add_key(content="trollololoooolll")
        self.assert_error_json(r)
        self.assertEquals(r.status_code, 422)
        self.assertIn("Key could not be parsed. Make sure your key format is correct.",r.json()['error'])

    def test_post_wrong_keytype(self):
        r = self.add_key(type='sdfdhhgj')
        self.assert_error_json(r)
        self.assertEquals(r.status_code, 422)
        self.assertIn("Invalid keytype",r.json()['error'])

    def test_post_wrong_bits_format(self):
        r = self.add_key(bits='sdfdhhgj')
        self.assert_error_json(r)
        self.assertEquals(r.status_code, 422)
        self.assertIn("'bits' must be a positive integer value",r.json()['error'])

        r = self.add_key(bits='5.5')
        self.assert_error_json(r)
        self.assertEquals(r.status_code, 422)
        self.assertIn("'bits' must be a positive integer value",r.json()['error'])

        r = self.add_key(bits='-6')
        self.assert_error_json(r)
        self.assertEquals(r.status_code, 422)
        self.assertIn("'bits' must be a positive integer value",r.json()['error'])

    def test_post_unsupported_algorithm(self):
        r = self.add_key(algo='lkjhgf')
        self.assert_error_json(r)
        self.assertEquals(r.status_code, 422)
        self.assertIn("Unknown algorithm:",r.json()['error'])

    def test_post_forgot_bits(self):
        r = self.add_key(algo="rsasha256")
        self.assert_error_json(r)
        self.assertEquals(r.status_code, 422)
        self.assertIn("key requires the size (in bits) to be passed", r.json()['error'])

    def test_post_wrong_bit_size(self):
        r = self.add_key(algo=10, bits=30)
        self.assert_error_json(r)
        self.assertEquals(r.status_code,422)
        self.assertIn("The algorithm does not support the given bit size.", r.json()['error'])

    def test_post_can_not_guess_key_size(self):
        r = self.add_key(algo=17)
        self.assert_error_json(r)
        self.assertEquals(r.status_code,422)
        self.assertIn("Can not guess key size for algorithm", r.json()['error'])

    def test_put_activate_key(self):
        self.keyid = self.add_zone_key()

        payload = {
            'active': True
        }
        r = self.session.put(
            self.url("/api/v1/servers/localhost/zones/"+self.zone+"/cryptokeys/"+self.keyid),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEquals(r.status_code, 204)
        self.assertEquals(r.content, b"")

        # check if key is activated
        out = pdnsutil("show-zone", self.zone_nodot)
        self.assertIn("Active", out)

    def test_put_deactivate_key(self):
        self.keyid = self.add_zone_key(status='active')
        # deactivate key
        payload2 = {
            'active': False
        }

        r = self.session.put(
            self.url("/api/v1/servers/localhost/zones/"+self.zone+"/cryptokeys/"+self.keyid),
            data=json.dumps(payload2),
            headers={'content-type': 'application/json'})
        self.assertEquals(r.status_code, 204)
        self.assertEquals(r.content, b"")

        # check if key is deactivated
        out = pdnsutil("show-zone", self.zone_nodot)
        self.assertIn("Inactive", out)

    def test_put_deactivate_inactive_key(self):
        self.keyid = self.add_zone_key()

        # deactivate key
        payload = {
            'active': False
        }

        r = self.session.put(
            self.url("/api/v1/servers/localhost/zones/"+self.zone+"/cryptokeys/"+self.keyid),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEquals(r.status_code, 204)
        self.assertEquals(r.content, b"")

        # check if key is still deactivated
        out = pdnsutil("show-zone", self.zone_nodot)
        self.assertIn("Inactive", out)

    def test_put_activate_active_key(self):
        self.keyid =self.add_zone_key(status='active')

        # activate key
        payload2 = {
            'active': True
        }
        r = self.session.put(
            self.url("/api/v1/servers/localhost/zones/"+self.zone+"/cryptokeys/"+self.keyid),
            data=json.dumps(payload2),
            headers={'content-type': 'application/json'})
        self.assertEquals(r.status_code, 204)
        self.assertEquals(r.content, b"")

        # check if key is activated
        out = pdnsutil("show-zone", self.zone_nodot)
        self.assertIn("Active", out)
