import subprocess
import json
import unittest

from test_helper import ApiTestCase, is_auth

@unittest.skipIf(not is_auth(), "Not applicable")
class Cryptokeys(ApiTestCase):
    zone = "cryptokeyzone"
    def setUp(self):
        super(Cryptokeys, self).setUp()
        try:
            subprocess.check_output(["../pdns/pdnsutil", "--config-dir=.", "create-zone", Cryptokeys.zone])
        except subprocess.CalledProcessError as e:
            self.fail("Couldn't create zone: "+e.output)


    def tearDown(self):
        super(Cryptokeys,self).tearDown()
        try:
            subprocess.check_output(["../pdns/pdnsutil", "--config-dir=.", "delete-zone", Cryptokeys.zone])
        except subprocess.CalledProcessError as e:
            self.fail("Couldn't delete zone: "+e.output)


    # This methode test the DELETE api call. Sometimes 200 or 422 are valid return codes,
    # because it "could" happen that the backend crashes during the test or the remove function returns false.
    # In this case 422 is correct. I don't know how to force false backend behavior. So i assume that the backend
    # works correct.
    def test_delete(self):
        try:
            keyid = subprocess.check_output(["../pdns/pdnsutil", "--config-dir=.", "add-zone-key", Cryptokeys.zone, "ksk"])
        except subprocess.CalledProcessError as e:
            self.fail("pdnsutil add-zone-key failed: "+e.output)

        #checks the status code. I don't know how to test explicit that the backend fail removing a key.
        r = self.session.delete(self.url("/api/v1/servers/localhost/zones/"+Cryptokeys.zone+"/cryptokeys/"+keyid))
        self.assertTrue(r.status_code == 200 or r.status_code == 422)

        # Check that the key is actually deleted
        try:
            out = subprocess.check_output(["../pdns/pdnsutil", "--config-dir=.", "list-keys", Cryptokeys.zone])
            self.assertFalse(Cryptokeys.zone in out)
        except subprocess.CalledProcessError as e:
            self.fail("pdnsutil list-keys failed: " + e.output)

        #checks for not covered zonename
        r = self.session.delete(self.url("/api/v1/servers/localhost/zones/"+Cryptokeys.zone+"fail/cryptokeys/"+keyid))
        self.assertEquals(r.status_code, 400)

        #checks for key is gone. Its ok even if no key had to be deleted. Or something went wrong with the backend.
        r = self.session.delete(self.url("/api/v1/servers/localhost/zones/"+Cryptokeys.zone+"/cryptokeys/"+keyid))
        self.assertTrue(r.status_code == 200 or r.status_code == 422)

    # Prepares the json object for Post and sends it to the server
    def add_key(self, content='', type='ksk', active='true' , algo='', bits=0):
        if algo == '':
            payload = {
                'keytype': type,
                'active' : active
            }
        else:
            payload = {
                'keytype': type,
                'active' : active,
                'algo' : algo
            }
        if bits > 0:
            payload['bits'] = bits
        if content != '':
            payload['content'] = content
        r = self.session.post(
            self.url("/api/v1/servers/localhost/zones/"+Cryptokeys.zone+"/cryptokeys"),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        return r

    # Removes a key by id using the pdnsutil command
    def remove_key(self, key_id):
        try:
            subprocess.check_output(["../pdns/pdnsutil", "--config-dir=.", "remove-zone-key", Cryptokeys.zone, str(key_id)])
        except subprocess.CalledProcessError as e:
            self.fail("pdnsutil remove-zone-key failed: "+e.output)

    # Tests POST for a positiv result and deletes the added key
    def post_helper(self,content='', algo='', bits=0):
        r = self.add_key(content=content, algo=algo, bits=bits)
        self.assert_success_json(r)
        self.assertEquals(r.status_code, 201)
        response = r.json()
        # Only a ksk added, so expected type is csk
        self.assertEquals(response['keytype'], 'csk')
        key_id = response['id']
        # Check if the key is actually added
        try:
            out = subprocess.check_output(["../pdns/pdnsutil", "--config-dir=.", "list-keys", Cryptokeys.zone])
            self.assertTrue(Cryptokeys.zone in out)
        except subprocess.CalledProcessError as e:
            self.fail("pdnsutil list-keys failed: " + e.output)

        # Remove it for further testing
        self.remove_key(key_id)

    def test_post(self):
        # Test add a key with default algorithm
        self.post_helper()

        # Test add a key with specific number
        self.post_helper(algo=10, bits=512)

        # Test add a key with specific name and bits
        self.post_helper(algo="rsasha256", bits=256)

        # Test add a key with specific name
        self.post_helper(algo='ecdsa256')

        # Test add a private key from extern resource
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

        # Test wrong key format
        r = self.add_key(content="trollololoooolll")
        self.assert_error_json(r)
        self.assertEquals(r.status_code, 422)
        self.assertIn("Wrong key format!",r.json()['error'])

        # Test wrong keytype
        r = self.add_key(type='sdfdhhgj')
        self.assert_error_json(r)
        self.assertEquals(r.status_code, 422)
        self.assertIn("Invalid keytype",r.json()['error'])

        #Test unsupported algorithem
        r = self.add_key(algo='lkjhgf')
        self.assert_error_json(r)
        self.assertEquals(r.status_code, 422)
        self.assertIn("Unknown algorithm:",r.json()['error'])

        #Test add a key and forgot bits
        r = self.add_key(algo="rsasha256")
        self.assert_error_json(r)
        self.assertEquals(r.status_code, 422)
        self.assertIn("key requires the size (in bits) to be passed", r.json()['error'])

        #Test wrong bit size
        r = self.add_key(algo=10, bits=30)
        self.assert_error_json(r)
        self.assertEquals(r.status_code,422)
        self.assertIn("Wrong bit size!", r.json()['error'])

        #Test can't guess key size
        r = self.add_key(algo=15)
        self.assert_error_json(r)
        self.assertEquals(r.status_code,422)
        self.assertIn("Can't guess key size for algorithm", r.json()['error'])

    def test_put_activate_deactivate_key(self):

        #create key
        try:
            keyid = subprocess.check_output(["../pdns/pdnsutil", "--config-dir=.", "add-zone-key", Cryptokeys.zone, "ksk"])
        except subprocess.CalledProcessError as e:
            self.fail("pdnsutil add-zone-key failed: "+e.output)

        # activate key
        payload = {
            'active': True
        }
        o = self.session.put(
            self.url("/api/v1/servers/localhost/zones/"+Cryptokeys.zone+"/cryptokeys/"+keyid),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEquals(o.status_code, 200)

        # check if key is activated
        try:
            out = subprocess.check_output(["../pdns/pdnsutil", "--config-dir=.", "show-zone", Cryptokeys.zone])
            self.assertTrue("Active" in out)
        except subprocess.CalledProcessError as e:
            self.fail("pdnsutil show-zone failed: " + e.output)

        # deactivate key
        payload2 = {
            'active': False
        }
        q = self.session.put(
            self.url("/api/v1/servers/localhost/zones/"+Cryptokeys.zone+"/cryptokeys/"+keyid),
            data=json.dumps(payload2),
            headers={'content-type': 'application/json'})
        self.assertEquals(q.status_code, 200)
        self.assert_success_json(q)

        # check if key is deactivated
        try:
            out = subprocess.check_output(["../pdns/pdnsutil", "--config-dir=.", "show-zone", Cryptokeys.zone])
            self.assertTrue("Inactive" in out)
        except subprocess.CalledProcessError as e:
            self.fail("pdnsutil show-zone failed: " + e.output)

        # Remove it for further testing
        try:
            subprocess.check_output(["../pdns/pdnsutil", "--config-dir=.", "remove-zone-key", Cryptokeys.zone, str(keyid)])
        except subprocess.CalledProcessError as e:
            self.fail("pdnsutil remove-zone-key failed: "+e.output)

    def test_put_deactivate_deactivated_activate_activated_key(self):

        #create key
        try:
            keyid = subprocess.check_output(["../pdns/pdnsutil", "--config-dir=.", "add-zone-key", Cryptokeys.zone, "ksk"])
        except subprocess.CalledProcessError as e:
            self.fail("pdnsutil add-zone-key failed: "+e.output)

        # deactivate key
        payload = {
            'active': False
        }
        q = self.session.put(
            self.url("/api/v1/servers/localhost/zones/"+Cryptokeys.zone+"/cryptokeys/"+keyid),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'})
        self.assertEquals(q.status_code, 200)
        self.assert_success_json(q)

        # check if key is still deactivated
        try:
            out = subprocess.check_output(["../pdns/pdnsutil", "--config-dir=.", "show-zone", Cryptokeys.zone])
            self.assertTrue("Inactive" in out)
        except subprocess.CalledProcessError as e:
            self.fail("pdnsutil show-zone failed: " + e.output)

        # activate key
        payload2 = {
            'active': True
        }
        o = self.session.put(
            self.url("/api/v1/servers/localhost/zones/"+Cryptokeys.zone+"/cryptokeys/"+keyid),
            data=json.dumps(payload2),
            headers={'content-type': 'application/json'})
        self.assertEquals(o.status_code, 200)

        # check if key is activated
        try:
            out = subprocess.check_output(["../pdns/pdnsutil", "--config-dir=.", "show-zone", Cryptokeys.zone])
            self.assertTrue("Active" in out)
        except subprocess.CalledProcessError as e:
            self.fail("pdnsutil show-zone failed: " + e.output)

        #activate again
        z = self.session.put(
            self.url("/api/v1/servers/localhost/zones/"+Cryptokeys.zone+"/cryptokeys/"+keyid),
            data=json.dumps(payload2),
            headers={'content-type': 'application/json'})
        self.assertEquals(z.status_code, 200)

        # check if key is still activated
        try:
            out = subprocess.check_output(["../pdns/pdnsutil", "--config-dir=.", "show-zone", Cryptokeys.zone])
            self.assertTrue("Active" in out)
        except subprocess.CalledProcessError as e:
            self.fail("pdnsutil show-zone failed: " + e.output)