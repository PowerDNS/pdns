import clientsubnetoption
import cookiesoption
import dns
import os
import requests
import subprocess

from recursortests import RecursorTest

class NotifyTest(RecursorTest):

    _auth_zones = {
        '8': {'threads': 1,
              'zones': ['ROOT']}
    }

    _confdir = 'Notify'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _config_template = """
packetcache:
    disable: true
recursor:
    auth_zones:
    - zone: example
      file: configs/%s/example.zone
incoming:
    allow_notify_from: [127.0.0.1]
    allow_notify_for: ['example']
logging:
    quiet: false
    loglevel: 9
webservice:
    webserver: true
    port: %d
    address: 127.0.0.1
    password: %s
    api_key: %s
""" % (_confdir, _wsPort, _wsPassword, _apiKey)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'example.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN example.
@ 3600 IN SOA {soa}
a 3600 IN A 192.0.2.42
b 3600 IN A 192.0.2.42
c 3600 IN A 192.0.2.42
d 3600 IN A 192.0.2.42
e 3600 IN A 192.0.2.42
f 3600 IN CNAME f            ; CNAME loop: dirty trick to get a ServFail in an authzone
""".format(soa=cls._SOA))
        super(NotifyTest, cls).generateRecursorYamlConfig(confdir)

    def checkRecordCacheMetrics(self, expectedHits, expectedMisses):
        headers = {'x-api-key': self._apiKey}
        url = 'http://127.0.0.1:' + str(self._wsPort) + '/api/v1/servers/localhost/statistics'
        r = requests.get(url, headers=headers, timeout=self._wsTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        foundHits = False
        foundMisses = True
        for entry in content:
            if entry['name'] == 'cache-hits':
                foundHits = True
                self.assertEqual(int(entry['value']), expectedHits)
            elif entry['name'] == 'cache-misses':
                foundMisses = True
                self.assertEqual(int(entry['value']), expectedMisses)

        self.assertTrue(foundHits)
        self.assertTrue(foundMisses)

    def testNotify(self):
        self.waitForTCPSocket("127.0.0.1", self._wsPort)
        # first query
        qname = 'a.example.'
        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.42')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

        self.checkRecordCacheMetrics(1, 1)

        # we should get a hit over UDP this time
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkRecordCacheMetrics(2, 1)

        # we should get a hit over TCP this time
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkRecordCacheMetrics(3, 1)

        notify = dns.message.make_query('example', 'SOA', want_dnssec=False)
        notify.set_opcode(4) # notify
        notifyexpected = dns.rrset.from_text('example.', 0, dns.rdataclass.IN, 'SOA')
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(notify)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(res.opcode(), 4)
            print(res)
            self.assertEqual(res.question[0].to_text(), 'example. IN SOA')

        self.checkRecordCacheMetrics(3, 1)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

        self.checkRecordCacheMetrics(4, 2)

class NotifyNameNotAllowedTest(RecursorTest):

    _auth_zones = {
        '8': {'threads': 1,
              'zones': ['ROOT']}
    }

    _confdir = 'NotifyNameNotAllowed'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _config_template = """
packetcache:
    disable: true
recursor:
    auth_zones:
    - zone: example
      file: configs/%s/example.zone
incoming:
    allow_notify_from: [127.0.0.1]
    allow_notify_for: []
logging:
    quiet: false
    loglevel: 9
webservice:
    webserver: true
    port: %d
    address: 127.0.0.1
    password: %s
    api_key: %s
""" % (_confdir, _wsPort, _wsPassword, _apiKey)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'example.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN example.
@ 3600 IN SOA {soa}
a 3600 IN A 192.0.2.42
b 3600 IN A 192.0.2.42
c 3600 IN A 192.0.2.42
d 3600 IN A 192.0.2.42
e 3600 IN A 192.0.2.42
f 3600 IN CNAME f            ; CNAME loop: dirty trick to get a ServFail in an authzone
""".format(soa=cls._SOA))
        super(NotifyNameNotAllowedTest, cls).generateRecursorYamlConfig(confdir)

    def checkRecordCacheMetrics(self, expectedHits, expectedMisses):
        headers = {'x-api-key': self._apiKey}
        url = 'http://127.0.0.1:' + str(self._wsPort) + '/api/v1/servers/localhost/statistics'
        r = requests.get(url, headers=headers, timeout=self._wsTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        foundHits = False
        foundMisses = True
        for entry in content:
            if entry['name'] == 'cache-hits':
                foundHits = True
                self.assertEqual(int(entry['value']), expectedHits)
            elif entry['name'] == 'cache-misses':
                foundMisses = True
                self.assertEqual(int(entry['value']), expectedMisses)

        self.assertTrue(foundHits)
        self.assertTrue(foundMisses)

    def testNotify(self):
        self.waitForTCPSocket("127.0.0.1", self._wsPort)
        # first query
        qname = 'a.example.'
        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.42')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

        self.checkRecordCacheMetrics(1, 1)

        # we should get a hit over UDP this time
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkRecordCacheMetrics(2, 1)

        # we should get a hit over TCP this time
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkRecordCacheMetrics(3, 1)

        notify = dns.message.make_query('example', 'SOA', want_dnssec=False)
        notify.set_opcode(4) # notify
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(notify)
            self.assertEqual(res, None);

        self.checkRecordCacheMetrics(3, 1)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

        self.checkRecordCacheMetrics(5, 1)

class NotifyNetNotAllowedTest(RecursorTest):

    _auth_zones = {
        '8': {'threads': 1,
              'zones': ['ROOT']}
    }

    _confdir = 'NotifyNetNotAllowed'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'
    _config_template = """
packetcache:
    disable: true
recursor:
    auth_zones:
    - zone: example
      file: configs/%s/example.zone
incoming:
    allow_notify_from: []
    allow_notify_for: [example]
logging:
    quiet: false
    loglevel: 9
webservice:
    webserver: true
    port: %d
    address: 127.0.0.1
    password: %s
    api_key: %s
""" % (_confdir, _wsPort, _wsPassword, _apiKey)

    @classmethod
    def generateRecursorConfig(cls, confdir):
        authzonepath = os.path.join(confdir, 'example.zone')
        with open(authzonepath, 'w') as authzone:
            authzone.write("""$ORIGIN example.
@ 3600 IN SOA {soa}
a 3600 IN A 192.0.2.42
b 3600 IN A 192.0.2.42
c 3600 IN A 192.0.2.42
d 3600 IN A 192.0.2.42
e 3600 IN A 192.0.2.42
f 3600 IN CNAME f            ; CNAME loop: dirty trick to get a ServFail in an authzone
""".format(soa=cls._SOA))
        super(NotifyNetNotAllowedTest, cls).generateRecursorYamlConfig(confdir)

    def checkRecordCacheMetrics(self, expectedHits, expectedMisses):
        headers = {'x-api-key': self._apiKey}
        url = 'http://127.0.0.1:' + str(self._wsPort) + '/api/v1/servers/localhost/statistics'
        r = requests.get(url, headers=headers, timeout=self._wsTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        foundHits = False
        foundMisses = True
        for entry in content:
            if entry['name'] == 'cache-hits':
                foundHits = True
                self.assertEqual(int(entry['value']), expectedHits)
            elif entry['name'] == 'cache-misses':
                foundMisses = True
                self.assertEqual(int(entry['value']), expectedMisses)

        self.assertTrue(foundHits)
        self.assertTrue(foundMisses)

    def testNotify(self):
        self.waitForTCPSocket("127.0.0.1", self._wsPort)
        # first query
        qname = 'a.example.'
        query = dns.message.make_query(qname, 'A', want_dnssec=True)
        expected = dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '192.0.2.42')

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

        self.checkRecordCacheMetrics(1, 1)

        # we should get a hit over UDP this time
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkRecordCacheMetrics(2, 1)

        # we should get a hit over TCP this time
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)
        self.checkRecordCacheMetrics(3, 1)

        notify = dns.message.make_query('example', 'SOA', want_dnssec=False)
        notify.set_opcode(4) # notify
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(notify)
            self.assertEqual(res, None);

        self.checkRecordCacheMetrics(3, 1)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            res = sender(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

        self.checkRecordCacheMetrics(5, 1)
