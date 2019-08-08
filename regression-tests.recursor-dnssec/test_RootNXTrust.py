import dns
import requests
import socket
from recursortests import RecursorTest

class RootNXTrustRecursorTest(RecursorTest):

    def getOutgoingQueriesCount(self):
        headers = {'x-api-key': self._apiKey}
        url = 'http://127.0.0.1:' + str(self._wsPort) + '/api/v1/servers/localhost/statistics'
        r = requests.get(url, headers=headers, timeout=self._wsTimeout)
        self.assertTrue(r)
        self.assertEquals(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        for entry in content:
            if entry['name'] == 'all-outqueries':
                return int(entry['value'])

        return 0

class testRootNXTrustDisabled(RootNXTrustRecursorTest):
    _confdir = 'RootNXTrustDisabled'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'

    _config_template = """
root-nx-trust=no
webserver=yes
webserver-port=%d
webserver-address=127.0.0.1
webserver-password=%s
api-key=%s
""" % (_wsPort, _wsPassword, _apiKey)

    def testRootNXTrust(self):
        """
        Check that, with root-nx-trust disabled, we still query the root for www2.nx-example.
        after receiving a NXD from "." for nx-example. as an answer for www.nx-example.
        """

        # first query nx.example.
        before = self.getOutgoingQueriesCount()
        query = dns.message.make_query('www.nx-example.', 'A')
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        print(res)
        self.assertAuthorityHasSOA(res)

        # check that we sent one query to the root
        after = self.getOutgoingQueriesCount()
        self.assertEqual(after, before + 1)

        # then query nx2.example.
        before = after
        query = dns.message.make_query('www2.nx-example.', 'A')
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertAuthorityHasSOA(res)

        after = self.getOutgoingQueriesCount()
        self.assertEqual(after, before + 1)

class testRootNXTrustEnabled(RootNXTrustRecursorTest):
    _confdir = 'RootNXTrustEnabled'
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = 'secretpassword'
    _apiKey = 'secretapikey'

    _config_template = """
root-nx-trust=yes
webserver=yes
webserver-port=%d
webserver-address=127.0.0.1
webserver-password=%s
api-key=%s
""" % (_wsPort, _wsPassword, _apiKey)

    def testRootNXTrust(self):
        """
        Check that, with root-nx-trust enabled, we don't query the root for www2.nx-example.
        after receiving a NXD from "." for nx-example. as an answer for www.nx-example.
        """

        # first query nx.example.
        before = self.getOutgoingQueriesCount()
        query = dns.message.make_query('www.nx-example.', 'A')
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        print(res)
        self.assertAuthorityHasSOA(res)

        # check that we sent one query to the root
        after = self.getOutgoingQueriesCount()
        self.assertEqual(after, before + 1)

        # then query nx2.example.
        before = after
        query = dns.message.make_query('www2.nx-example.', 'A')
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertAuthorityHasSOA(res)

        after = self.getOutgoingQueriesCount()
        self.assertEqual(after, before)
