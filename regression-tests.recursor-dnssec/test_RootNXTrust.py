import dns
import requests
import socket
import time
import extendederrors

from recursortests import RecursorTest


class RootNXTrustRecursorTest(RecursorTest):
    def getOutgoingQueriesCount(self):
        headers = {"x-api-key": self._apiKey}
        url = "http://127.0.0.1:" + str(self._wsPort) + "/api/v1/servers/localhost/statistics"
        r = requests.get(url, headers=headers, timeout=self._wsTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        for entry in content:
            if entry["name"] == "all-outqueries":
                return int(entry["value"])

        return 0

    # Recursor can still be busy resolving root hints, so wait a bit until
    # getOutgoingQueriesCount() stabilizes.
    # Code below is inherently racey, but better than a fixed sleep
    def waitForOutgoingToStabilize(self):
        for count in range(20):
            outgoing1 = self.getOutgoingQueriesCount()
            time.sleep(0.1)
            outgoing2 = self.getOutgoingQueriesCount()
            if outgoing1 == outgoing2:
                break


class RootNXTrustDisabledTest(RootNXTrustRecursorTest):
    _confdir = "RootNXTrustDisabled"
    _auth_zones = RecursorTest._default_auth_zones
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = "secretpassword"
    _apiKey = "secretapikey"

    _config_template = """
root-nx-trust=no
qname-minimization=no
webserver=yes
webserver-port=%d
webserver-address=127.0.0.1
webserver-password=%s
api-key=%s
devonly-regression-test-mode
extended-resolution-errors
""" % (_wsPort, _wsPassword, _apiKey)

    def testRootNXTrust(self):
        """
        Check that, with root-nx-trust disabled, we still query the root for www2.nx-example.
        after receiving a NXD from "." for nx-example. as an answer for www.nx-example.
        """

        self.waitForTCPSocket("127.0.0.1", self._wsPort)
        self.waitForOutgoingToStabilize()
        # First query nx.example.
        before = self.getOutgoingQueriesCount()
        query = dns.message.make_query("www.nx-example.", "A")
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        print(res)
        self.assertAuthorityHasSOA(res)

        # check that we sent one query to the root
        after = self.getOutgoingQueriesCount()
        self.assertEqual(after, before + 1)

        # then query nx2.example.
        before = after
        query = dns.message.make_query("www2.nx-example.", "A", use_edns=True)
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertAuthorityHasSOA(res)

        after = self.getOutgoingQueriesCount()
        self.assertEqual(after, before + 1)
        self.assertEqual(res.edns, 0)
        self.assertEqual(len(res.options), 0)


class RootNXTrustEnabledTest(RootNXTrustRecursorTest):
    _confdir = "RootNXTrustEnabled"
    _auth_zones = RecursorTest._default_auth_zones
    _wsPort = 8042
    _wsTimeout = 2
    _wsPassword = "secretpassword"
    _apiKey = "secretapikey"

    _config_template = """
root-nx-trust=yes
webserver=yes
webserver-port=%d
webserver-address=127.0.0.1
webserver-password=%s
api-key=%s
devonly-regression-test-mode
extended-resolution-errors
""" % (_wsPort, _wsPassword, _apiKey)

    def testRootNXTrust(self):
        """
        Check that, with root-nx-trust enabled, we don't query the root for www2.nx-example.
        after receiving a NXD from "." for nx-example. as an answer for www.nx-example.
        """

        self.waitForTCPSocket("127.0.0.1", self._wsPort)
        self.waitForOutgoingToStabilize()
        # first query nx.example.
        before = self.getOutgoingQueriesCount()
        query = dns.message.make_query("www.nx-example.", "A")
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        print(res)
        self.assertAuthorityHasSOA(res)

        # check that we sent one query to the root
        after = self.getOutgoingQueriesCount()
        self.assertEqual(after, before + 1)

        # then query nx2.example.
        before = after
        query = dns.message.make_query("www2.nx-example.", "A", use_edns=True)
        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
        self.assertAuthorityHasSOA(res)

        after = self.getOutgoingQueriesCount()
        self.assertEqual(after, before)
        self.assertEqual(res.edns, 0)
        self.assertEqual(len(res.options), 1)
        self.assertEqual(res.options[0].otype, 15)
        self.assertEqual(res.options[0], extendederrors.ExtendedErrorOption(29, b"Result synthesized by root-nx-trust"))
