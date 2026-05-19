#!/usr/bin/env python
import os
import socket
import time
import unittest

import dns
from mmdb_writer import MMDBWriter
from netaddr import IPNetwork, IPSet

from dnsdisttests import DNSDistTest


def writeMMDB(fname, empty=False):
    writer = MMDBWriter()
    if not empty:
        writer.insert_network(
            IPSet(IPNetwork("127.0.0.0/24")),
            {"country": {"iso_code": "US"}},
        )
    writer.to_db_file(fname)


@unittest.skipIf("SKIP_MMDB_TESTS" in os.environ, "MMDB tests are disabled")
class MMDBTest(DNSDistTest):
    _mmdbFileName = "/tmp/test-mmdb-db"
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    mmdb = openMMDB('%s')
    kvs = newMMDBKVStore(mmdb, { "country", "iso_code" })

    -- does a lookup in the MMDB database using the source IP as key, and store the result into the 'kvs-sourceip-result' tag
    addAction(AllRule(), KeyValueStoreLookupAction(kvs, KeyValueLookupKeySourceIP(), 'kvs-sourceip-result'))

    -- if the value of the 'kvs-sourceip-result' is set to 'US', spoof a response
    addAction(TagRule('kvs-sourceip-result', 'US'), SpoofAction('5.6.7.8'))

    -- otherwise, spoof a different response
    addAction(AllRule(), SpoofAction('9.9.9.9'))
    """
    _config_params = ["_testServerPort", "_mmdbFileName"]


class TestMMDBSimple(MMDBTest):
    @classmethod
    def setUpMMDB(cls):
        writeMMDB(cls._mmdbFileName)

    @classmethod
    def setUpClass(cls):

        cls.setUpMMDB()
        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

        print("Launching tests..")

    def testMMDBSource(self):
        """
        MMDB: Match on source address
        """
        name = "source-ip.mmdb.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "5.6.7.8")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


class TestMMDBMissing(MMDBTest):
    @classmethod
    def setUpMMDB(cls):
        writeMMDB(cls._mmdbFileName, empty=True)

    @classmethod
    def setUpClass(cls):

        cls.setUpMMDB()
        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

        print("Launching tests..")

    def testMMDBSource(self):
        """
        MMDB: Match on source address
        """
        name = "source-ip.mmdb.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "9.9.9.9")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)
