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
            {"country": {"iso_code": "US"}, "result_ip": "6.7.8.9"},
        )
    writer.to_db_file(fname)


@unittest.skipIf("SKIP_MMDB_TESTS" in os.environ, "MMDB tests are disabled")
class MMDBTest(DNSDistTest):
    _mmdbFileName = "/tmp/test-mmdb-db"
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    mmdb = openMMDB('%s')
    kvs = newMMDBKVStore(mmdb, { "country", "iso_code" })

    function lua_mmdb_query(dq)
    	local mmdbData = mmdb:query({"result_ip"}, dq.remoteaddr)
        if mmdbData == nil then
            return DNSAction.None
        end
        return DNSAction.Spoof, mmdbData
    end

    -- does a lookup in the MMDB database using the source IP as key, and store the result into the 'kvs-sourceip-result' tag
    addAction(RegexRule('regular.*'), KeyValueStoreLookupAction(kvs, KeyValueLookupKeySourceIP(), 'kvs-sourceip-result'))

    -- if the value of the 'kvs-sourceip-result' is set to 'US', spoof a response
    addAction(TagRule('kvs-sourceip-result', 'US'), SpoofAction('5.6.7.8'))

    -- does a lookup and directly spoofs if found, using data from MMDB
    addAction(RegexRule('lua.*'), LuaAction(lua_mmdb_query))

    -- otherwise, spoof a different response
    addAction(RegexRule('regular.*'), SpoofAction('9.9.9.9'))
    addAction(RegexRule('lua.*'), SpoofAction('9.9.9.10'))
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
        name = "regular.source-ip.mmdb.tests.powerdns.com."
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

    def testMMDBLua(self):
        """
        MMDB: Using MMDB in Lua
        """
        name = "lua.source-ip.mmdb.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "6.7.8.9")
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
        name = "regular.source-ip.mmdb.tests.powerdns.com."
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

    def testMMDBLua(self):
        """
        MMDB: Using MMDB in Lua
        """
        name = "lua.source-ip.mmdb.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "9.9.9.10")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


@unittest.skipIf("SKIP_MMDB_TESTS" in os.environ, "MMDB tests are disabled")
class MMDBYamlTest(DNSDistTest):
    _mmdbFileName = "/tmp/test-mmdb-db"
    _yaml_config_template = """---
binds:
  - listen_address: "127.0.0.1:%d"
    reuseport: true
    protocol: Do53
    threads: 2

mmdbs:
  - name: test-mmdb
    file_name: %s
    mmap: true

key_value_stores:
  mmdb:
    - name: MMDBCountryKV
      mmdb: test-mmdb
      query_params:
        - country
        - iso_code
  lookup_keys:
    source_ip_keys:
      - name: source_ip

query_rules:
  - name: MMDB Country rule
    selector:
      type: Regex
      expression: regular.*
    action:
      type: KeyValueStoreLookup
      kvs_name: MMDBCountryKV
      lookup_key_name: source_ip
      destination_tag: kvs-source-ip-result

  - name: Spoof US rule
    selector:
      type: Tag
      tag: kvs-source-ip-result
      value: US
    action:
      type: Spoof
      ips:
        - 5.6.7.8

  - name: MMDB Lua lookup rule
    selector:
      type: Regex
      expression: lua.*
    action:
      type: Lua
      function_code: |
        function lua_mmdb_query(dq)
            local mmdb = getObjectFromYAMLConfiguration("test-mmdb")
            local mmdbData = mmdb:query({"result_ip"}, dq.remoteaddr)
            if mmdbData == nil then
                return DNSAction.None
            end
            return DNSAction.Spoof, mmdbData
        end
        return lua_mmdb_query

  - name: Spoof regular missed rule
    selector:
      type: Regex
      expression: regular.*
    action:
      type: Spoof
      ips:
        - 9.9.9.9

  - name: Spoof Lua missed rule
    selector:
      type: Regex
      expression: lua.*
    action:
      type: Spoof
      ips:
        - 9.9.9.10
"""
    _yaml_config_params = ["_testServerPort", "_mmdbFileName"]


class TestMMDBYamlSimple(MMDBYamlTest):
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
        name = "regular.source-ip.mmdb.tests.powerdns.com."
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

    def testMMDBLua(self):
        """
        MMDB: Using MMDB in Lua
        """
        name = "lua.source-ip.mmdb.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "6.7.8.9")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


class TestMMDBYamlMissing(MMDBYamlTest):
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
        name = "regular.source-ip.mmdb.tests.powerdns.com."
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

    def testMMDBLua(self):
        """
        MMDB: Using MMDB in Lua
        """
        name = "lua.source-ip.mmdb.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "9.9.9.10")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)
