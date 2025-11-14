#!/usr/bin/env python
import unittest
import dns
import lmdb
import os
import socket
import struct

from dnsdisttests import DNSDistTest


@unittest.skipIf("SKIP_LMDB_TESTS" in os.environ, "LMDB tests are disabled")
class TestLMDB(DNSDistTest):
    _lmdbFileName = "/tmp/test-lmdb-db"
    _lmdbDBName = "db-name"
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    kvs = newLMDBKVStore('%s', '%s')
    kvs:reload()
    kvs:lookup('does not exist, just testing that the lookup binding exists')
    kvs:lookupSuffix(newDNSName('dummy'))

    -- KVS lookups follow
    -- if the qname is 'kvs-rule.lmdb.tests.powerdns.com.', does a lookup in the LMDB database using the qname as key, and spoof an answer if it matches
    addAction(AndRule{QNameRule('kvs-rule.lmdb.tests.powerdns.com.'), KeyValueStoreLookupRule(kvs, KeyValueLookupKeyQName(false))}, SpoofAction('13.14.15.16'))

    -- does a lookup in the LMDB database using the source IP as key, and store the result into the 'kvs-sourceip-result' tag
    addAction(AllRule(), KeyValueStoreLookupAction(kvs, KeyValueLookupKeySourceIP(), 'kvs-sourceip-result'))

    -- does a lookup in the LMDB database using the qname in _plain text_ format as key, and store the result into the 'kvs-plain-text-result' tag
    addAction(AllRule(), KeyValueStoreLookupAction(kvs, KeyValueLookupKeyQName(false), 'kvs-plain-text-result'))
    -- if the value of the 'kvs-plain-text-result' is set to 'this is the value of the plaintext tag', spoof a response
    addAction(TagRule('kvs-plain-text-result', 'this is the value of the plaintext tag'), SpoofAction('9.10.11.12'))

    -- does a lookup in the LMDB database using the qname in wire format as key, and store the result into the 'kvs-qname-result' tag
    addAction(AllRule(), KeyValueStoreLookupAction(kvs, KeyValueLookupKeyQName(), 'kvs-qname-result'))

    -- if the value of the 'kvs-qname-result' tag is set to 'this is the value of the qname tag'
    -- does a lookup in the LMDB database using the value of the 'kvs-qname-result' tag as key, and store the result into the 'kvs-tag-result' tag
    addAction(TagRule('kvs-qname-result', 'this is the value of the qname tag'), KeyValueStoreLookupAction(kvs, KeyValueLookupKeyTag('kvs-qname-result'), 'kvs-tag-result'))

    -- does a lookup in the LMDB database using the source IP as key, and store the result into the 'kvs-sourceip-result' tag
    addAction(AllRule(), KeyValueStoreLookupAction(kvs, KeyValueLookupKeySourceIP(), 'kvs-sourceip-result'))

    -- does a lookup in the LMDB database using the qname in wire format as key, but this time does a suffix lookup, and store the result into the 'kvs-suffix-result' tag
    addAction(AllRule(), KeyValueStoreLookupAction(kvs, KeyValueLookupKeySuffix(), 'kvs-suffix-result'))

    -- Now we take action based on the result of the lookups
    -- if the value of the 'kvs-tag-result' is set to 'this is the value of the second tag', spoof a response
    addAction(TagRule('kvs-tag-result', 'this is the value of the second tag'), SpoofAction('1.2.3.4'))

    -- if the value of the 'kvs-suffix-result' is set to 'this is the value of the suffix tag', spoof a response
    addAction(TagRule('kvs-suffix-result', 'this is the value of the suffix tag'), SpoofAction('42.42.42.42'))

    -- if the value of the 'kvs-sourceip-result' is set to 'this is the value of the source address tag', spoof a response
    addAction(TagRule('kvs-sourceip-result', 'this is the value of the source address tag'), SpoofAction('5.6.7.8'))

    -- otherwise, spoof a different response
    addAction(AllRule(), SpoofAction('9.9.9.9'))
    """
    _config_params = ["_testServerPort", "_lmdbFileName", "_lmdbDBName"]

    @classmethod
    def setUpLMDB(cls):
        env = lmdb.open(cls._lmdbFileName, map_size=1014 * 1024, max_dbs=1024, subdir=False)
        db = env.open_db(key=cls._lmdbDBName.encode())
        with env.begin(db=db, write=True) as txn:
            txn.put(b"\x05qname\x04lmdb\x05tests\x08powerdns\x03com\x00", b"this is the value of the qname tag")
            txn.put(socket.inet_aton("127.0.0.1"), b"this is the value of the source address tag")
            txn.put(b"this is the value of the qname tag", b"this is the value of the second tag")
            txn.put(b"\x06suffix\x04lmdb\x05tests\x08powerdns\x03com\x00", b"this is the value of the suffix tag")
            txn.put(b"qname-plaintext.lmdb.tests.powerdns.com", b"this is the value of the plaintext tag")
            txn.put(b"kvs-rule.lmdb.tests.powerdns.com", b"the value does not matter")

    @classmethod
    def setUpClass(cls):
        cls.setUpLMDB()
        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

        print("Launching tests..")

    def testLMDBSource(self):
        """
        LMDB: Match on source address
        """
        name = "source-ip.lmdb.tests.powerdns.com."
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

    def testLMDBQNamePlusTagLookup(self):
        """
        LMDB: Match on qname then does a second lookup using the value of the first lookup
        """
        name = "qname.lmdb.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.4")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testLMDBSuffixLookup(self):
        """
        LMDB: Match on the qname via a suffix lookup
        """
        name = "sub.sub.suffix.lmdb.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "42.42.42.42")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testLMDBQNamePlainText(self):
        """
        LMDB: Match on qname in plain text format
        """
        name = "qname-plaintext.lmdb.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "9.10.11.12")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testLMDBKeyValueStoreLookupRule(self):
        """
        LMDB: KeyValueStoreLookupRule
        """
        name = "kvs-rule.lmdb.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "13.14.15.16")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


class TestLMDBYaml(TestLMDB):
    _lmdbFileName = "/tmp/test-lmdb-db"
    _lmdbDBName = "db-name"
    _config_template = ""
    _config_params = []
    _yaml_config_template = """---
backends:
  - address: "127.0.0.1:%d"
    protocol: Do53
key_value_stores:
  lmdb:
    - name: "lmdb-kvs"
      file_name: "%s"
      database_name: "%s"
  lookup_keys:
    source_ip_keys:
      - name: "lookup-source-ip"
    qname_keys:
      - name: "lookup-qname"
      - name: "lookup-qname-plaintext"
        wire_format: false
    suffix_keys:
      - name: "lookup-suffix"
    tag_keys:
      - name: "lookup-tag-qname-result"
        tag: "kvs-qname-result"

query_rules:
  - name: "qname as key"
    selector:
      type: "And"
      selectors:
        - type: "QName"
          qname: "kvs-rule.lmdb.tests.powerdns.com."
        - type: "KeyValueStoreLookup"
          kvs_name: "lmdb-kvs"
          lookup_key_name: "lookup-qname-plaintext"
    action:
      type: "Spoof"
      ips:
        - "13.14.15.16"
  - name: "source IP as key"
    selector:
      type: "All"
    action:
      type: "KeyValueStoreLookup"
      kvs_name: "lmdb-kvs"
      lookup_key_name: "lookup-source-ip"
      destination_tag: "kvs-sourceip-result"
  - name: "plaintext qname as key"
    selector:
      type: "All"
    action:
      type: "KeyValueStoreLookup"
      kvs_name: "lmdb-kvs"
      lookup_key_name: "lookup-qname-plaintext"
      destination_tag: "kvs-plain-text-result"
  - name: "plaintext qname tag check"
    selector:
      type: "Tag"
      tag: "kvs-plain-text-result"
      value: "this is the value of the plaintext tag"
    action:
      type: "Spoof"
      ips:
        - "9.10.11.12"
  - name: "wire qname as key"
    selector:
      type: "All"
    action:
      type: "KeyValueStoreLookup"
      kvs_name: "lmdb-kvs"
      lookup_key_name: "lookup-qname"
      destination_tag: "kvs-qname-result"
  - name: "wire qname tag check"
    selector:
      type: "Tag"
      tag: "kvs-qname-result"
      value: "this is the value of the qname tag"
    action:
      type: "KeyValueStoreLookup"
      kvs_name: "lmdb-kvs"
      lookup_key_name: "lookup-tag-qname-result"
      destination_tag: "kvs-tag-result"
  - name: "source IP as key"
    selector:
      type: "All"
    action:
      type: "KeyValueStoreLookup"
      kvs_name: "lmdb-kvs"
      lookup_key_name: "lookup-source-ip"
      destination_tag: "kvs-sourceip-result"
  - name: "qname suffix as key"
    selector:
      type: "All"
    action:
      type: "KeyValueStoreLookup"
      kvs_name: "lmdb-kvs"
      lookup_key_name: "lookup-suffix"
      destination_tag: "kvs-suffix-result"
  - name: "tag check"
    selector:
      type: "Tag"
      tag: "kvs-tag-result"
      value: "this is the value of the second tag"
    action:
      type: "Spoof"
      ips:
        - "1.2.3.4"
  - name: "suffix tag check"
    selector:
      type: "Tag"
      tag: "kvs-suffix-result"
      value: "this is the value of the suffix tag"
    action:
      type: "Spoof"
      ips:
        - "42.42.42.42"
  - name: "source IP tag check"
    selector:
      type: "Tag"
      tag: "kvs-sourceip-result"
      value: "this is the value of the source address tag"
    action:
      type: "Spoof"
      ips:
        - "5.6.7.8"
  - name: "otherwise"
    selector:
      type: "All"
    action:
      type: "Spoof"
      ips:
        - "9.9.9.9"
    """
    _yaml_config_params = ["_testServerPort", "_lmdbFileName", "_lmdbDBName"]


class TestLMDBIPInRange(DNSDistTest):
    _lmdbFileName = "/tmp/test-lmdb-range-1-db"
    _lmdbDBName = "db-name"
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    kvs = newLMDBKVStore('%s', '%s')

    -- KVS range lookups follow
    -- does a range lookup in the LMDB database using the source IP as key
    addAction(KeyValueStoreRangeLookupRule(kvs, KeyValueLookupKeySourceIP(32, 128, true)), SpoofAction('5.6.7.8'))

    -- otherwise, spoof a different response
    addAction(AllRule(), SpoofAction('9.9.9.9'))
    """
    _config_params = ["_testServerPort", "_lmdbFileName", "_lmdbDBName"]

    @classmethod
    def setUpLMDB(cls):
        env = lmdb.open(cls._lmdbFileName, map_size=1014 * 1024, max_dbs=1024, subdir=False)
        db = env.open_db(key=cls._lmdbDBName.encode())
        with env.begin(db=db, write=True) as txn:
            txn.put(
                socket.inet_aton("127.255.255.255") + struct.pack("!H", 255),
                socket.inet_aton("127.0.0.0") + struct.pack("!H", 0) + b"this is the value of the source address tag",
            )

    @classmethod
    def setUpClass(cls):
        cls.setUpLMDB()
        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

        print("Launching tests..")

    def testLMDBSource(self):
        """
        LMDB range: Match on source address
        """
        name = "source-ip.lmdb-range.tests.powerdns.com."
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


class TestLMDBIPNotInRange(DNSDistTest):
    _lmdbFileName = "/tmp/test-lmdb-range-2-db"
    _lmdbDBName = "db-name"
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    kvs = newLMDBKVStore('%s', '%s')

    -- KVS range lookups follow
    -- does a range lookup in the LMDB database using the source IP as key
    addAction(KeyValueStoreRangeLookupRule(kvs, KeyValueLookupKeySourceIP(32, 128, true)), SpoofAction('5.6.7.8'))

    -- otherwise, spoof a different response
    addAction(AllRule(), SpoofAction('9.9.9.9'))
    """
    _config_params = ["_testServerPort", "_lmdbFileName", "_lmdbDBName"]

    @classmethod
    def setUpLMDB(cls):
        env = lmdb.open(cls._lmdbFileName, map_size=1014 * 1024, max_dbs=1024, subdir=False)
        db = env.open_db(key=cls._lmdbDBName.encode())
        with env.begin(db=db, write=True) as txn:
            txn.put(
                socket.inet_aton("127.0.0.0") + struct.pack("!H", 255),
                socket.inet_aton("127.0.0.0") + struct.pack("!H", 0) + b"this is the value of the source address tag",
            )

    @classmethod
    def setUpClass(cls):
        cls.setUpLMDB()
        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

        print("Launching tests..")

    def testLMDBSource(self):
        """
        LMDB not in range: Match on source address
        """
        name = "source-ip.lmdb-not-in-range.tests.powerdns.com."
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
