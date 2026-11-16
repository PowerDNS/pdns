#!/usr/bin/env python
import dns
import requests

import clientsubnetoption
import cookiesoption
from dnsdisttests import DNSDistTest, pickAvailablePort


class CacheTests(object):
    def testExistsCheck(self):
        """
        Cache: Refused when value is cached
        """
        read_name = "read.cache.tests.powerdns.com."
        store_name = "store.cache.tests.powerdns.com."

        # First read, to show no Refused
        query = dns.message.make_query(read_name, "A", "IN")
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(read_name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

        # then store
        query = dns.message.make_query(store_name, "A", "IN")
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(store_name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "127.0.0.1")
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

        # Then read again, should get Refused
        query = dns.message.make_query(read_name, "A", "IN")
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.Rcode.REFUSED)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertIsNone(receivedQuery)
        self.assertTrue(receivedResponse)
        self.assertEqual(receivedResponse, response)

    def testRemove(self):
        """
        Cache: Refused when value is cached, but it gets removed too
        """
        read_name = "read.cache.tests.powerdns.com."
        store_name = "store.cache.tests.powerdns.com."

        # store
        query = dns.message.make_query(store_name, "AAAA", "IN")
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(store_name, 3600, dns.rdataclass.IN, dns.rdatatype.AAAA, "::1")
        response.answer.append(rrset)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEqual(query, receivedQuery)
        self.assertEqual(receivedResponse, response)

        # read, should get Refused
        query = dns.message.make_query(read_name, "AAAA", "IN")
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.Rcode.REFUSED)

        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response, useQueue=False)
        self.assertIsNone(receivedQuery)
        self.assertTrue(receivedResponse)
        self.assertEqual(receivedResponse, response)

        # read again, should get response
        query = dns.message.make_query(read_name, "AAAA", "IN")
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(read_name, 3600, dns.rdataclass.IN, dns.rdatatype.AAAA, "::1")
        response.answer.append(rrset)

        (_, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedResponse)
        self.assertEqual(receivedResponse, response)


class TestGenericCache(DNSDistTest, CacheTests):
    _config_template = """
    cache = newObjectCache("test", { maxEntries = 1000 })
    function store(dq)
        cache:insert(dq.remoteaddr:toString(), "some value")
        return DNSAction.None, ""
    end
    function dropWhenExists(dq)
        if cache:contains(dq.remoteaddr:toString()) then
            cache:remove(dq.remoteaddr:toString())
            return DNSAction.Refused
        end
        return DNSAction.None, ""
    end
    addAction("store.cache.tests.powerdns.com.", LuaAction(store))
    addAction("read.cache.tests.powerdns.com.", LuaAction(dropWhenExists))
    newServer{address="127.0.0.1:%d"}
    """


class TestGenericCacheYaml(DNSDistTest, CacheTests):
    _yaml_config_template = """---
backends:
  - address: "127.0.0.1:%d"
    protocol: Do53

generic_caches:
  object:
    - name: "test-cache"
      max_entries: 1000

query_rules:
  - name: Lua store to cache rule
    selector:
      type: Regex
      expression: store.*
    action:
      type: Lua
      function_code: |
        function store(dq)
            local cache = getObjectFromYAMLConfiguration("test-cache")
            cache:insert(dq.remoteaddr:toString(), "some value")
            return DNSAction.None, ""
        end
        return store

  - name: Lua read from cache rule
    selector:
      type: Regex
      expression: read.*
    action:
      type: Lua
      function_code: |
        function dropWhenExists(dq)
            local cache = getObjectFromYAMLConfiguration("test-cache")
            if cache:contains(dq.remoteaddr:toString()) then
                cache:remove(dq.remoteaddr:toString())
                return DNSAction.Refused
            end
            return DNSAction.None, ""
        end
        return dropWhenExists
    """
    _yaml_config_params = ["_testServerPort"]
