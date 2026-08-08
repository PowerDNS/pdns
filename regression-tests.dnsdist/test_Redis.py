#!/usr/bin/env python
import os
import socket
import time
import unittest
from threading import Thread

import dns
import fakeredis
from netaddr import IPNetwork, IPSet

from dnsdisttests import DNSDistTest, pickAvailablePort


class RedisGet(object):
    def testRedisGetKvs(self):
        """
        Redis: Match on Qname in KVS
        """
        name = "kvs.correct.tests.powerdns.com."
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

    def testRedisGetLua(self):
        """
        Redis: match on QName in Lua action
        """
        name = "lua-get.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "7.8.9.10")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testRedisGetKvsFailedLookup(self):
        """
        Redis: QName not found in KVS
        """
        name = "kvs.wrong.tests.powerdns.com."
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

    def testRedisGetLuaFailedLookup(self):
        """
        Redis: QName not found in Lua lookup
        """
        name = "lua-get.wrong.tests.powerdns.com."
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


class RedisHGet(object):
    def testRedisHGetKvs(self):
        """
        Redis: Match on Qname in KVS
        """
        name = "kvs.correct.tests.powerdns.com."
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

    def testRedisHGetLua(self):
        """
        Redis: match on QName in GET Lua action
        """
        name = "lua-get.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "7.8.9.11")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testRedisHGetLua(self):
        """
        Redis: match on QName in HGET Lua action
        """
        name = "lua-hget.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "7.8.9.12")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testRedisHGetKvsFailedLookup(self):
        """
        Redis: QName not found in KVS
        """
        name = "kvs.wrong.tests.powerdns.com."
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

    def testRedisGetLuaFailedLookup(self):
        """
        Redis: QName not found in Lua GET lookup
        """
        name = "lua-get.wrong.tests.powerdns.com."
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

    def testRedisHGetLuaFailedLookup(self):
        """
        Redis: QName not found in Lua HGET lookup
        """
        name = "lua-hget.wrong.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "9.9.9.11")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


@unittest.skipIf("SKIP_REDIS_TESTS" in os.environ, "Redis tests are disabled")
class RedisTest(DNSDistTest):
    _redisPort = pickAvailablePort()
    _lookupAction = "get"
    _dataName = ""
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    dataName = "%s"
    redis = newRedisClient("redis://127.0.0.1:%d")
    kvs = newRedisKVStore(redis, { lookupAction = "%s", dataName = dataName })

    function lua_redis_get_query(dq)
        if not redis:exists(dq.qname:toString()) then
            return DNSAction.None
        end
        local data = redis:get(dq.qname:toString())
        if data == nil then
            return DNSAction.None
        end
        return DNSAction.Spoof, data
    end

    function lua_redis_hget_query(dq)
        if not redis:hexists(dataName, dq.qname:toString()) then
            return DNSAction.None
        end
        local data = redis:hget(dataName, dq.qname:toString())
        if data == nil then
            return DNSAction.None
        end
        return DNSAction.Spoof, data
    end

    -- does a lookup in the Redis database using the qname as key, and store the result into the 'kvs-qname-result' tag
    addAction(RegexRule('kvs.*'), KeyValueStoreLookupAction(kvs, KeyValueLookupKeyQName(false), 'kvs-qname-result'))

    -- if the value of the 'kvs-qname-result' is set to 'test-result', spoof a response
    addAction(TagRule('kvs-qname-result', 'test-result'), SpoofAction('5.6.7.8'))

    -- does a lookup using get and directly spoofs if found
    addAction(RegexRule('lua-get.*'), LuaAction(lua_redis_get_query))

    -- does a lookup using hget and directly spoofs if found
    addAction(RegexRule('lua-hget.*'), LuaAction(lua_redis_hget_query))

    -- otherwise, spoof a different response
    addAction(RegexRule('kvs.*'), SpoofAction('9.9.9.9'))
    addAction(RegexRule('lua-get.*'), SpoofAction('9.9.9.10'))
    addAction(RegexRule('lua-hget.*'), SpoofAction('9.9.9.11'))
    """
    _config_params = ["_testServerPort", "_dataName", "_redisPort", "_lookupAction"]

    @classmethod
    def setUpRedis(cls):
        print("Configuring Redis for test")
        cls._redisPort = pickAvailablePort()
        cls._redisServer = fakeredis.TcpFakeServer(("localhost", cls._redisPort))
        cls._redisThread = Thread(target=cls._redisServer.serve_forever, daemon=True)
        cls._redisThread.start()

    @classmethod
    def tearDownClass(cls):
        super(RedisTest, cls).tearDownClass()
        cls._redisServer.shutdown()
        cls._redisThread.join()


class TestRedisGetSimple(RedisTest, RedisGet):
    @classmethod
    def setUpRedis(cls):
        super(TestRedisGetSimple, cls).setUpRedis()
        redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)
        redis.set("kvs.correct.tests.powerdns.com", "test-result")
        redis.set("lua-get.tests.powerdns.com.", "7.8.9.10")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisGetSimple, cls).setUpClass()


class TestRedisHGetAndGetWithDataName(RedisTest, RedisHGet):
    _dataName = "test_hash"
    _lookupAction = "hget"

    @classmethod
    def setUpRedis(cls):
        super(TestRedisHGetAndGetWithDataName, cls).setUpRedis()
        redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)
        redis.hset("test_hash", "kvs.correct.tests.powerdns.com", "test-result")
        redis.set("test_hashlua-get.tests.powerdns.com", "7.8.9.11")
        redis.hset("test_hash", "lua-hget.tests.powerdns.com.", "7.8.9.12")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisHGetAndGetWithDataName, cls).setUpClass()


@unittest.skipIf("SKIP_REDIS_TESTS" in os.environ, "Redis tests are disabled")
class RedisYamlTest(DNSDistTest):
    _redisPort = pickAvailablePort()
    _lookupAction = "get"
    _dataName = ""
    _yaml_config_template = """---
backends:
  - address: "127.0.0.1:%d"
    protocol: Do53

redis_clients:
  - name: test-redis
    url: redis://127.0.0.1:%d

key_value_stores:
  redis:
    - name: RedisKV
      redis_client: test-redis
      lookup_action: %s
      data_name: %s
  lookup_keys:
    qname_keys:
      - name: qname
        wire_format: false

query_rules:
  - name: Redis KV Rule
    selector:
      type: Regex
      expression: kvs.*
    action:
      type: KeyValueStoreLookup
      kvs_name: RedisKV
      lookup_key_name: qname
      destination_tag: kvs-qname-result

  - name: Spoof KV test rule
    selector:
      type: Tag
      tag: kvs-qname-result
      value: test-result
    action:
      type: Spoof
      ips:
        - 5.6.7.8

  - name: Redis Lua GET lookup rule
    selector:
      type: Regex
      expression: lua-get.*
    action:
      type: Lua
      function_code: |
        function lua_redis_get_query(dq)
            local redis = getObjectFromYAMLConfiguration("test-redis")
            if not redis:exists(dq.qname:toString()) then
                return DNSAction.None
            end
            local data = redis:get(dq.qname:toString())
            if data == nil then
                return DNSAction.None
            end
            return DNSAction.Spoof, data
        end
        return lua_redis_get_query

  - name: Redis Lua HGET lookup rule
    selector:
      type: Regex
      expression: lua-hget.*
    action:
      type: Lua
      function_code: |
        function lua_redis_hget_query(dq)
            local redis = getObjectFromYAMLConfiguration("test-redis")
            if not redis:hexists("%s", dq.qname:toString()) then
                return DNSAction.None
            end
            local data = redis:hget("%s", dq.qname:toString())
            if data == nil then
                return DNSAction.None
            end
            return DNSAction.Spoof, data
        end
        return lua_redis_hget_query

  - name: Spoof KV missed rule
    selector:
      type: Regex
      expression: kvs.*
    action:
      type: Spoof
      ips:
        - 9.9.9.9

  - name: Spoof Lua GET missed rule
    selector:
      type: Regex
      expression: lua-get.*
    action:
      type: Spoof
      ips:
        - 9.9.9.10

  - name: Spoof Lua HGET missed rule
    selector:
      type: Regex
      expression: lua-hget.*
    action:
      type: Spoof
      ips:
        - 9.9.9.11
"""
    _yaml_config_params = ["_testServerPort", "_redisPort", "_lookupAction", "_dataName", "_dataName", "_dataName"]

    @classmethod
    def setUpRedis(cls):
        print("Configuring Redis for YAML test")
        cls._redisPort = pickAvailablePort()
        cls._redisServer = fakeredis.TcpFakeServer(("localhost", cls._redisPort))
        cls._redisThread = Thread(target=cls._redisServer.serve_forever, daemon=True)
        cls._redisThread.start()

    @classmethod
    def tearDownClass(cls):
        super(RedisYamlTest, cls).tearDownClass()
        cls._redisServer.shutdown()
        cls._redisThread.join()


class TestRedisYamlGetSimple(RedisYamlTest, RedisGet):
    @classmethod
    def setUpRedis(cls):
        super(TestRedisYamlGetSimple, cls).setUpRedis()
        redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)
        redis.set("kvs.correct.tests.powerdns.com", "test-result")
        redis.set("lua-get.tests.powerdns.com.", "7.8.9.10")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisYamlGetSimple, cls).setUpClass()


class TestRedisYamlHGetAndGetWithDataName(RedisYamlTest, RedisHGet):
    _dataName = "test_hash"
    _lookupAction = "hget"

    @classmethod
    def setUpRedis(cls):
        super(TestRedisYamlHGetAndGetWithDataName, cls).setUpRedis()
        redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)
        redis.hset("test_hash", "kvs.correct.tests.powerdns.com", "test-result")
        redis.set("test_hashlua-get.tests.powerdns.com", "7.8.9.11")
        redis.hset("test_hash", "lua-hget.tests.powerdns.com.", "7.8.9.12")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisYamlHGetAndGetWithDataName, cls).setUpClass()
