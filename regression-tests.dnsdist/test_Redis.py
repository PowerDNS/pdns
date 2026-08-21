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


class RedisCommon(object):
    def testRedisKvs(self):
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

    def testRedisKvsFailedLookup(self):
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

    def testRedisSIsMemberLuaFailedLookup(self):
        """
        Redis: QName not found in Lua SISMEMBER lookup
        """
        name = "lua-sismember.wrong.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "9.9.9.12")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testRedisRawLuaFailedLookup(self):
        """
        Redis: QName not found in Lua RAW lookup
        """
        name = "lua-raw.wrong.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "9.9.9.13")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


class RedisGet(RedisCommon):
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


class RedisHGet(RedisCommon):
    def testRedisGetLua(self):
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


class RedisSIsMember(RedisCommon):
    def testRedisGetLua(self):
        """
        Redis: match on QName in GET Lua action
        """
        name = "lua-get.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "7.8.9.13")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testRedisSIsMemberLua(self):
        """
        Redis: match on QName in SISMEMBER Lua action
        """
        name = "lua-sismember.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "7.8.9.14")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)


class RedisRaw(RedisCommon):
    def testRedisGetLua(self):
        """
        Redis: match on QName in GET Lua action
        """
        name = "lua-get.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "7.8.9.15")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testRedisRawLua(self):
        """
        Redis: match on QName in RAW Lua action
        """
        name = "lua-raw.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 3600, dns.rdataclass.IN, dns.rdatatype.A, "7.8.9.16")
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
    _rawArgs = "{}"
    _rawExistsArgs = "{}"
    _sismemberSpoof = ""
    _expectedKvsResult = "test-result"
    _verboseMode = True
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    dataName = "%s"
    redis = newRedisClient("redis://127.0.0.1:%d")
    kvs = newRedisKVStore(redis, { lookupAction = "%s", dataName = dataName, rawArgs = %s, rawExistsArgs = %s})

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

    function lua_redis_sismember_query(dq)
        if not redis:sismember(dataName, dq.qname:toString()) then
            return DNSAction.None
        end
        return DNSAction.Spoof, "%s"
    end

    function lua_redis_raw_query(dq)
        if not redis:raw({"EXISTS", dq.qname:toString()}) then
            return DNSAction.None
        end
        local data = redis:raw({"HGET", dq.qname:toString(), "ip"})
        if data == nil then
            return DNSAction.None
        end
        return DNSAction.Spoof, data
    end

    -- does a lookup in the Redis database using the qname as key, and store the result into the 'kvs-qname-result' tag
    addAction(RegexRule('kvs.*'), KeyValueStoreLookupAction(kvs, KeyValueLookupKeyQName(false), 'kvs-qname-result'))

    -- if the value of the 'kvs-qname-result' is set to 'test-result', spoof a response
    addAction(TagRule('kvs-qname-result', '%s'), SpoofAction('5.6.7.8'))

    -- does a lookup using get and directly spoofs if found
    addAction(RegexRule('lua-get.*'), LuaAction(lua_redis_get_query))

    -- does a lookup using hget and directly spoofs if found
    addAction(RegexRule('lua-hget.*'), LuaAction(lua_redis_hget_query))

    -- does a lookup using sismember and directly spoofs if found
    addAction(RegexRule('lua-sismember.*'), LuaAction(lua_redis_sismember_query))

    -- does a lookup using raw command and directly spoofs if found
    addAction(RegexRule('lua-raw.*'), LuaAction(lua_redis_raw_query))

    -- otherwise, spoof a different response
    addAction(RegexRule('kvs.*'), SpoofAction('9.9.9.9'))
    addAction(RegexRule('lua-get.*'), SpoofAction('9.9.9.10'))
    addAction(RegexRule('lua-hget.*'), SpoofAction('9.9.9.11'))
    addAction(RegexRule('lua-sismember.*'), SpoofAction('9.9.9.12'))
    addAction(RegexRule('lua-raw.*'), SpoofAction('9.9.9.13'))
    """
    _config_params = ["_testServerPort", "_dataName", "_redisPort", "_lookupAction", "_rawArgs", "_rawExistsArgs", "_sismemberSpoof", "_expectedKvsResult"]

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
        redis.set("lua-get.tests.powerdns.com.", "7.8.9.11")
        redis.hset("test_hash", "lua-hget.tests.powerdns.com.", "7.8.9.12")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisHGetAndGetWithDataName, cls).setUpClass()


class TestRedisSIsMember(RedisTest, RedisSIsMember):
    _dataName = "test_set"
    _lookupAction = "sismember"
    _sismemberSpoof = "7.8.9.14"
    _expectedKvsResult = "true"

    @classmethod
    def setUpRedis(cls):
        super(TestRedisSIsMember, cls).setUpRedis()
        redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)
        redis.sadd("test_set", "kvs.correct.tests.powerdns.com")
        redis.set("lua-get.tests.powerdns.com.", "7.8.9.13")
        redis.sadd("test_set", "lua-sismember.tests.powerdns.com.")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisSIsMember, cls).setUpClass()


class TestRedisRaw(RedisTest, RedisRaw):
    _dataName = "test_prefix"
    _lookupAction = "raw"
    _rawArgs = '{"HGET", "{}", "value"}'
    _rawExistsArgs = '{"EXISTS", "{}"}'

    @classmethod
    def setUpRedis(cls):
        super(TestRedisRaw, cls).setUpRedis()
        redis = fakeredis.FakeStrictRedis(server=cls._redisServer.fake_server)
        redis.hset("kvs.correct.tests.powerdns.com", "value", "test-result")
        redis.set("lua-get.tests.powerdns.com.", "7.8.9.15")
        redis.hset("lua-raw.tests.powerdns.com.", "ip", "7.8.9.16")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisRaw, cls).setUpClass()


@unittest.skipIf("SKIP_REDIS_TESTS" in os.environ, "Redis tests are disabled")
class RedisYamlTest(DNSDistTest):
    _redisPort = pickAvailablePort()
    _lookupAction = "get"
    _dataName = ""
    _rawArgs = "[]"
    _rawExistsArgs = "[]"
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
      raw_args: %s
      raw_exists_args: %s
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

  - name: Spoof Lua SISMEMBER missed rule
    selector:
      type: Regex
      expression: lua-sismember.*
    action:
      type: Spoof
      ips:
        - 9.9.9.12

  - name: Spoof Lua RAW missed rule
    selector:
      type: Regex
      expression: lua-raw.*
    action:
      type: Spoof
      ips:
        - 9.9.9.13
"""
    _yaml_config_params = ["_testServerPort", "_redisPort", "_lookupAction", "_dataName", "_rawArgs", "_rawExistsArgs", "_dataName", "_dataName"]

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
        redis.set("lua-get.tests.powerdns.com.", "7.8.9.11")
        redis.hset("test_hash", "lua-hget.tests.powerdns.com.", "7.8.9.12")

    @classmethod
    def setUpClass(cls):
        cls.setUpRedis()
        super(TestRedisYamlHGetAndGetWithDataName, cls).setUpClass()
