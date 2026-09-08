/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#pragma once

#include "dolog.hh"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_REDIS
#include "dnsdist-lua-types.hh"
#include "ext/json11/json11.hpp"
#include "lock.hh"
#include <boost/variant/get.hpp>
#include <optional>
#include <unordered_set>
#include <yahttp/yahttp.hpp>
#include <hiredis/hiredis.h>
#include <memory>
#include <string>
#include "redis-stats.hh"

class RedisClient;

template <typename T>
class RedisReplyInterface
{
public:
  RedisReplyInterface(const RedisReplyInterface&) = delete;
  RedisReplyInterface(RedisReplyInterface&&) = delete;
  RedisReplyInterface& operator=(const RedisReplyInterface&) = delete;
  RedisReplyInterface& operator=(RedisReplyInterface&&) = delete;
  virtual ~RedisReplyInterface() = default;
  RedisReplyInterface() = default;
  [[nodiscard]] virtual bool ok() const = 0;
  [[nodiscard]] virtual T getValue() const = 0;
  [[nodiscard]] virtual std::string getError() const = 0;
};

template <typename T>
class RedisReply : public RedisReplyInterface<T>
{
public:
  RedisReply(const RedisReply&) = delete;
  RedisReply(RedisReply&&) = delete;
  RedisReply& operator=(const RedisReply&) = delete;
  RedisReply& operator=(RedisReply&&) = delete;
  RedisReply(redisReply* reply) :
    d_reply(reply)
  {
  }
  ~RedisReply() override
  {
    if (d_reply != nullptr) {
      freeReplyObject(d_reply);
    }
  }

  [[nodiscard]] bool ok() const override
  {
    return d_reply != nullptr && d_reply->type != REDIS_REPLY_ERROR;
  }

  [[nodiscard]] std::string getError() const override
  {
    if (d_reply != nullptr) {
      return {d_reply->str, d_reply->len};
    }

    return {};
  }

protected:
  redisReply* d_reply;
};

template <typename S, typename T>
class MappedRedisReply : public RedisReplyInterface<T>
{
public:
  MappedRedisReply(std::unique_ptr<RedisReplyInterface<S>> inner) :
    d_inner(std::move(inner)) { };

  [[nodiscard]] bool ok() const override
  {
    return d_inner->ok();
  }

  [[nodiscard]] std::string getError() const override
  {
    return d_inner->getError();
  }

  [[nodiscard]] T getValue() const override = 0;

protected:
  std::unique_ptr<RedisReplyInterface<S>> d_inner;
};

template <typename S, typename T>
class DefaultMappedRedisReply : public MappedRedisReply<S, T>
{
public:
  DefaultMappedRedisReply(std::unique_ptr<RedisReplyInterface<S>> inner) :
    MappedRedisReply<S, T>(std::move(inner)) { };

  T getValue() const override
  {
    return T(this->d_inner->getValue());
  }
};

class RedisStringReply : public RedisReply<std::string>
{
public:
  RedisStringReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  [[nodiscard]] bool ok() const override
  {
    return RedisReply::ok() && (d_reply->str != nullptr);
  }
  [[nodiscard]] std::string getValue() const override
  {
    return {d_reply->str, d_reply->len};
  }
};

class RedisIntReply : public RedisReply<long long>
{
public:
  RedisIntReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  [[nodiscard]] bool ok() const override
  {
    return d_reply != nullptr && d_reply->type == REDIS_REPLY_INTEGER;
  }
  [[nodiscard]] long long getValue() const override
  {
    return d_reply->integer;
  }
};

class RedisIntAsStringReply : public MappedRedisReply<long long, std::string>
{
public:
  RedisIntAsStringReply(std::unique_ptr<RedisReplyInterface<long long>> inner) :
    MappedRedisReply(std::move(inner))
  {
  }
  [[nodiscard]] std::string getValue() const override
  {
    return std::to_string(d_inner->getValue());
  }
};

class RedisIntAsBoolReply : public MappedRedisReply<long long, bool>
{
public:
  RedisIntAsBoolReply(std::unique_ptr<RedisReplyInterface<long long>> inner) :
    MappedRedisReply(std::move(inner))
  {
  }
  [[nodiscard]] bool getValue() const override
  {
    return d_inner->getValue() > 0;
  }
};

class RedisBoolAsStringReply : public MappedRedisReply<bool, std::string>
{
public:
  RedisBoolAsStringReply(std::unique_ptr<RedisReplyInterface<bool>> inner) :
    MappedRedisReply(std::move(inner))
  {
  }
  [[nodiscard]] std::string getValue() const override
  {
    return d_inner->getValue() ? "1" : "0";
  }
};

class RedisHashReply : public RedisReply<std::unordered_map<std::string, std::string>>
{
public:
  RedisHashReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  [[nodiscard]] bool ok() const override
  {
    return d_reply != nullptr && d_reply->type == REDIS_REPLY_ARRAY && d_reply->elements % 2 == 0;
  }
  [[nodiscard]] std::unordered_map<std::string, std::string> getValue() const override
  {
    std::unordered_map<std::string, std::string> result{d_reply->elements / 2};
    for (size_t i = 0; i < d_reply->elements; i += 2) {
      auto key = std::string(d_reply->element[i]->str, d_reply->element[i]->len);
      auto value = std::string(d_reply->element[i + 1]->str, d_reply->element[i + 1]->len);
      result.emplace(key, value);
    }
    return result;
  }
};

class RedisArrayReply : public RedisReply<std::vector<std::pair<int, std::optional<std::string>>>>
{
public:
  RedisArrayReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  [[nodiscard]] bool ok() const override
  {
    return d_reply != nullptr && d_reply->type == REDIS_REPLY_ARRAY;
  }
  [[nodiscard]] std::vector<std::pair<int, std::optional<std::string>>> getValue() const override
  {
    std::vector<std::pair<int, std::optional<std::string>>> result{d_reply->elements};
    for (size_t i = 0; i < d_reply->elements; i++) {
      if (d_reply->element[i]->type == REDIS_REPLY_NIL) {
        result.emplace_back(i + 1, std::nullopt);
      }
      else {
        // Lua arrays start at 1 instead of 0
        result.emplace_back(i + 1, d_reply->element[i]->str);
      }
    }
    return result;
  }
};

class RedisSetReply : public RedisReply<std::unordered_set<std::string>>
{
public:
  RedisSetReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  [[nodiscard]] bool ok() const override
  {
    return (d_reply != nullptr) && d_reply->type == REDIS_REPLY_ARRAY;
  }
  [[nodiscard]] std::unordered_set<std::string> getValue() const override
  {
    std::unordered_set<std::string> result{d_reply->elements};
    for (size_t i = 0; i < d_reply->elements; i++) {
      result.emplace(d_reply->element[i]->str);
    }
    return result;
  }
};

class RedisRawReply : public RedisReply<std::optional<LuaAny>>
{
public:
  RedisRawReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  [[nodiscard]] std::optional<LuaAny> getValue() const override
  {
    return parseReply(d_reply);
  }

private:
  std::optional<LuaAny> parseReply(redisReply* reply) const
  {
    switch (reply->type) {
    case REDIS_REPLY_INTEGER:
      // TODO: narrowing conversion
      return static_cast<int64_t>(reply->integer);
      break;
    case REDIS_REPLY_STRING:
    case REDIS_REPLY_STATUS:
#if HIREDIS_MAJOR > 0
    case REDIS_REPLY_BIGNUM:
    case REDIS_REPLY_VERB:
#endif
      return std::string(reply->str, reply->len);
      break;
    case REDIS_REPLY_ARRAY:
#if HIREDIS_MAJOR > 0
    case REDIS_REPLY_SET:
#endif
      return parseArray(reply);
      break;
#if HIREDIS_MAJOR > 0
    case REDIS_REPLY_DOUBLE:
      return reply->dval;
      break;
    case REDIS_REPLY_BOOL:
      return reply->integer > 0;
      break;
    case REDIS_REPLY_MAP:
      return parseMap(reply);
      break;
#endif
    }
    return std::nullopt;
  }

  LuaArray<LuaAny> parseArray(redisReply* data) const
  {
    LuaArray<LuaAny> res{data->elements};
    for (size_t i = 0; i < data->elements; i++) {
      if (auto value = parseReply(data->element[i])) {
        res[i] = std::make_pair(i + 1, value.value());
      }
    }
    return res;
  }

#if HIREDIS_MAJOR > 0
  LuaAssociativeTable<LuaAny> parseMap(redisReply* data) const
  {
    LuaAssociativeTable<LuaAny> res{data->elements / 2};
    for (size_t i = 0; i < data->elements / 2; i += 2) {
      if (auto value = parseReply(data->element[i + 1])) {
        res.emplace(data->element[i]->str, value.value());
      }
    }
    return res;
  }
#endif
};

class RedisRawAsBoolReply : public MappedRedisReply<std::optional<LuaAny>, bool>
{
public:
  RedisRawAsBoolReply(std::unique_ptr<RedisReplyInterface<std::optional<LuaAny>>> inner) :
    MappedRedisReply(std::move(inner))
  {
  }
  [[nodiscard]] bool getValue() const override
  {
    auto rawReply = dynamic_cast<RedisRawReply*>(d_inner.get());
    return rawReply->getValue().has_value();
  }
};

class RedisRawAsStringReply : public MappedRedisReply<std::optional<LuaAny>, std::string>
{
public:
  RedisRawAsStringReply(std::unique_ptr<RedisReplyInterface<std::optional<LuaAny>>> inner) :
    MappedRedisReply(std::move(inner))
  {
  }
  [[nodiscard]] std::string getValue() const override
  {
    auto result = d_inner->getValue();
    if (!result.has_value()) {
      return json11::Json().dump();
    }
    if (result.value().type() == typeid(std::string)) {
      return boost::get<std::string>(result.value());
    }

    json11::Json json = parseAny(result.value());
    return json.dump();
  }

private:
  [[nodiscard]] json11::Json parseAny(const LuaAny& any) const
  {
    if (any.type() == typeid(std::string)) {
      return boost::get<std::string>(any);
    }
    if (any.type() == typeid(uint64_t)) {
      return static_cast<int>(boost::get<uint64_t>(any));
    }
    if (any.type() == typeid(int64_t)) {
      return static_cast<int>(boost::get<int64_t>(any));
    }
    if (any.type() == typeid(double)) {
      return boost::get<double>(any);
    }
    if (any.type() == typeid(bool)) {
      return boost::get<bool>(any);
    }
    if (any.type() == typeid(LuaArray<LuaAny>)) {
      auto luaArray = boost::get<LuaArray<LuaAny>>(any);
      std::vector<json11::Json> array;
      array.reserve(luaArray.size());
      for (auto& kv : luaArray) {
        array.emplace_back(parseAny(kv.second));
      }
      return array;
    }
    if (any.type() == typeid(LuaAssociativeTable<LuaAny>)) {
      auto luaTable = boost::get<LuaAssociativeTable<LuaAny>>(any);
      std::unordered_map<std::string, json11::Json> map(luaTable.size());
      for (auto& kv : map) {
        map.emplace(kv.first, kv.second);
      }
      return map;
    }
    return {};
  }
};

template <typename T, typename... Args>
struct RedisCommand
{
  virtual ~RedisCommand() = default;
  RedisCommand(const RedisCommand&) = delete;
  RedisCommand(RedisCommand&&) = delete;
  RedisCommand& operator=(const RedisCommand&) = delete;
  RedisCommand& operator=(RedisCommand&&) = delete;
  RedisCommand() = default;
  virtual std::unique_ptr<RedisReplyInterface<T>> operator()(const RedisClient& client, const Args&... args) const = 0;
};

struct RedisGetCommand : public RedisCommand<std::string, std::string>
{
  ~RedisGetCommand() override = default;
  RedisGetCommand(const RedisGetCommand&) = delete;
  RedisGetCommand(RedisGetCommand&&) = delete;
  RedisGetCommand& operator=(const RedisGetCommand&) = delete;
  RedisGetCommand& operator=(RedisGetCommand&&) = delete;
  RedisGetCommand() = default;
  std::unique_ptr<RedisReplyInterface<std::string>> operator()(const RedisClient& client, const std::string& key) const override;
};

struct RedisExistsCommand : public RedisCommand<bool, std::string>
{
  ~RedisExistsCommand() override = default;
  RedisExistsCommand(const RedisExistsCommand&) = delete;
  RedisExistsCommand(RedisExistsCommand&&) = delete;
  RedisExistsCommand& operator=(const RedisExistsCommand&) = delete;
  RedisExistsCommand& operator=(RedisExistsCommand&&) = delete;
  RedisExistsCommand() = default;
  std::unique_ptr<RedisReplyInterface<bool>> operator()(const RedisClient& client, const std::string& key) const override;
};

struct RedisHGetCommand : public RedisCommand<std::string, std::string, std::string>
{
  ~RedisHGetCommand() override = default;
  RedisHGetCommand(const RedisHGetCommand&) = delete;
  RedisHGetCommand(RedisHGetCommand&&) = delete;
  RedisHGetCommand& operator=(const RedisHGetCommand&) = delete;
  RedisHGetCommand& operator=(RedisHGetCommand&&) = delete;
  RedisHGetCommand() = default;
  std::unique_ptr<RedisReplyInterface<std::string>> operator()(const RedisClient& client, const std::string& hash_key, const std::string& key) const override;
};

// This works with vector of pairs to better work with Lua interface
struct RedisHMGetCommand : public RedisCommand<std::vector<std::pair<int, std::optional<std::string>>>, std::string, std::vector<std::pair<int, std::string>>>
{
  ~RedisHMGetCommand() override = default;
  RedisHMGetCommand(const RedisHMGetCommand&) = delete;
  RedisHMGetCommand(RedisHMGetCommand&&) = delete;
  RedisHMGetCommand& operator=(const RedisHMGetCommand&) = delete;
  RedisHMGetCommand& operator=(RedisHMGetCommand&&) = delete;
  RedisHMGetCommand() = default;
  std::unique_ptr<RedisReplyInterface<std::string>> operator()(const RedisClient& client, const std::string& hash_key, const std::string& key) const;
  std::unique_ptr<RedisReplyInterface<std::vector<std::pair<int, std::optional<std::string>>>>> operator()(const RedisClient& client, const std::string& hash_key, const std::vector<std::pair<int, std::string>>& fields) const override;
};

struct RedisHExistsCommand : public RedisCommand<bool, std::string, std::string>
{
  ~RedisHExistsCommand() override = default;
  RedisHExistsCommand(const RedisHExistsCommand&) = delete;
  RedisHExistsCommand(RedisHExistsCommand&&) = delete;
  RedisHExistsCommand& operator=(const RedisHExistsCommand&) = delete;
  RedisHExistsCommand& operator=(RedisHExistsCommand&&) = delete;
  RedisHExistsCommand() = default;
  std::unique_ptr<RedisReplyInterface<bool>> operator()(const RedisClient& client, const std::string& hash_key, const std::string& key) const override;
};

struct RedisSIsMemberCommand : public RedisCommand<bool, std::string, std::string>
{
  ~RedisSIsMemberCommand() override = default;
  RedisSIsMemberCommand(const RedisSIsMemberCommand&) = delete;
  RedisSIsMemberCommand(RedisSIsMemberCommand&&) = delete;
  RedisSIsMemberCommand& operator=(const RedisSIsMemberCommand&) = delete;
  RedisSIsMemberCommand& operator=(RedisSIsMemberCommand&&) = delete;
  RedisSIsMemberCommand() = default;
  std::unique_ptr<RedisReplyInterface<bool>> operator()(const RedisClient& client, const std::string& set_key, const std::string& key) const override;
};

struct RedisRawCommand : public RedisCommand<std::optional<LuaAny>, LuaArray<std::string>>
{
  ~RedisRawCommand() override = default;
  RedisRawCommand(const RedisRawCommand&) = delete;
  RedisRawCommand(RedisRawCommand&&) = delete;
  RedisRawCommand& operator=(const RedisRawCommand&) = delete;
  RedisRawCommand& operator=(RedisRawCommand&&) = delete;
  RedisRawCommand() = default;
  std::unique_ptr<RedisReplyInterface<std::optional<LuaAny>>> operator()(const RedisClient& client, const LuaArray<std::string>& raw_command) const override;
};

class RedisLookupAction
{
public:
  RedisLookupAction() = default;
  RedisLookupAction(const RedisLookupAction&) = default;
  RedisLookupAction(RedisLookupAction&&) = delete;
  RedisLookupAction& operator=(const RedisLookupAction&) = default;
  RedisLookupAction& operator=(RedisLookupAction&&) = delete;
  virtual ~RedisLookupAction() = default;

  [[nodiscard]] virtual std::unique_ptr<RedisReplyInterface<std::string>> getValue(const RedisClient& client, const std::string& key) const = 0;
  [[nodiscard]] virtual std::unique_ptr<RedisReplyInterface<bool>> keyExists(const RedisClient& client, const std::string& key) const = 0;
};

class RedisGetLookupAction : public RedisLookupAction
{
public:
  RedisGetLookupAction(std::string prefix = "") :
    d_prefix(std::move(prefix))
  {
  }
  [[nodiscard]] std::unique_ptr<RedisReplyInterface<std::string>> getValue(const RedisClient& client, const std::string& key) const override;
  [[nodiscard]] std::unique_ptr<RedisReplyInterface<bool>> keyExists(const RedisClient& client, const std::string& key) const override;

private:
  std::string d_prefix;
  RedisGetCommand d_getCommand;
  RedisExistsCommand d_existsCommand;
};

class RedisHGetLookupAction : public RedisLookupAction
{
public:
  RedisHGetLookupAction(std::string hash_key) :
    d_hash_key(std::move(hash_key))
  {
  }
  [[nodiscard]] std::unique_ptr<RedisReplyInterface<std::string>> getValue(const RedisClient& client, const std::string& key) const override;
  [[nodiscard]] std::unique_ptr<RedisReplyInterface<bool>> keyExists(const RedisClient& client, const std::string& key) const override;

private:
  std::string d_hash_key;
  RedisHGetCommand d_getCommand;
  RedisHExistsCommand d_existsCommand;
};

class RedisSIsMemberLookupAction : public RedisLookupAction
{
public:
  RedisSIsMemberLookupAction(std::string set_key) :
    d_set_key(std::move(set_key))
  {
  }
  [[nodiscard]] std::unique_ptr<RedisReplyInterface<std::string>> getValue(const RedisClient& client, const std::string& key) const override;
  [[nodiscard]] std::unique_ptr<RedisReplyInterface<bool>> keyExists(const RedisClient& client, const std::string& key) const override;

private:
  std::string d_set_key;
  RedisSIsMemberCommand d_sIsMemberCommand;
};

class RedisRawLookupAction : public RedisLookupAction
{
public:
  RedisRawLookupAction(const std::vector<std::string>& args, const std::optional<std::vector<std::string>>& existsArgs = std::nullopt) :
    d_args(args), d_existsArgs(existsArgs.value_or(d_args)), d_keyArgPos(find_if(args.begin(), args.end(), [](const std::string& arg) { return arg.find("{}") != std::string::npos; }) - args.begin()), d_keyArgPosInString(d_keyArgPos < d_args.size() ? args[d_keyArgPos].find("{}") : 0), d_keyArgPosInExists(existsArgs ? find_if(existsArgs.value().begin(), existsArgs.value().end(), [](const std::string& arg) { return arg.find("{}") != std::string::npos; }) - existsArgs.value().begin() : d_keyArgPos), d_keyArgPosInExistsInString(d_keyArgPosInExists < d_existsArgs.size() ? d_existsArgs[d_keyArgPosInExists].find("{}") : 0)
  {
  }
  [[nodiscard]] std::unique_ptr<RedisReplyInterface<std::string>> getValue(const RedisClient& client, const std::string& key) const override;
  [[nodiscard]] std::unique_ptr<RedisReplyInterface<bool>> keyExists(const RedisClient& client, const std::string& key) const override;

private:
  std::vector<std::string> d_args;
  std::vector<std::string> d_existsArgs;
  size_t d_keyArgPos;
  size_t d_keyArgPosInString;
  size_t d_keyArgPosInExists;
  size_t d_keyArgPosInExistsInString;
  RedisRawCommand d_rawCommand;
};

class RedisClient
{
public:
  RedisClient(const std::string& url) :
    d_connection(url) { }

  redisReply* executeCommand(const char* format, ...) const;
  redisReply* executeCommandArgv(std::vector<std::string> args) const;

  const YaHTTP::URL& getUrl() const
  {
    return d_connection.getUrl();
  }

private:
  [[nodiscard]] std::shared_ptr<const Logr::Logger> getLogger() const;

  class RedisConnection
  {
  public:
    RedisConnection(const std::string& url);
    bool reconnect();
    LockGuardedHolder<const std::unique_ptr<redisContext, decltype(&redisFree)>> getConnection() const
    {
      return d_context.read_only_lock();
    }

    bool needsReconnect()
    {
      auto connection = d_context.read_only_lock();
      return *connection == nullptr || connection->get()->err != 0;
    }

    const YaHTTP::URL& getUrl() const
    {
      return d_url;
    }

  private:
    mutable LockGuarded<std::unique_ptr<redisContext, decltype(&redisFree)>> d_context{std::unique_ptr<redisContext, decltype(&redisFree)>(nullptr, redisFree)};
    YaHTTP::URL d_url;
  };

  RedisConnection d_connection;
};

class RedisKVClientInterface
{
public:
  RedisKVClientInterface(const RedisKVClientInterface&) = default;
  RedisKVClientInterface(RedisKVClientInterface&&) = delete;
  RedisKVClientInterface& operator=(const RedisKVClientInterface&) = default;
  RedisKVClientInterface& operator=(RedisKVClientInterface&&) = delete;
  RedisKVClientInterface() = default;
  virtual ~RedisKVClientInterface() = default;
  virtual bool getValue(const std::string& key, std::string& value) = 0;
  virtual bool keyExists(const std::string& key) = 0;
};

class RedisKVClient : public RedisKVClientInterface
{
public:
  RedisKVClient(const std::shared_ptr<RedisClient>& client, std::unique_ptr<RedisLookupAction> lookupAction, std::shared_ptr<RedisStats> stats) :
    d_client(client), d_lookupAction(std::move(lookupAction)), d_stats(std::move(stats))
  {
  }

  bool getValue(const std::string& key, std::string& value) override;
  bool keyExists(const std::string& key) override;

private:
  [[nodiscard]] std::shared_ptr<const Logr::Logger> getLogger() const;

  std::shared_ptr<RedisClient>
    d_client;
  std::unique_ptr<RedisLookupAction> d_lookupAction;
  std::shared_ptr<RedisStats> d_stats;
};
#else
class RedisClient
{
};
#endif
