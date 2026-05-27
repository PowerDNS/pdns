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

#ifdef HAVE_REDIS

#include "channel.hh"
#include "lock.hh"
#include <thread>
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
  virtual ~RedisReplyInterface() {};
  virtual bool ok() const = 0;
  virtual T getValue() const = 0;
  virtual std::string getError() const = 0;
};

template <typename T>
class RedisReply : public RedisReplyInterface<T>
{
public:
  RedisReply(redisReply* reply) :
    d_reply(reply)
  {
  }
  virtual ~RedisReply() override
  {
    if (d_reply) {
      freeReplyObject(d_reply);
    }
  }

  virtual bool ok() const override
  {
    return d_reply;
  }

  virtual std::string getError() const override
  {
    if (d_reply) {
      return std::string(d_reply->str, d_reply->len);
    }
    else {
      return std::string();
    }
  }

protected:
  redisReply* d_reply;
};

template <typename S, typename T>
class MappedRedisReply : public RedisReplyInterface<T>
{
public:
  MappedRedisReply(std::unique_ptr<RedisReplyInterface<S>> inner) :
    d_inner(std::move(inner)) {};

  virtual bool ok() const override
  {
    return d_inner->ok();
  }

  virtual std::string getError() const override
  {
    return d_inner->getError();
  }

  virtual T getValue() const override = 0;

protected:
  std::unique_ptr<RedisReplyInterface<S>> d_inner;
};

class RedisStringReply : public RedisReply<std::string>
{
public:
  RedisStringReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  bool ok() const override
  {
    return d_reply && (d_reply->str);
  }
  std::string getValue() const override
  {
    return std::string(d_reply->str, d_reply->len);
  }
};

class RedisIntReply : public RedisReply<long long>
{
public:
  RedisIntReply(redisReply* reply) :
    RedisReply(reply)
  {
  }
  bool ok() const override
  {
    return d_reply && d_reply->type == REDIS_REPLY_INTEGER;
  }
  long long getValue() const override
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
  std::string getValue() const override
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
  bool getValue() const override
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
  std::string getValue() const override
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
  bool ok() const override
  {
    return d_reply && d_reply->type == REDIS_REPLY_ARRAY && d_reply->elements % 2 == 0;
  }
  std::unordered_map<std::string, std::string> getValue() const override
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
  bool ok() const override
  {
    return d_reply && d_reply->type == REDIS_REPLY_ARRAY;
  }
  std::vector<std::pair<int, std::optional<std::string>>> getValue() const override
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
  bool ok() const override
  {
    return d_reply && d_reply->type == REDIS_REPLY_ARRAY;
  }
  std::unordered_set<std::string> getValue() const override
  {
    std::unordered_set<std::string> result{d_reply->elements};
    for (size_t i = 0; i < d_reply->elements; i++) {
      result.emplace(d_reply->element[i]->str);
    }
    return result;
  }
};

template <typename T, typename... Args>
struct RedisCommand
{
  virtual std::unique_ptr<RedisReplyInterface<T>> operator()(const RedisClient& client, const Args&... args) const = 0;
};

struct RedisGetCommand : public RedisCommand<std::string, std::string>
{
  std::unique_ptr<RedisReplyInterface<std::string>> operator()(const RedisClient& client, const std::string& key) const override;
};

struct RedisExistsCommand : public RedisCommand<bool, std::string>
{
  std::unique_ptr<RedisReplyInterface<bool>> operator()(const RedisClient& client, const std::string& key) const override;
};

struct RedisHGetCommand : public RedisCommand<std::string, std::string, std::string>
{
  std::unique_ptr<RedisReplyInterface<std::string>> operator()(const RedisClient& client, const std::string& hash_key, const std::string& key) const override;
};

struct RedisHExistsCommand : public RedisCommand<bool, std::string, std::string>
{
  std::unique_ptr<RedisReplyInterface<bool>> operator()(const RedisClient& client, const std::string& hash_key, const std::string& key) const override;
};

class RedisLookupAction
{
public:
  RedisLookupAction() {};
  virtual ~RedisLookupAction() = default;

  virtual std::unique_ptr<RedisReplyInterface<std::string>> getValue(const RedisClient& client, const std::string& key) const = 0;
  virtual std::unique_ptr<RedisReplyInterface<bool>> keyExists(const RedisClient& client, const std::string& key) const = 0;
};

class RedisGetLookupAction : public RedisLookupAction
{
public:
  RedisGetLookupAction(const std::string& prefix = "") :
    d_prefix(prefix)
  {
  }
  std::unique_ptr<RedisReplyInterface<std::string>> getValue(const RedisClient& client, const std::string& key) const override;
  std::unique_ptr<RedisReplyInterface<bool>> keyExists(const RedisClient& client, const std::string& key) const override;

private:
  std::string d_prefix;
  RedisGetCommand d_getCommand;
  RedisExistsCommand d_existsCommand;
};

class RedisHGetLookupAction : public RedisLookupAction
{
public:
  RedisHGetLookupAction(const std::string& hash_key) :
    d_hash_key(hash_key)
  {
  }
  std::unique_ptr<RedisReplyInterface<std::string>> getValue(const RedisClient& client, const std::string& key) const override;
  std::unique_ptr<RedisReplyInterface<bool>> keyExists(const RedisClient& client, const std::string& key) const override;

private:
  std::string d_hash_key;
  RedisHGetCommand d_getCommand;
  RedisHExistsCommand d_existsCommand;
};

class RedisClient
{
public:
  RedisClient(const std::string& url) :
    d_connection(url) {}

  redisReply* executeCommand(const char* format, ...) const;
  redisReply* executeCommandArgv(std::vector<std::string> args) const;

  const YaHTTP::URL& getUrl() const
  {
    return d_connection.getUrl();
  }

private:
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
      return connection->get() == nullptr || connection->get()->err != 0;
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
  virtual ~RedisKVClientInterface() = default;
  virtual bool getValue(const std::string& key, std::string& value) = 0;
  virtual bool keyExists(const std::string& key) = 0;
};

class RedisKVClient : public RedisKVClientInterface
{
public:
  RedisKVClient(const std::shared_ptr<RedisClient>& client, std::unique_ptr<RedisLookupAction> lookupAction, std::shared_ptr<RedisStats> stats) :
    d_client(client), d_lookupAction(std::move(lookupAction)), d_stats(stats)
  {
  }

  bool getValue(const std::string& key, std::string& value) override;
  bool keyExists(const std::string& key) override;

private:
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
