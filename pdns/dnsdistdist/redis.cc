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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_REDIS
#include "gettime.hh"
#include "threadname.hh"
#include <condition_variable>
#include <memory>
#include <stdexcept>

#include "redis.hh"
#include "dolog.hh"
#include <hiredis/hiredis.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

std::unique_ptr<RedisReplyInterface<std::string>> RedisGetCommand::operator()(const RedisClient& client, const std::string& key) const
{
  return std::make_unique<RedisStringReply>(client.executeCommand("GET %b", key.data(), key.length()));
}

std::unique_ptr<RedisReplyInterface<bool>> RedisExistsCommand::operator()(const RedisClient& client, const std::string& key) const
{
  return std::make_unique<RedisIntAsBoolReply>(std::make_unique<RedisIntReply>(client.executeCommand("EXISTS %b", key.data(), key.length())));
}

std::unique_ptr<RedisReplyInterface<std::string>> RedisHGetCommand::operator()(const RedisClient& client, const std::string& hash_key, const std::string& key) const
{
  return std::make_unique<RedisStringReply>(client.executeCommand("HGET %b %b", hash_key.data(), hash_key.length(), key.data(), key.length()));
}

std::unique_ptr<RedisReplyInterface<bool>> RedisHExistsCommand::operator()(const RedisClient& client, const std::string& hash_key, const std::string& key) const
{
  return std::make_unique<RedisIntAsBoolReply>(std::make_unique<RedisIntReply>(client.executeCommand("HEXISTS %b %b", hash_key.data(), hash_key.length(), key.data(), key.length())));
}

std::unique_ptr<RedisReplyInterface<std::string>> RedisGetLookupAction::getValue(const RedisClient& client, const std::string& key) const
{
  return d_getCommand(client, d_prefix + key);
}

std::unique_ptr<RedisReplyInterface<bool>> RedisGetLookupAction::keyExists(const RedisClient& client, const std::string& key) const
{
  return d_existsCommand(client, d_prefix + key);
}

std::unique_ptr<RedisReplyInterface<std::string>> RedisHGetLookupAction::getValue(const RedisClient& client, const std::string& key) const
{
  return d_getCommand(client, d_hash_key, key);
}

std::unique_ptr<RedisReplyInterface<bool>> RedisHGetLookupAction::keyExists(const RedisClient& client, const std::string& key) const
{
  return d_existsCommand(client, d_hash_key, key);
}

redisReply* RedisClient::executeCommand(const char* format, ...) const
{
  va_list ap;
  va_start(ap, format);
  auto connection = d_connection.getConnection();
  auto result = static_cast<redisReply*>(redisvCommand(connection->get(), format, ap));
  if (connection->get()->err != 0) {
    vinfolog("Redis connection error %s", connection->get()->errstr);
  }
  va_end(ap);
  return result;
};

redisReply* RedisClient::executeCommandArgv(std::vector<std::string> args) const
{
  std::vector<const char*> argv;
  std::vector<size_t> argvlen;
  for (size_t i = 0; i < args.size(); ++i) {
    argv.push_back(args[i].data());
    argvlen.push_back(args[i].length());
  }
  auto connection = d_connection.getConnection();
  auto result = static_cast<redisReply*>(redisCommandArgv(connection->get(), args.size(), argv.data(), argvlen.data()));
  if (connection->get()->err != 0) {
    vinfolog("Redis connection error %s", connection->get()->errstr);
  }
  return result;
};

bool RedisKVClient::getValue(const std::string& key, std::string& value)
{
  auto reply = d_lookupAction->getValue(*d_client, key);

  if (reply->ok()) {
    value = reply->getValue();
    d_stats->d_successfulRequests += 1;
    return true;
  }

  vinfolog("Error while looking up key '%s' from Redis: %s", key, reply->getError());
  d_stats->d_errors += 1;
  return false;
}

bool RedisKVClient::keyExists(const std::string& key)
{
  auto reply = d_lookupAction->keyExists(*d_client, key);
  if (reply->ok()) {
    d_stats->d_successfulRequests += 1;
    return reply->getValue();
  }

  vinfolog("Error while looking up key '%s' from Redis: %s", key, reply->getError());
  d_stats->d_errors += 1;
  return false;
}

namespace
{
void validateRedisUrl(const YaHTTP::URL& parsed, const std::string& url)
{
  if (parsed.protocol.empty() || (parsed.protocol != "redis" && parsed.protocol != "rediss")) {
    throw std::runtime_error("Invalid redis URL: " + url + " - Invalid protocol! Use redis or rediss.");
  }
  else if (parsed.host.empty()) {
    throw std::runtime_error("Invalid redis URL: " + url + " - Host empty.");
  }
}
}

RedisClient::RedisConnection::RedisConnection(const std::string& url)
{
  auto parsed = YaHTTP::URL();
  if (!parsed.parse(url)) {
    validateRedisUrl(parsed, url);
  }

  validateRedisUrl(parsed, url);
  d_url = parsed;

  if (parsed.port == 0) {
    parsed.port = 6379;
  }
  auto context = std::unique_ptr<redisContext, decltype(&redisFree)>(redisConnect(parsed.host.c_str(), parsed.port), redisFree);
  // Check if the context is null or if a specific
  // error occurred.
  if (context == nullptr || context->err) {
    if (context != nullptr) {
      warnlog("Error connecting to redis: %s", context->errstr);
    }
    else {
      warnlog("Can't allocate redis context");
    }
  }

  *(d_context.lock()) = std::move(context);
}

bool RedisClient::RedisConnection::reconnect()
{
  {
    auto context = d_context.read_only_lock();
    if (context->get() != nullptr) {
      int result = redisReconnect(context->get());
      return result == REDIS_OK;
    }
  }

  auto context = std::unique_ptr<redisContext, decltype(&redisFree)>(redisConnect(d_url.host.c_str(), d_url.port), redisFree);
  // Check if the context is null or if a specific
  // error occurred.
  if (context == nullptr || context->err) {
    if (context != nullptr) {
      warnlog("Error connecting to redis: %s", context->errstr);
      return false;
    }
    else {
      warnlog("Can't allocate redis context");
      return false;
    }
  }

  *(d_context.lock()) = std::move(context);
  return true;
}
#endif
