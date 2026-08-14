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

std::unique_ptr<RedisReplyInterface<std::vector<std::pair<int, std::optional<std::string>>>>> RedisHMGetCommand::operator()(const RedisClient& client, const std::string& hash_key, const std::vector<std::pair<int, std::string>>& fields) const
{

  std::vector<std::string> command;
  command.emplace_back("HMGET");
  command.emplace_back(hash_key);
  for (const auto& field : fields) {
    command.push_back(field.second);
  }

  return std::make_unique<RedisArrayReply>(client.executeCommandArgv(command));
}

std::unique_ptr<RedisReplyInterface<bool>> RedisHExistsCommand::operator()(const RedisClient& client, const std::string& hash_key, const std::string& key) const
{
  return std::make_unique<RedisIntAsBoolReply>(std::make_unique<RedisIntReply>(client.executeCommand("HEXISTS %b %b", hash_key.data(), hash_key.length(), key.data(), key.length())));
}

std::unique_ptr<RedisReplyInterface<bool>> RedisSIsMemberCommand::operator()(const RedisClient& client, const std::string& set_key, const std::string& key) const
{
  auto reply = client.executeCommand("SISMEMBER %b %b", set_key.data(), set_key.length(), key.data(), key.length());
  if (reply != nullptr) {
  }
  return std::make_unique<RedisIntAsBoolReply>(std::make_unique<RedisIntReply>(reply));
}

std::unique_ptr<RedisReplyInterface<std::optional<LuaAny>>> RedisRawCommand::operator()(const RedisClient& client, const LuaArray<std::string>& raw_command) const
{
  std::vector<std::string> command{raw_command.size()};
  for (size_t i = 0; i < raw_command.size(); ++i) {
    command[i] = raw_command[i].second;
  }

  std::string joinedString = boost::algorithm::join(command, ",");

  return std::make_unique<RedisRawReply>(client.executeCommandArgv(command));
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

std::unique_ptr<RedisReplyInterface<std::string>> RedisSIsMemberLookupAction::getValue(const RedisClient& client, const std::string& key) const
{
  return std::make_unique<RedisBoolAsStringReply>(d_sIsMemberCommand(client, d_set_key, key));
}

std::unique_ptr<RedisReplyInterface<bool>> RedisSIsMemberLookupAction::keyExists(const RedisClient& client, const std::string& key) const
{
  return d_sIsMemberCommand(client, d_set_key, key);
}

std::unique_ptr<RedisReplyInterface<std::string>> RedisRawLookupAction::getValue(const RedisClient& client, const std::string& key) const
{
  LuaArray<std::string> args(std::max(d_keyArgPos + 1, d_args.size()));
  for (size_t i = 0; i < d_args.size(); ++i) {
    if (i == d_keyArgPos) {
      auto insertedKey = d_args[i];
      insertedKey.replace(d_keyArgPosInString, size_t(2), key);
      args[i] = {i + 1, insertedKey};
    }
    else {
      args[i] = {i + 1, d_args[i]};
    }
  }
  if (d_keyArgPos >= d_args.size()) {
    args[d_keyArgPos] = {d_keyArgPos + 1, key};
  }
  return std::make_unique<RedisRawAsStringReply>(d_rawCommand(client, args));
}

std::unique_ptr<RedisReplyInterface<bool>> RedisRawLookupAction::keyExists(const RedisClient& client, const std::string& key) const
{
  LuaArray<std::string> args(std::max(d_keyArgPosInExists + 1, d_existsArgs.size()));
  for (size_t i = 0; i < d_existsArgs.size(); ++i) {
    if (i == d_keyArgPosInExists) {
      auto insertedKey = d_existsArgs[i];
      insertedKey.replace(d_keyArgPosInExistsInString, size_t(2), key);
      args[i] = {i + 1, insertedKey};
    }
    else {
      args[i] = {i + 1, d_existsArgs[i]};
    }
  }
  if (d_keyArgPosInExists >= d_existsArgs.size()) {
    args[d_keyArgPosInExists] = {d_keyArgPosInExists + 1, key};
  }
  return std::make_unique<RedisRawAsBoolReply>(d_rawCommand(client, args));
}

std::shared_ptr<const Logr::Logger> RedisClient::getLogger() const
{
  return dnsdist::logging::getTopLogger("redis")->withValues("url", Logging::Loggable(d_connection.getUrl()));
}

redisReply* RedisClient::executeCommand(const char* format, ...) const
{
  va_list ap;
  va_start(ap, format);
  auto connection = d_connection.getConnection();
  auto* result = static_cast<redisReply*>(redisvCommand(connection->get(), format, ap));
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
  for (auto& arg : args) {
    argv.push_back(arg.data());
    argvlen.push_back(arg.length());
  }
  auto connection = d_connection.getConnection();
  auto* result = static_cast<redisReply*>(redisCommandArgv(connection->get(), args.size(), argv.data(), argvlen.data()));
  if (connection->get()->err != 0) {
    VERBOSESLOG(infolog("Redis connection error %s", connection->get()->errstr),
                getLogger()->error(Logr::Info, connection->get()->errstr, "Redis connection error"));
  }
  return result;
};

std::shared_ptr<const Logr::Logger> RedisKVClient::getLogger() const
{
  return dnsdist::logging::getTopLogger("redis")->withValues("url", Logging::Loggable(d_client->getUrl()));
}

bool RedisKVClient::getValue(const std::string& key, std::string& value)
{
  auto reply = d_lookupAction->getValue(*d_client, key);

  if (reply->ok()) {
    value = reply->getValue();
    d_stats->d_successfulRequests += 1;
    return true;
  }

  VERBOSESLOG(infolog("Error while looking up key '%s' from Redis: %s", key, reply->getError()),
              getLogger()->error(Logr::Info, reply->getError(), "Error while loking up key from Redis", "key", Logging::Loggable(key)));
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

  VERBOSESLOG(infolog("Error while looking up key '%s' from Redis: %s", key, reply->getError()),
              getLogger()->error(Logr::Info, reply->getError(), "Error while loking up key from Redis", "key", Logging::Loggable(key)));
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
  if (parsed.host.empty()) {
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
  if (context == nullptr || (context->err != 0)) {
    if (context != nullptr) {
      auto logger = dnsdist::logging::getTopLogger("redis")->withValues("url", Logging::Loggable(url));
      SLOG(warnlog("Error connecting to redis: %s", context->errstr),
           logger->error(Logr::Warning, context->errstr, "Error connecting to redis"));
    }
    else {
      auto logger = dnsdist::logging::getTopLogger("redis")->withValues("url", Logging::Loggable(url));
      SLOG(warnlog("Can't allocate redis context"),
           logger->info(Logr::Warning, "Can't allocate redis context"));
    }
  }

  *(d_context.lock()) = std::move(context);
}

bool RedisClient::RedisConnection::reconnect()
{
  {
    auto context = d_context.read_only_lock();
    if (*context != nullptr) {
      int result = redisReconnect(context->get());
      return result == REDIS_OK;
    }
  }

  auto context = std::unique_ptr<redisContext, decltype(&redisFree)>(redisConnect(d_url.host.c_str(), d_url.port), redisFree);
  // Check if the context is null or if a specific
  // error occurred.
  if (context == nullptr || (context->err != 0)) {
    if (context != nullptr) {
      warnlog("Error connecting to redis: %s", context->errstr);
      return false;
    }
    warnlog("Can't allocate redis context");
    return false;
  }

  *(d_context.lock()) = std::move(context);
  return true;
}
#endif
