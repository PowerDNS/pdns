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
#include "dnsdist-lua.hh"
#include <memory>
#include "redis.hh"

void setupLuaBindingsRedis([[maybe_unused]] LuaContext& luaCtx, [[maybe_unused]] bool client)
{
#ifdef HAVE_REDIS
  luaCtx.writeFunction("newRedisClient", [client](const std::string& url) {
    if (client) {
      return std::shared_ptr<RedisClient>(nullptr);
    }

    return std::make_shared<RedisClient>(url);
  });

  luaCtx.registerFunction<std::string (std::shared_ptr<RedisClient>::*)(const std::string&)>("get", [](std::shared_ptr<RedisClient>& rc, const std::string& key) {
    std::string result;
    if (!rc) {
      return result;
    }

    auto reply = RedisGetCommand{}(*rc, key);

    if (reply->ok()) {
      result = reply->getValue();
    }

    return result;
  });

  luaCtx.registerFunction<bool (std::shared_ptr<RedisClient>::*)(const std::string&)>("exists", [](std::shared_ptr<RedisClient>& rc, const std::string& key) {
    if (!rc) {
      return false;
    }

    auto reply = RedisExistsCommand{}(*rc, key);

    if (reply->ok()) {
      return reply->getValue();
    }

    return false;
  });

  luaCtx.registerFunction<std::string (std::shared_ptr<RedisClient>::*)(const std::string&, const std::string&)>("hget", [](std::shared_ptr<RedisClient>& rc, const std::string& hash_key, const std::string& key) {
    std::string result;
    if (!rc) {
      return result;
    }

    auto reply = RedisHGetCommand{}(*rc, hash_key, key);

    if (reply->ok()) {
      result = reply->getValue();
    }

    return result;
  });

  luaCtx.registerFunction<bool (std::shared_ptr<RedisClient>::*)(const std::string&, const std::string&)>("hexists", [](std::shared_ptr<RedisClient>& rc, const std::string& hash_key, const std::string& key) {
    if (!rc) {
      return false;
    }

    auto reply = RedisHExistsCommand{}(*rc, hash_key, key);

    if (reply->ok()) {
      return reply->getValue();
    }

    return false;
  });
#endif /* HAVE_REDIS */
}
