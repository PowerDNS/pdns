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
#include <yahttp/yahttp.hpp>

#include "dnsdist.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-web.hh"

void registerWebHandler(const std::string& endpoint, std::function<void(const YaHTTP::Request&, YaHTTP::Response&)> handler);

void setupLuaWeb(LuaContext& luaCtx)
{
  luaCtx.writeFunction("registerWebHandler", [](const std::string& path, std::function<void(const YaHTTP::Request*, YaHTTP::Response*)> handler) {
    /* LuaWrapper does a copy for objects passed by reference, so we pass a pointer */
    registerWebHandler(path, [handler](const YaHTTP::Request& req, YaHTTP::Response& resp) { handler(&req, &resp); });
  });

  luaCtx.registerMember<std::string(YaHTTP::Request::*)>("path", [](const YaHTTP::Request& req) -> std::string { return req.url.path; }, [](YaHTTP::Request& req, const std::string& path) { (void) path; });
  luaCtx.registerMember<int(YaHTTP::Request::*)>("version", [](const YaHTTP::Request& req) -> int { return req.version; }, [](YaHTTP::Request& req, int version) { (void) version; });
  luaCtx.registerMember<std::string(YaHTTP::Request::*)>("method", [](const YaHTTP::Request& req) -> std::string { return req.method; }, [](YaHTTP::Request& req, const std::string& method) { (void) method; });
  luaCtx.registerMember<std::string(YaHTTP::Request::*)>("body", [](const YaHTTP::Request& req) -> const std::string { return req.body; }, [](YaHTTP::Request& req, const std::string& body) { (void) body; });
  luaCtx.registerMember<std::unordered_map<std::string, std::string>(YaHTTP::Request::*)>("getvars", [](const YaHTTP::Request& req) {
    std::unordered_map<std::string, std::string> values;
    for (const auto& entry : req.getvars) {
      values.insert({entry.first, entry.second});
    }
    return values;
  }, [](YaHTTP::Request& req, const std::unordered_map<std::string, std::string>& values) { (void) values; });
  luaCtx.registerMember<std::unordered_map<std::string, std::string>(YaHTTP::Request::*)>("postvars", [](const YaHTTP::Request& req) {
    std::unordered_map<std::string, std::string> values;
    for (const auto& entry : req.postvars) {
      values.insert({entry.first, entry.second});
    }
    return values;
  }, [](YaHTTP::Request& req, const std::unordered_map<std::string, std::string>& values) { (void) values; });
  luaCtx.registerMember<std::unordered_map<std::string, std::string>(YaHTTP::Request::*)>("headers", [](const YaHTTP::Request& req) {
    std::unordered_map<std::string, std::string> values;
    for (const auto& entry : req.headers) {
      values.insert({entry.first, entry.second});
    }
    return values;
  }, [](YaHTTP::Request& req, const std::unordered_map<std::string, std::string>& values) { (void) values; });

  /* Response */
  luaCtx.registerMember<std::string(YaHTTP::Response::*)>("body", [](const YaHTTP::Response& resp) -> const std::string { return resp.body; }, [](YaHTTP::Response& resp, const std::string& body) { resp.body = body; });
  luaCtx.registerMember<int(YaHTTP::Response::*)>("status", [](const YaHTTP::Response& resp) -> int { return resp.status; }, [](YaHTTP::Response& resp, int status) { resp.status = status; });
  luaCtx.registerMember<std::unordered_map<std::string, std::string>(YaHTTP::Response::*)>("headers", [](const YaHTTP::Response& resp) {
    std::unordered_map<std::string, std::string> values;
    for (const auto& entry : resp.headers) {
      values.insert({entry.first, entry.second});
    }
    return values;
  }, [](YaHTTP::Response& resp, const std::unordered_map<std::string, std::string>& values) {
    resp.headers.clear();
    for (const auto& entry : values) {
      resp.headers.insert({entry.first, entry.second});
    }
  });
}

