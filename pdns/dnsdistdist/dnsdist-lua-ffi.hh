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

#include "dnsdist.hh"
#include "protozero.hh"

extern "C"
{
#include "dnsdist-lua-ffi-interface.h"
}

#include "ext/luawrapper/include/LuaContext.hpp"

// dnsdist_ffi_dnsquestion_t is a lightuserdata
template <>
struct LuaContext::Pusher<dnsdist_ffi_dnsquestion_t*>
{
  static const int minSize = 1;
  static const int maxSize = 1;

  static PushedObject push(lua_State* state, dnsdist_ffi_dnsquestion_t* ptr) noexcept
  {
    lua_pushlightuserdata(state, ptr);
    return PushedObject{state, 1};
  }
};

struct dnsdist_ffi_dnsquestion_t
{
  dnsdist_ffi_dnsquestion_t(DNSQuestion* dq_) :
    dq(dq_)
  {
  }

  DNSQuestion* dq{nullptr};
  ComboAddress maskedRemote;
  std::string trailingData;
  std::optional<std::string> result{std::nullopt};
  std::optional<std::string> httpPath{std::nullopt};
  std::optional<std::string> httpQueryString{std::nullopt};
  std::optional<std::string> httpHost{std::nullopt};
  std::optional<std::string> httpScheme{std::nullopt};
  std::unique_ptr<std::vector<dnsdist_ffi_ednsoption_t>> ednsOptionsVect;
  std::unique_ptr<std::vector<dnsdist_ffi_http_header_t>> httpHeadersVect;
  std::unique_ptr<std::vector<dnsdist_ffi_tag_t>> tagsVect;
  std::unique_ptr<std::vector<dnsdist_ffi_proxy_protocol_value_t>> proxyProtocolValuesVect;
  std::unique_ptr<std::unordered_map<std::string, std::string>> httpHeaders;
#if !defined(DISABLE_PROTOBUF)
  protozero::pbf_writer pbfWriter;
  protozero::pbf_writer pbfMetaWriter;
  protozero::pbf_writer pbfMetaValueWriter;
#endif /* DISABLE_PROTOBUF */
};

// dnsdist_ffi_dnsresponse_t is a lightuserdata
template <>
struct LuaContext::Pusher<dnsdist_ffi_dnsresponse_t*>
{
  static const int minSize = 1;
  static const int maxSize = 1;

  static PushedObject push(lua_State* state, dnsdist_ffi_dnsresponse_t* ptr) noexcept
  {
    lua_pushlightuserdata(state, ptr);
    return PushedObject{state, 1};
  }
};

struct dnsdist_ffi_dnsresponse_t
{
  dnsdist_ffi_dnsresponse_t(DNSResponse* dr_) :
    dr(dr_)
  {
  }

  DNSResponse* dr{nullptr};
  std::optional<std::string> result{std::nullopt};
};

// dnsdist_ffi_server_t is a lightuserdata
template <>
struct LuaContext::Pusher<dnsdist_ffi_server_t*>
{
  static const int minSize = 1;
  static const int maxSize = 1;

  static PushedObject push(lua_State* state, dnsdist_ffi_server_t* ptr) noexcept
  {
    lua_pushlightuserdata(state, ptr);
    return PushedObject{state, 1};
  }
};

struct dnsdist_ffi_server_t
{
  dnsdist_ffi_server_t(const std::shared_ptr<DownstreamState>& server_) :
    server(server_)
  {
  }

  const std::shared_ptr<DownstreamState>& server;
};

// dnsdist_ffi_servers_list_t is a lightuserdata
template <>
struct LuaContext::Pusher<dnsdist_ffi_servers_list_t*>
{
  static const int minSize = 1;
  static const int maxSize = 1;

  static PushedObject push(lua_State* state, dnsdist_ffi_servers_list_t* ptr) noexcept
  {
    lua_pushlightuserdata(state, ptr);
    return PushedObject{state, 1};
  }
};

struct dnsdist_ffi_servers_list_t
{
  dnsdist_ffi_servers_list_t(const ServerPolicy::NumberedServerVector& servers_) :
    servers(servers_)
  {
    ffiServers.reserve(servers.size());
    for (const auto& server : servers) {
      ffiServers.push_back(dnsdist_ffi_server_t(server.second));
    }
  }

  std::vector<dnsdist_ffi_server_t> ffiServers;
  const ServerPolicy::NumberedServerVector& servers;
};

// dnsdist_ffi_network_message_t is a lightuserdata
template <>
struct LuaContext::Pusher<dnsdist_ffi_network_message_t*>
{
  static const int minSize = 1;
  static const int maxSize = 1;

  static PushedObject push(lua_State* state, dnsdist_ffi_network_message_t* ptr) noexcept
  {
    lua_pushlightuserdata(state, ptr);
    return PushedObject{state, 1};
  }
};

struct dnsdist_ffi_network_message_t
{
  dnsdist_ffi_network_message_t(const std::string& payload_, const std::string& from_, uint16_t endpointID_) :
    payload(payload_), from(from_), endpointID(endpointID_)
  {
  }

  const std::string& payload;
  const std::string& from;
  uint16_t endpointID;
};

const char* getLuaFFIWrappers();
void setupLuaFFIPerThreadContext(LuaContext& luaCtx);
