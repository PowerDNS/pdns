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
#include "dnsdist.hh"
#include "dnsdist-async.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-lua-ffi.hh"
#include "dnsdist-lua-network.hh"
#include "dolog.hh"

void setupLuaBindingsNetwork(LuaContext& luaCtx, bool client)
{
  luaCtx.writeFunction("newNetworkEndpoint", [client](const std::string& path) {
    if (client) {
      return std::shared_ptr<dnsdist::NetworkEndpoint>(nullptr);
    }

    try {
      return std::make_shared<dnsdist::NetworkEndpoint>(path);
    }
    catch (const std::exception& e) {
      SLOG(warnlog("Error connecting to network endpoint: %s", e.what()),
           dnsdist::logging::getTopLogger()->error(Logr::Error, e.what(), "Error connecting to network endpoint"));
    }
    return std::shared_ptr<dnsdist::NetworkEndpoint>(nullptr);
  });

  luaCtx.registerFunction<bool (std::shared_ptr<dnsdist::NetworkEndpoint>::*)() const>("isValid", [](const std::shared_ptr<dnsdist::NetworkEndpoint>& endpoint) {
    return endpoint != nullptr;
  });

  luaCtx.registerFunction<bool (std::shared_ptr<dnsdist::NetworkEndpoint>::*)(const std::string&) const>("send", [client](const std::shared_ptr<dnsdist::NetworkEndpoint>& endpoint, const std::string& payload) {
    if (client || !endpoint || payload.empty()) {
      return false;
    }

    return endpoint->send(payload);
  });

  luaCtx.writeFunction("newNetworkListener", [client]() {
    if (client) {
      return std::shared_ptr<dnsdist::NetworkListener>(nullptr);
    }

    return std::make_shared<dnsdist::NetworkListener>();
  });

  luaCtx.registerFunction<bool (std::shared_ptr<dnsdist::NetworkListener>::*)(const std::string&, uint16_t, std::function<void(uint16_t, std::string& dgram, const std::string& from)>)>("addUnixListeningEndpoint", [client](std::shared_ptr<dnsdist::NetworkListener>& listener, const std::string& path, uint16_t endpointID, std::function<void(uint16_t endpoint, std::string& dgram, const std::string& from)> cb) {
    if (client || !cb) {
      return false;
    }

    return listener->addUnixListeningEndpoint(path, endpointID, [cb = std::move(cb)](dnsdist::NetworkListener::EndpointID endpoint, std::string&& dgram, const std::string& from) {
      {
        auto lock = g_lua.lock();
        cb(endpoint, dgram, from);
      }
      dnsdist::handleQueuedAsynchronousEvents();
    });
  });

  // if you make the dnsdist_ffi_network_message_t* in the function prototype const, LuaWrapper will stop treating it like a lightuserdata, messing everything up!!
  luaCtx.registerFunction<bool (std::shared_ptr<dnsdist::NetworkListener>::*)(const std::string&, uint16_t, std::function<void(dnsdist_ffi_network_message_t*)>)>("addUnixListeningEndpointFFI", [client](std::shared_ptr<dnsdist::NetworkListener>& listener, const std::string& path, uint16_t endpointID, std::function<void(dnsdist_ffi_network_message_t*)> cb) {
    if (client) {
      return false;
    }

    return listener->addUnixListeningEndpoint(path, endpointID, [cb](dnsdist::NetworkListener::EndpointID endpoint, std::string&& dgram, const std::string& from) {
      {
        auto lock = g_lua.lock();
        dnsdist_ffi_network_message_t msg(dgram, from, endpoint);
        cb(&msg);
      }
      dnsdist::handleQueuedAsynchronousEvents();
    });
  });

  luaCtx.registerFunction<void (std::shared_ptr<dnsdist::NetworkListener>::*)()>("start", [client](std::shared_ptr<dnsdist::NetworkListener>& listener) {
    if (client) {
      return;
    }

    listener->start();
  });

  luaCtx.writeFunction("getResolvers", [](const std::string& resolvConfPath) -> LuaArray<std::string> {
    auto resolvers = getResolvers(resolvConfPath);
    LuaArray<std::string> result;
    result.reserve(resolvers.size());
    int counter = 1;
    for (const auto& resolver : resolvers) {
      result.emplace_back(counter, resolver.toString());
      counter++;
    }
    return result;
  });
};
