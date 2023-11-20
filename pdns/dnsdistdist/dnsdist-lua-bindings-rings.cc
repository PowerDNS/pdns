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
#include "dnsdist-rings.hh"
#include "dnsdist-lua.hh"

#ifndef DISABLE_LUA_BINDINGS_RINGS
struct LuaRingEntry
{
  DNSName qname;
  ComboAddress requestor;
  ComboAddress ds;
  struct timespec when;
  std::string macAddr;
  struct dnsheader dh;
  unsigned int usec;
  unsigned int size;
  uint16_t qtype;
  dnsdist::Protocol protocol;
  bool isResponse;
};

template <typename T>
static void addRingEntryToList(LuaArray<LuaRingEntry>& list, const T& entry)
{
  constexpr bool response = std::is_same_v<T, Rings::Response>;
  if constexpr (!response) {
#if defined(DNSDIST_RINGS_WITH_MACADDRESS)
    list.emplace_back(list.size() + 1, LuaRingEntry{entry.name, entry.requestor, ComboAddress(), entry.when, entry.hasmac ? std::string(reinterpret_cast<const char*>(entry.macaddress.data()), entry.macaddress.size()) : std::string(), entry.dh, 0U, entry.size, entry.qtype, entry.protocol, false});
#else
    list.emplace_back(list.size() + 1, LuaRingEntry{entry.name, entry.requestor, ComboAddress(), entry.when, std::string(), entry.dh, 0U, entry.size, entry.qtype, entry.protocol, false});
#endif
  }
  else {
    list.emplace_back(list.size() + 1, LuaRingEntry{entry.name, entry.requestor, entry.ds, entry.when, std::string(), entry.dh, entry.usec, entry.size, entry.qtype, entry.protocol, true});
  }
}

#endif /* DISABLE_LUA_BINDINGS_RINGS */

void setupLuaBindingsRings(LuaContext& luaCtx, bool client)
{
#ifndef DISABLE_LUA_BINDINGS_RINGS
  luaCtx.writeFunction("getRingEntries", [client]() {
    LuaArray<LuaRingEntry> results;

    if (client) {
      return results;
    }

    for (const auto& shard : g_rings.d_shards) {
      {
        auto ql = shard->queryRing.lock();
        for (const auto& entry : *ql) {
          addRingEntryToList(results, entry);
        }
      }
      {
        auto rl = shard->respRing.lock();
        for (const auto& entry : *rl) {
          addRingEntryToList(results, entry);
        }
      }
    }

    return results;
  });

  luaCtx.registerMember<DNSName(LuaRingEntry::*)>(std::string("qname"), [](const LuaRingEntry& entry) -> const DNSName& {
    return entry.qname;
  });

  luaCtx.registerMember<ComboAddress(LuaRingEntry::*)>(std::string("requestor"), [](const LuaRingEntry& entry) -> const ComboAddress& {
    return entry.requestor;
  });

  luaCtx.registerMember<ComboAddress(LuaRingEntry::*)>(std::string("backend"), [](const LuaRingEntry& entry) -> const ComboAddress& {
    return entry.ds;
  });

  luaCtx.registerMember<timespec(LuaRingEntry::*)>(std::string("when"), [](const LuaRingEntry& entry) {
    return entry.when;
  });

  luaCtx.registerMember<std::string(LuaRingEntry::*)>(std::string("macAddress"), [](const LuaRingEntry& entry) -> const std::string& {
    return entry.macAddr;
  });

  luaCtx.registerMember<dnsheader(LuaRingEntry::*)>(std::string("dnsheader"), [](const LuaRingEntry& entry) {
    return entry.dh;
  });

  luaCtx.registerMember<unsigned int(LuaRingEntry::*)>(std::string("usec"), [](const LuaRingEntry& entry) {
    return entry.usec;
  });

  luaCtx.registerMember<unsigned int(LuaRingEntry::*)>(std::string("size"), [](const LuaRingEntry& entry) {
    return entry.size;
  });

  luaCtx.registerMember<uint16_t(LuaRingEntry::*)>(std::string("qtype"), [](const LuaRingEntry& entry) {
    return entry.qtype;
  });

  luaCtx.registerMember<std::string(LuaRingEntry::*)>(std::string("protocol"), [](const LuaRingEntry& entry) {
    return entry.protocol.toString();
  });

  luaCtx.registerMember<bool(LuaRingEntry::*)>(std::string("isResponse"), [](const LuaRingEntry& entry) {
    return entry.isResponse;
  });

  luaCtx.registerMember<int64_t(timespec::*)>(std::string("tv_sec"), [](const timespec& ts) {
    return ts.tv_sec;
  });

  luaCtx.registerMember<uint64_t(timespec::*)>(std::string("tv_nsec"), [](const timespec& ts) {
    return ts.tv_nsec;
  });

#endif /* DISABLE_LUA_BINDINGS_RINGS */
}
