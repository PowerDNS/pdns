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
#include "dnsdist-lua-types.hh"
#include "dnsdist-lua.hh"
#include "iputils.hh"
#include <memory>
#ifdef HAVE_MMDB
#include "mmdb.hh"
#endif

void setupLuaBindingsMMDB([[maybe_unused]] LuaContext& luaCtx)
{
#ifdef HAVE_MMDB
  luaCtx.writeFunction("openMMDB", [](const std::string& name, std::optional<LuaAssociativeTable<boost::variant<bool>>> vars) {
    bool mmap{false};
    getOptionalValue<bool>(vars, "mmap", mmap);

    auto mmdb = std::make_shared<MMDB>(name, mmap ? "mmap" : "");

    return mmdb;
  });

  luaCtx.registerFunction<std::optional<LuaAny> (std::shared_ptr<MMDB>::*)(const LuaTypeOrArrayOf<std::string>&, const boost::variant<ComboAddress, std::string>)>("query", [](std::shared_ptr<MMDB>& mmdb, const LuaTypeOrArrayOf<std::string>& queryParams, const boost::variant<ComboAddress, std::string>& ip) {
    std::optional<LuaAny> result{std::nullopt};
    if (!mmdb) {
      return result;
    }

    LuaAny value{false};

    ComboAddress queryIp;
    if (const auto str = boost::get<std::string>(&ip)) {
      queryIp = ComboAddress(*str);
    }
    else if (const auto addr = boost::get<ComboAddress>(&ip)) {
      queryIp = *addr;
    }
    else {
      return result;
    }

    if (mmdb->query(value, MMDB::convertParams(queryParams), queryIp)) {
      result = value;
    }

    return result;
  });

  luaCtx.registerFunction<bool (std::shared_ptr<MMDB>::*)(const boost::variant<ComboAddress, std::string>)>("exists", [](std::shared_ptr<MMDB>& mmdb, const boost::variant<ComboAddress, std::string>& ip) {
    bool result = false;
    if (!mmdb) {
      return result;
    }

    if (const auto str = boost::get<std::string>(&ip)) {
      return mmdb->exists(ComboAddress(*str));
    }
    else if (const auto addr = boost::get<ComboAddress>(&ip)) {
      return mmdb->exists(*addr);
    }
    return false;
  });
#endif
}
