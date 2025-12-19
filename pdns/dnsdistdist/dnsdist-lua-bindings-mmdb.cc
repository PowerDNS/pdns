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

    auto mmdb = std::shared_ptr<MMDB>(new MMDB(name, mmap ? "mmap" : ""));

    return mmdb;
  });

  luaCtx.registerFunction<std::optional<std::string> (std::shared_ptr<MMDB>::*)(const ComboAddress&)>("queryCountry", [](std::shared_ptr<MMDB>& mmdb, const ComboAddress& ip) {
    std::optional<std::string> result{std::nullopt};
    if (!mmdb) {
      return result;
    }

    std::string value;
    if (mmdb->queryCountry(value, ip)) {
      result = value;
    }

    return result;
  });

  luaCtx.registerFunction<std::optional<std::string> (std::shared_ptr<MMDB>::*)(const ComboAddress&)>("queryContinent", [](std::shared_ptr<MMDB>& mmdb, const ComboAddress& ip) {
    std::optional<std::string> result{std::nullopt};
    if (!mmdb) {
      return result;
    }

    std::string value;
    if (mmdb->queryContinent(value, ip)) {
      result = value;
    }

    return result;
  });

  luaCtx.registerFunction<std::optional<std::string> (std::shared_ptr<MMDB>::*)(const ComboAddress&)>("queryAS", [](std::shared_ptr<MMDB>& mmdb, const ComboAddress& ip) {
    std::optional<std::string> result{std::nullopt};
    if (!mmdb) {
      return result;
    }

    std::string value;
    if (mmdb->queryAS(value, ip)) {
      result = value;
    }

    return result;
  });

  luaCtx.registerFunction<std::optional<std::string> (std::shared_ptr<MMDB>::*)(const ComboAddress&)>("queryASN", [](std::shared_ptr<MMDB>& mmdb, const ComboAddress& ip) {
    std::optional<std::string> result{std::nullopt};
    if (!mmdb) {
      return result;
    }

    std::string value;
    if (mmdb->queryASN(value, ip)) {
      result = value;
    }

    return result;
  });

  luaCtx.registerFunction<std::optional<std::string> (std::shared_ptr<MMDB>::*)(const ComboAddress&)>("queryRegion", [](std::shared_ptr<MMDB>& mmdb, const ComboAddress& ip) {
    std::optional<std::string> result{std::nullopt};
    if (!mmdb) {
      return result;
    }

    std::string value;
    if (mmdb->queryRegion(value, ip)) {
      result = value;
    }

    return result;
  });

  luaCtx.registerFunction<std::optional<std::string> (std::shared_ptr<MMDB>::*)(const ComboAddress&, const std::string&)>("queryCity", [](std::shared_ptr<MMDB>& mmdb, const ComboAddress& ip, const std::string& language) {
    std::optional<std::string> result{std::nullopt};
    if (!mmdb) {
      return result;
    }

    std::string value;
    if (mmdb->queryCity(value, ip, language)) {
      result = value;
    }

    return result;
  });

  luaCtx.registerFunction<std::optional<std::tuple<double, double, int>> (std::shared_ptr<MMDB>::*)(const ComboAddress&)>("queryLocation", [](std::shared_ptr<MMDB>& mmdb, const ComboAddress& ip) {
    std::optional<std::tuple<double, double, int>> result{std::nullopt};
    if (!mmdb) {
      return result;
    }

    double lat;
    double lon;
    int prec;
    if (mmdb->queryLocation(lat, lon, prec, ip)) {
      result = {lat, lon, prec};
    }

    return result;
  });
#endif
}
