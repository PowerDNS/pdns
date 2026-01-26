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
#include "dnsdist-kvs.hh"
#include "dnsdist-lua.hh"

void setupLuaBindingsKVS([[maybe_unused]] LuaContext& luaCtx, [[maybe_unused]] bool client)
{
#ifdef HAVE_LMDB
  luaCtx.writeFunction("newLMDBKVStore", [client](const std::string& fname, const std::string& dbName, std::optional<bool> noLock) {
    if (client) {
      return std::shared_ptr<KeyValueStore>(nullptr);
    }
    return std::shared_ptr<KeyValueStore>(new LMDBKVStore(fname, dbName, noLock ? *noLock : false));
  });
#endif /* HAVE_LMDB */

#ifdef HAVE_CDB
  luaCtx.writeFunction("newCDBKVStore", [client](const std::string& fname, time_t refreshDelay) {
    if (client) {
      return std::shared_ptr<KeyValueStore>(nullptr);
    }
    return std::shared_ptr<KeyValueStore>(new CDBKVStore(fname, refreshDelay));
  });
#endif /* HAVE_CDB */

#if defined(HAVE_LMDB) || defined(HAVE_CDB)
  /* Key Value Store objects */
  luaCtx.writeFunction("KeyValueLookupKeySourceIP", [](std::optional<uint8_t> v4Mask, std::optional<uint8_t> v6Mask, std::optional<bool> includePort) {
    return std::shared_ptr<KeyValueLookupKey>(new KeyValueLookupKeySourceIP(v4Mask ? *v4Mask : 32, v6Mask ? *v6Mask : 128, includePort ? *includePort : false));
  });
  luaCtx.writeFunction("KeyValueLookupKeyQName", [](std::optional<bool> wireFormat) {
    return std::shared_ptr<KeyValueLookupKey>(new KeyValueLookupKeyQName(wireFormat ? *wireFormat : true));
  });
  luaCtx.writeFunction("KeyValueLookupKeySuffix", [](std::optional<size_t> minLabels, std::optional<bool> wireFormat) {
    return std::shared_ptr<KeyValueLookupKey>(new KeyValueLookupKeySuffix(minLabels ? *minLabels : 0, wireFormat ? *wireFormat : true));
  });
  luaCtx.writeFunction("KeyValueLookupKeyTag", [](const std::string& tag) {
    return std::shared_ptr<KeyValueLookupKey>(new KeyValueLookupKeyTag(tag));
  });

  luaCtx.registerFunction<std::string (std::shared_ptr<KeyValueStore>::*)(const boost::variant<ComboAddress, DNSName, std::string>, std::optional<bool> wireFormat)>("lookup", [](std::shared_ptr<KeyValueStore>& kvs, const boost::variant<ComboAddress, DNSName, std::string> keyVar, std::optional<bool> wireFormat) {
    std::string result;
    if (!kvs) {
      return result;
    }

    if (keyVar.type() == typeid(ComboAddress)) {
      const auto ca = boost::get<ComboAddress>(&keyVar);
      KeyValueLookupKeySourceIP lookup(32, 128, false);
      for (const auto& key : lookup.getKeys(*ca)) {
        if (kvs->getValue(key, result)) {
          return result;
        }
      }
    }
    else if (keyVar.type() == typeid(DNSName)) {
      const DNSName* dn = boost::get<DNSName>(&keyVar);
      KeyValueLookupKeyQName lookup(wireFormat ? *wireFormat : true);
      for (const auto& key : lookup.getKeys(*dn)) {
        if (kvs->getValue(key, result)) {
          return result;
        }
      }
    }
    else if (keyVar.type() == typeid(std::string)) {
      const std::string* keyStr = boost::get<std::string>(&keyVar);
      kvs->getValue(*keyStr, result);
    }

    return result;
  });

  luaCtx.registerFunction<std::string (std::shared_ptr<KeyValueStore>::*)(const DNSName&, std::optional<size_t> minLabels, std::optional<bool> wireFormat)>("lookupSuffix", [](std::shared_ptr<KeyValueStore>& kvs, const DNSName& lookupKey, std::optional<size_t> minLabels, std::optional<bool> wireFormat) {
    std::string result;
    if (!kvs) {
      return result;
    }

    KeyValueLookupKeySuffix lookup(minLabels ? *minLabels : 0, wireFormat ? *wireFormat : true);
    for (const auto& key : lookup.getKeys(lookupKey)) {
      if (kvs->getValue(key, result)) {
        return result;
      }
    }

    return result;
  });

  luaCtx.registerFunction<bool (std::shared_ptr<KeyValueStore>::*)()>("reload", [](std::shared_ptr<KeyValueStore>& kvs) {
    if (!kvs) {
      return false;
    }

    return kvs->reload();
  });
#endif /* defined(HAVE_LMDB) || defined(HAVE_CDB) */
}
