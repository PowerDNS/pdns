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

void setupLuaBindingsKVS(bool client)
{
  /* Key Value Store objects */
  g_lua.writeFunction("KeyValueLookupKeySourceIP", []() {
    return std::shared_ptr<KeyValueLookupKey>(new KeyValueLookupKeySourceIP());
  });
  g_lua.writeFunction("KeyValueLookupKeyQName", [](boost::optional<bool> wireFormat) {
    return std::shared_ptr<KeyValueLookupKey>(new KeyValueLookupKeyQName(wireFormat ? *wireFormat : true));
  });
  g_lua.writeFunction("KeyValueLookupKeySuffix", [](boost::optional<size_t> minLabels, boost::optional<bool> wireFormat) {
    return std::shared_ptr<KeyValueLookupKey>(new KeyValueLookupKeySuffix(minLabels ? *minLabels : 0, wireFormat ? *wireFormat : true));
  });
  g_lua.writeFunction("KeyValueLookupKeyTag", [](const std::string& tag) {
    return std::shared_ptr<KeyValueLookupKey>(new KeyValueLookupKeyTag(tag));
  });

#ifdef HAVE_LMDB
  g_lua.writeFunction("newLMDBKVStore", [client](const std::string& fname, const std::string& dbName) {
    if (client) {
      return std::shared_ptr<KeyValueStore>(nullptr);
    }
    return std::shared_ptr<KeyValueStore>(new LMDBKVStore(fname, dbName));
  });
#endif /* HAVE_LMDB */

#ifdef HAVE_CDB
  g_lua.writeFunction("newCDBKVStore", [client](const std::string& fname, time_t refreshDelay) {
    if (client) {
      return std::shared_ptr<KeyValueStore>(nullptr);
    }
    return std::shared_ptr<KeyValueStore>(new CDBKVStore(fname, refreshDelay));
  });
#endif /* HAVE_CDB */

  g_lua.registerFunction<std::string(std::shared_ptr<KeyValueStore>::*)(const boost::variant<ComboAddress, DNSName, std::string>, boost::optional<bool> wireFormat)>("lookup", [](std::shared_ptr<KeyValueStore>& kvs, const boost::variant<ComboAddress, DNSName, std::string> keyVar, boost::optional<bool> wireFormat) {
    std::string result;
    if (!kvs) {
      return result;
    }

    if (keyVar.type() == typeid(ComboAddress)) {
      const auto ca = *boost::get<ComboAddress>(&keyVar);
      KeyValueLookupKeySourceIP lookup;
      for (const auto& key : lookup.getKeys(ca)) {
        if (kvs->getValue(key, result)) {
          return result;
        }
      }
    }
    else if (keyVar.type() == typeid(DNSName)) {
      DNSName dn = *boost::get<DNSName>(&keyVar);
      KeyValueLookupKeyQName lookup(wireFormat ? *wireFormat : true);
      for (const auto& key : lookup.getKeys(dn)) {
        if (kvs->getValue(key, result)) {
          return result;
        }
      }
    }
    else if (keyVar.type() == typeid(std::string)) {
      std::string keyStr = *boost::get<std::string>(&keyVar);
      kvs->getValue(keyStr, result);
    }

    return result;
  });

  g_lua.registerFunction<std::string(std::shared_ptr<KeyValueStore>::*)(const DNSName&, boost::optional<size_t> minLabels, boost::optional<bool> wireFormat)>("lookupSuffix", [](std::shared_ptr<KeyValueStore>& kvs, const DNSName& dn, boost::optional<size_t> minLabels, boost::optional<bool> wireFormat) {
    std::string result;
    if (!kvs) {
      return result;
    }

    KeyValueLookupKeySuffix lookup(minLabels ? *minLabels : 0, wireFormat ? *wireFormat : true);
    for (const auto& key : lookup.getKeys(dn)) {
      if (kvs->getValue(key, result)) {
        return result;
      }
    }

    return result;
  });

  g_lua.registerFunction<bool(std::shared_ptr<KeyValueStore>::*)()>("reload", [](std::shared_ptr<KeyValueStore>& kvs) {
    if (!kvs) {
      return false;
    }

    return kvs->reload();
  });
}
