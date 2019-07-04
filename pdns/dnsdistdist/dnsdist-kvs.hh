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

class KeyValueLookupKey
{
public:
  virtual ~KeyValueLookupKey()
  {
  }
  virtual std::string getKey(const DNSQuestion&) = 0;
  virtual std::string toString() const = 0;
};

class KeyValueLookupKeySourceIP: public KeyValueLookupKey
{
public:
  std::string getKey(const DNSQuestion& dq) override
  {
    std::string key;
    if (dq.remote->sin4.sin_family == AF_INET) {
      key = std::string(reinterpret_cast<const char*>(&dq.remote->sin4.sin_addr.s_addr), sizeof(dq.remote->sin4.sin_addr.s_addr));
    }
    else if (dq.remote->sin4.sin_family == AF_INET6) {
      key = std::string(reinterpret_cast<const char*>(&dq.remote->sin6.sin6_addr.s6_addr), sizeof(dq.remote->sin6.sin6_addr.s6_addr));
    }
    return key;
  }

  std::string toString() const override
  {
    return "source IP";
  }
};

class KeyValueLookupKeyQName: public KeyValueLookupKey
{
public:
  std::string getKey(const DNSQuestion& dq) override
  {
    return dq.qname->toDNSStringLC();
  }

  std::string toString() const override
  {
    return "qname";
  }
};

class KeyValueLookupKeyTag: public KeyValueLookupKey
{
public:
  KeyValueLookupKeyTag(const std::string& tag): d_tag(tag)
  {
  }

  std::string getKey(const DNSQuestion& dq) override
  {
    std::string key;
    if (dq.qTag) {
      const auto& it = dq.qTag->find(d_tag);
      if (it != dq.qTag->end()) {
        key = it->second;
      }
    }
    return key;
  }

  std::string toString() const override
  {
    return " value of the tag named '" + d_tag + '"';
  }

private:
  std::string d_tag;
};

class KeyValueStore
{
public:
  virtual ~KeyValueStore()
  {
  }

  virtual std::string getValue(const std::string& key) = 0;
};

#ifdef HAVE_LMDB

#include "lmdb-safe.hh"

class LMDBKVStore: public KeyValueStore
{
public:
  LMDBKVStore(const std::string& fname, const std::string& dbName): d_env(fname.c_str(), MDB_NOSUBDIR, 0600), d_fname(fname), d_dbName(dbName)
  {
  }

  std::string getValue(const std::string& key) override;

private:
  MDBEnv d_env;
  std::string d_fname;
  std::string d_dbName;
};

#endif /* HAVE_LMDB */
