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

#include <memory>
#include "dnsdist.hh"
#include "logr.hh"

class KeyValueLookupKey
{
public:
  virtual ~KeyValueLookupKey()
  {
  }
  virtual std::vector<std::string> getKeys(const DNSQuestion&) = 0;
  virtual std::string toString() const = 0;
};

class KeyValueLookupKeySourceIP: public KeyValueLookupKey
{
public:
  KeyValueLookupKeySourceIP(uint8_t v4Mask, uint8_t v6Mask, bool includePort): d_v4Mask(v4Mask), d_v6Mask(v6Mask), d_includePort(includePort)
  {
  }

  std::vector<std::string> getKeys(const ComboAddress& addr);

  std::vector<std::string> getKeys(const DNSQuestion& dq) override
  {
    return getKeys(dq.ids.origRemote);
  }

  std::string toString() const override
  {
    return "source IP (masked to " + std::to_string(d_v4Mask) + " (v4) / " + std::to_string(d_v6Mask) + " (v6) bits)" + (d_includePort ? " including the port" : "");
  }
private:
  uint8_t d_v4Mask;
  uint8_t d_v6Mask;
  bool d_includePort;
};

class KeyValueLookupKeyQName: public KeyValueLookupKey
{
public:

  KeyValueLookupKeyQName(bool wireFormat): d_wireFormat(wireFormat)
  {
  }

  std::vector<std::string> getKeys(const DNSName& qname)
  {
    if (d_wireFormat) {
      return {qname.toDNSStringLC()};
    }
    return {qname.makeLowerCase().toStringRootDot()};
  }

  std::vector<std::string> getKeys(const DNSQuestion& dq) override
  {
    return getKeys(dq.ids.qname);
  }

  std::string toString() const override
  {
    if (d_wireFormat) {
      return "qname in wire format";
    }
    return "qname";
  }

private:
  bool d_wireFormat;
};

class KeyValueLookupKeySuffix: public KeyValueLookupKey
{
public:
  KeyValueLookupKeySuffix(size_t minLabels, bool wireFormat): d_minLabels(minLabels), d_wireFormat(wireFormat)
  {
  }

  std::vector<std::string> getKeys(const DNSName& qname);

  std::vector<std::string> getKeys(const DNSQuestion& dq) override
  {
    return getKeys(dq.ids.qname);
  }

  std::string toString() const override
  {
    if (d_minLabels > 0) {
      return "suffix " + std::string(d_wireFormat ? "in wire format " : "") + "with at least " + std::to_string(d_minLabels) + " label(s)";
    }
    return "suffix" + std::string(d_wireFormat ? " in wire format" : "");
  }

private:
  size_t d_minLabels;
  bool d_wireFormat;
};

class KeyValueLookupKeyTag: public KeyValueLookupKey
{
public:
  KeyValueLookupKeyTag(const std::string& tag): d_tag(tag)
  {
  }

  std::vector<std::string> getKeys(const DNSQuestion& dq) override
  {
    if (dq.ids.qTag) {
      const auto& it = dq.ids.qTag->find(d_tag);
      if (it != dq.ids.qTag->end()) {
        return { it->second };
      }
    }
    return {};
  }

  std::string toString() const override
  {
    return "value of the tag named '" + d_tag + "'";
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

  virtual bool keyExists(const std::string& key) = 0;
  virtual bool getValue(const std::string& key, std::string& value) = 0;
  // do a range-based lookup (mostly useful for IP addresses), assuming that:
  // there is a key for the last element of the range (2001:0db8:ffff:ffff:ffff:ffff:ffff:ffff, in network byte order, for 2001:db8::/32)
  // which contains the first element of the range (2001:0db8:0000:0000:0000:0000:0000:0000, in network bytes order) followed by any data in the value
  // AND there is no overlapping ranges in the database !!
  // This requires that the underlying store supports ordered keys, which is true for LMDB but not for CDB, for example.
  virtual bool getRangeValue(const std::string& key, std::string& value)
  {
    (void)key;
    (void)value;
    throw std::runtime_error("range-based lookups are not implemented for this Key-Value Store");
  }
  virtual bool reload()
  {
    return false;
  }
};

#ifdef HAVE_LMDB

#include "ext/lmdb-safe/lmdb-safe.hh"

class LMDBKVStore: public KeyValueStore
{
public:
  LMDBKVStore(const std::string& fname, const std::string& dbName, bool noLock=false): d_env(getMDBEnv(fname.c_str(), noLock ? MDB_NOSUBDIR|MDB_RDONLY|MDB_NOLOCK : MDB_NOSUBDIR|MDB_RDONLY, 0600, 0)), d_dbi(d_env->openDB(dbName, 0)), d_fname(fname), d_dbName(dbName)
  {
  }

  bool keyExists(const std::string& key) override;
  bool getValue(const std::string& key, std::string& value) override;
  bool getRangeValue(const std::string& key, std::string& value) override;

private:
  std::shared_ptr<const Logr::Logger> getLogger() const;

  std::shared_ptr<MDBEnv> d_env;
  MDBDbi d_dbi;
  std::string d_fname;
  std::string d_dbName;
};

#endif /* HAVE_LMDB */

#ifdef HAVE_CDB

#include "cdb.hh"

class CDBKVStore: public KeyValueStore
{
public:
  CDBKVStore(const std::string& fname, time_t refreshDelay);
  ~CDBKVStore();

  bool keyExists(const std::string& key) override;
  bool getValue(const std::string& key, std::string& value) override;
  bool reload() override;

private:
  std::shared_ptr<const Logr::Logger> getLogger() const;
  void refreshDBIfNeeded(time_t now);
  bool reload(const struct stat& st);

  SharedLockGuarded<std::unique_ptr<CDB>> d_cdb{nullptr};
  std::string d_fname;
  time_t d_mtime{0};
  time_t d_nextCheck{0};
  time_t d_refreshDelay{0};
  std::atomic_flag d_refreshing;
};

#endif /* HAVE_LMDB */
