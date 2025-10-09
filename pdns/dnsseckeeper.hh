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

#include <vector>
#include <boost/logic/tribool.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include "dnssecinfra.hh"
#include "dnsrecords.hh"
#include "dnspacket.hh"
#include "ueberbackend.hh"
#include "lock.hh"
#include "dnssec.hh"

using namespace ::boost::multi_index;

class DNSSECKeeper : public DNSSEC
{
public:

  struct KeyMetaData
  {
    string fname;
    unsigned int id;
    bool active;
    keytype_t keyType;
    bool hasSEPBit;
    bool published;
  };
  typedef std::pair<DNSSECPrivateKey, KeyMetaData> keymeta_t;
  typedef std::vector<keymeta_t > keyset_t;


private:
  UeberBackend* d_keymetadb;
  bool d_ourDB;

public:
  DNSSECKeeper() : d_keymetadb( new UeberBackend("key-only")), d_ourDB(true)
  {

  }

  DNSSECKeeper(UeberBackend* db) : d_keymetadb(db), d_ourDB(false)
  {
  }

  ~DNSSECKeeper()
  {
    if(d_ourDB)
      delete d_keymetadb;
  }

  DNSSECKeeper(const DNSSECKeeper&) = delete;
  DNSSECKeeper operator=(const DNSSECKeeper&) = delete;

  static uint64_t dbdnssecCacheSizes(const std::string& str);
  static void clearAllCaches();
  static bool clearKeyCache(const ZoneName& name);
  static bool clearMetaCache(const ZoneName& name);
  static void clearCaches(const ZoneName& name);

  bool doesDNSSEC();
  bool isSecuredZone(const ZoneName& zone, bool useCache=true);
  keyset_t getEntryPoints(const ZoneName& zname);
  keyset_t getKeys(const ZoneName& zone, bool useCache = true);
  DNSSECPrivateKey getKeyById(const ZoneName& zname, unsigned int keyId);
  bool addKey(const ZoneName& zname, bool setSEPBit, int algorithm, int64_t& keyId, int bits=0, bool active=true, bool published=true);
  bool addKey(const ZoneName& zname, const DNSSECPrivateKey& dpk, int64_t& keyId, bool active=true, bool published=true);
  bool removeKey(const ZoneName& zname, unsigned int keyId);
  bool activateKey(const ZoneName& zname, unsigned int keyId);
  bool deactivateKey(const ZoneName& zname, unsigned int keyId);
  bool publishKey(const ZoneName& zname, unsigned int keyId);
  bool unpublishKey(const ZoneName& zname, unsigned int keyId);
  bool checkKeys(const ZoneName& zone, std::optional<std::reference_wrapper<std::vector<std::string>>> errorMessages);

  bool getNSEC3PARAM(const ZoneName& zname, NSEC3PARAMRecordContent* ns3p=nullptr, bool* narrow=nullptr, bool useCache=true);
  bool checkNSEC3PARAM(const NSEC3PARAMRecordContent& ns3p, string& msg);
  bool setNSEC3PARAM(const ZoneName& zname, const NSEC3PARAMRecordContent& ns3p, const bool& narrow=false);
  bool unsetNSEC3PARAM(const ZoneName& zname);
  void getPreRRSIGs(UeberBackend& db, vector<DNSZoneRecord>& rrs, uint32_t signTTL, DNSPacket* p=nullptr);
  bool isPresigned(const ZoneName& zname, bool useCache=true);
  bool setPresigned(const ZoneName& zname);
  bool unsetPresigned(const ZoneName& zname);
  bool isSignalingZone(const ZoneName& zname, bool useCache=true);
  bool setPublishCDNSKEY(const ZoneName& zname, bool deleteAlg);
  void getPublishCDNSKEY(const ZoneName& zname, std::string& value);
  bool unsetPublishCDNSKEY(const ZoneName& zname);
  bool setPublishCDS(const ZoneName& zname, const string& digestAlgos);
  void getPublishCDS(const ZoneName& zname, std::string& value);
  bool unsetPublishCDS(const ZoneName& zname);

  bool TSIGGrantsAccess(const ZoneName& zone, const DNSName& keyname);
  bool getTSIGForAccess(const ZoneName& zone, const ComboAddress& primary, DNSName* keyname);

  void startTransaction(const ZoneName& zone)
  {
    (*d_keymetadb->backends.begin())->startTransaction(zone);
  }

  void commitTransaction()
  {
    (*d_keymetadb->backends.begin())->commitTransaction();
  }

  void getFromMetaOrDefault(const ZoneName& zname, const std::string& key, std::string& value, const std::string& defaultvalue);
  bool getFromMeta(const ZoneName& zname, const std::string& key, std::string& value);
  void getSoaEdit(const ZoneName& zname, std::string& value, bool useCache=true);
  bool unSecureZone(const ZoneName& zone, std::string& error);
  bool rectifyZone(const ZoneName& zone, std::string& error, std::string& info, bool doTransaction);

  static void setMaxEntries(size_t maxEntries);

  bool isMetadataOne(const ZoneName& zname, const std::string& metaname, bool useCache);

  int64_t d_metaCacheCleanAction{0};
  typedef std::map<std::string, std::vector<std::string> > METAValues;
private:
  bool getFromMetaNoCache(const ZoneName& name, const std::string& kind, std::string& value);

  bool d_metaUpdate{false};

  struct KeyCacheEntry
  {
    typedef vector<DNSSECKeeper::keymeta_t> keys_t;

    uint32_t isStale(time_t now) const
    {
      return d_ttd < now;
    }

    ZoneName d_domain;
    mutable keys_t d_keys;
    unsigned int d_ttd;
  };

  struct METACacheEntry
  {
    time_t isStale(time_t now) const
    {
      return d_ttd < now;
    }

    ZoneName d_domain;
    mutable METAValues d_value;
    time_t d_ttd;
  };

  struct KeyCacheTag{};
  struct CompositeTag{};
  struct SequencedTag{};

  typedef multi_index_container<
    KeyCacheEntry,
    indexed_by<
      hashed_unique<tag<KeyCacheTag>,member<KeyCacheEntry, ZoneName, &KeyCacheEntry::d_domain> >,
      sequenced<tag<SequencedTag>>
    >
  > keycache_t;

  typedef multi_index_container<
    METACacheEntry,
    indexed_by<
      ordered_unique<member<METACacheEntry, ZoneName, &METACacheEntry::d_domain> >,
      sequenced<tag<SequencedTag>>
    >
  > metacache_t;

  void cleanup();

  static SharedLockGuarded<keycache_t> s_keycache;
  static SharedLockGuarded<metacache_t> s_metacache;
  static int64_t s_metaCacheCleanActions;
  static AtomicCounter s_ops;
  static time_t s_last_prune;
  static size_t s_maxEntries;
};

uint32_t localtime_format_YYYYMMDDSS(time_t t, uint32_t seq);
// for SOA-EDIT
uint32_t calculateEditSOA(uint32_t old_serial, DNSSECKeeper& dsk, const ZoneName& zonename);
uint32_t calculateEditSOA(uint32_t old_serial, const string& kind, const ZoneName& zonename);
// for SOA-EDIT-DNSUPDATE/API
bool increaseSOARecord(DNSResourceRecord& rr, const string& increaseKind, const string& editKind, const ZoneName& zonename);
bool makeIncreasedSOARecord(SOAData& sd, const string& increaseKind, const string& editKind, DNSResourceRecord& rrout);
DNSZoneRecord makeEditedDNSZRFromSOAData(DNSSECKeeper& dk, const SOAData& sd, DNSResourceRecord::Place place=DNSResourceRecord::ANSWER);
