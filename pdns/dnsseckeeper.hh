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
#include <string>
#include <string.h>
#include <vector>
#include <boost/logic/tribool.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include "dnssecinfra.hh"
#include "dnsrecords.hh"
#include "ueberbackend.hh"

using namespace ::boost::multi_index;

class DNSSECKeeper : public boost::noncopyable
{
public:
  enum keytype_t { KSK, ZSK, CSK };
  enum keyalgorithm_t : uint8_t {
    RSAMD5=1,
    DH=2,
    DSA=3,
    RSASHA1=5,
    DSANSEC3SHA1=6,
    RSASHA1NSEC3SHA1=7,
    RSASHA256=8,
    RSASHA512=10,
    ECCGOST=12,
    ECDSA256=13,
    ECDSA384=14,
    ED25519=15
  };

  struct KeyMetaData
  {
    string fname;
    unsigned int id;
    bool active;
    keytype_t keyType;
    bool hasSEPBit;
  };
  typedef std::pair<DNSSECPrivateKey, KeyMetaData> keymeta_t;
  typedef std::vector<keymeta_t > keyset_t;

  static string keyTypeToString(const keytype_t &keyType)
  {
    switch(keyType) {
      case DNSSECKeeper::KSK:
        return("KSK");
      case DNSSECKeeper::ZSK:
        return("ZSK");
      case DNSSECKeeper::CSK:
        return("CSK");
      default:
        return("UNKNOWN");
    }
  }

  static int shorthand2algorithm(const string &algorithm)
  {
    if (!algorithm.compare("rsamd5")) return RSAMD5;
    if (!algorithm.compare("dh")) return DH;
    if (!algorithm.compare("dsa")) return DSA;
    if (!algorithm.compare("rsasha1")) return RSASHA1;
    if (!algorithm.compare("rsasha256")) return RSASHA256;
    if (!algorithm.compare("rsasha512")) return RSASHA512;
    if (!algorithm.compare("ecc-gost")) return ECCGOST;
    if (!algorithm.compare("gost")) return ECCGOST;
    if (!algorithm.compare("ecdsa256")) return ECDSA256;
    if (!algorithm.compare("ecdsa384")) return ECDSA384;
    if (!algorithm.compare("ed25519")) return ED25519;
    return -1;
  }

  static string algorithm2name(uint8_t algo) {
    switch(algo) {
      case 0:
      case 4:
      case 9:
      case 11:
        return "Reserved";
      case RSAMD5:
        return "RSAMD5";
      case DH:
        return "DH";
      case DSA:
        return "DSA";
      case RSASHA1:
        return "RSASHA1";
      case DSANSEC3SHA1:
        return "DSA-NSEC3-SHA1";
      case RSASHA1NSEC3SHA1:
        return "RSASHA1-NSEC3-SHA1";
      case RSASHA256:
        return "RSASHA256";
      case RSASHA512:
        return "RSASHA512";
      case ECCGOST:
        return "ECC-GOST";
      case ECDSA256:
        return "ECDSAP256SHA256";
      case ECDSA384:
        return "ECDSAP384SHA384";
      case ED25519:
        return "ED25519";
      case 252:
        return "INDIRECT";
      case 253:
        return "PRIVATEDNS";
      case 254:
        return "PRIVATEOID";
      default:
        return "Unallocated/Reserved";
    }
  }

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
  bool doesDNSSEC();
  bool isSecuredZone(const DNSName& zone);
  static uint64_t dbdnssecCacheSizes(const std::string& str);
  keyset_t getEntryPoints(const DNSName& zname);
  keyset_t getKeys(const DNSName& zone, bool useCache = true);
  DNSSECPrivateKey getKeyById(const DNSName& zone, unsigned int id);
  bool addKey(const DNSName& zname, bool setSEPBit, int algorithm, int64_t& id, int bits=0, bool active=true);
  bool addKey(const DNSName& zname, const DNSSECPrivateKey& dpk, int64_t& id, bool active=true);
  bool removeKey(const DNSName& zname, unsigned int id);
  bool activateKey(const DNSName& zname, unsigned int id);
  bool deactivateKey(const DNSName& zname, unsigned int id);
  bool checkKeys(const DNSName& zname);

  bool getNSEC3PARAM(const DNSName& zname, NSEC3PARAMRecordContent* n3p=0, bool* narrow=0);
  bool setNSEC3PARAM(const DNSName& zname, const NSEC3PARAMRecordContent& n3p, const bool& narrow=false);
  bool unsetNSEC3PARAM(const DNSName& zname);
  void clearAllCaches();
  void clearCaches(const DNSName& name);
  bool getPreRRSIGs(UeberBackend& db, const DNSName& signer, const DNSName& qname, const DNSName& wildcardname, const QType& qtype, DNSResourceRecord::Place, vector<DNSZoneRecord>& rrsigs, uint32_t signTTL);
  bool isPresigned(const DNSName& zname);
  bool setPresigned(const DNSName& zname);
  bool unsetPresigned(const DNSName& zname);
  bool setPublishCDNSKEY(const DNSName& zname);
  bool unsetPublishCDNSKEY(const DNSName& zname);
  bool setPublishCDS(const DNSName& zname, const string& digestAlgos);
  bool unsetPublishCDS(const DNSName& zname);

  bool TSIGGrantsAccess(const DNSName& zone, const DNSName& keyname);
  bool getTSIGForAccess(const DNSName& zone, const string& master, DNSName* keyname);
  
  void startTransaction(const DNSName& zone, int zone_id)
  {
    (*d_keymetadb->backends.begin())->startTransaction(zone, zone_id);
  }
  
  void commitTransaction()
  {
    (*d_keymetadb->backends.begin())->commitTransaction();
  }
  
  void getFromMeta(const DNSName& zname, const std::string& key, std::string& value);
  void getSoaEdit(const DNSName& zname, std::string& value);
private:


  struct KeyCacheEntry
  {
    typedef vector<DNSSECKeeper::keymeta_t> keys_t;
  
    uint32_t getTTD() const
    {
      return d_ttd;
    }
  
    DNSName d_domain;
    mutable keys_t d_keys;
    unsigned int d_ttd;
  };
  
  struct METACacheEntry
  {
    uint32_t getTTD() const
    {
      return d_ttd;
    }
  
    DNSName d_domain;
    mutable std::string d_key, d_value;
    unsigned int d_ttd;
  
  };
  
  
  typedef multi_index_container<
    KeyCacheEntry,
    indexed_by<
      ordered_unique<member<KeyCacheEntry, DNSName, &KeyCacheEntry::d_domain> >,
      sequenced<>
    >
  > keycache_t;
  typedef multi_index_container<
    METACacheEntry,
    indexed_by<
      ordered_unique<
        composite_key< 
          METACacheEntry, 
          member<METACacheEntry, DNSName, &METACacheEntry::d_domain> ,
          member<METACacheEntry, std::string, &METACacheEntry::d_key>
        >, composite_key_compare<std::less<DNSName>, CIStringCompare> >,
      sequenced<>
    >
  > metacache_t;

  void cleanup();

  static keycache_t s_keycache;
  static metacache_t s_metacache;
  static pthread_rwlock_t s_metacachelock;
  static pthread_rwlock_t s_keycachelock;
  static AtomicCounter s_ops;
  static time_t s_last_prune;
};

class DNSPacket;
uint32_t localtime_format_YYYYMMDDSS(time_t t, uint32_t seq);
// for SOA-EDIT
uint32_t calculateEditSOA(const DNSZoneRecord& rr, const string& kind);
uint32_t calculateEditSOA(const SOAData& sd, const string& kind);
bool editSOA(DNSSECKeeper& dk, const DNSName& qname, DNSPacket* dp);
bool editSOARecord(DNSZoneRecord& rr, const string& kind, const DNSName& qname);
// for SOA-EDIT-DNSUPDATE/API
uint32_t calculateIncreaseSOA(SOAData sd, const string& increaseKind, const string& editKind);
bool increaseSOARecord(DNSResourceRecord& rr, const string& increaseKind, const string& editKind);
bool increaseSOARecord(DNSZoneRecord& rr, const string& increaseKind, const string& editKind);
