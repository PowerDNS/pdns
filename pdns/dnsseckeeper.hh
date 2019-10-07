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
    ED25519=15,
    ED448=16
  };

  enum dsdigestalgorithm_t : uint8_t {
    DIGEST_SHA1=1,
    DIGEST_SHA256=2,
    DIGEST_GOST=3,
    DIGEST_SHA384=4
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

  /*
   * Returns the algorithm number based on the mnemonic (or old PowerDNS value of) a string.
   * See https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml for the mapping
   */
  static int shorthand2algorithm(const string &algorithm)
  {
    if (pdns_iequals(algorithm, "rsamd5")) return RSAMD5;
    if (pdns_iequals(algorithm, "dh")) return DH;
    if (pdns_iequals(algorithm, "dsa")) return DSA;
    if (pdns_iequals(algorithm, "rsasha1")) return RSASHA1;
    if (pdns_iequals(algorithm, "dsa-nsec3-sha1")) return DSANSEC3SHA1;
    if (pdns_iequals(algorithm, "rsasha1-nsec3-sha1")) return RSASHA1NSEC3SHA1;
    if (pdns_iequals(algorithm, "rsasha256")) return RSASHA256;
    if (pdns_iequals(algorithm, "rsasha512")) return RSASHA512;
    if (pdns_iequals(algorithm, "ecc-gost")) return ECCGOST;
    if (pdns_iequals(algorithm, "gost")) return ECCGOST;
    if (pdns_iequals(algorithm, "ecdsa256")) return ECDSA256;
    if (pdns_iequals(algorithm, "ecdsap256sha256")) return ECDSA256;
    if (pdns_iequals(algorithm, "ecdsa384")) return ECDSA384;
    if (pdns_iequals(algorithm, "ecdsap384sha384")) return ECDSA384;
    if (pdns_iequals(algorithm, "ed25519")) return ED25519;
    if (pdns_iequals(algorithm, "ed448")) return ED448;
    if (pdns_iequals(algorithm, "indirect")) return 252;
    if (pdns_iequals(algorithm, "privatedns")) return 253;
    if (pdns_iequals(algorithm, "privateoid")) return 254;
    return -1;
  }

  /*
   * Returns the mnemonic from https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
   */
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
      case ED448:
        return "ED448";
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
  bool checkKeys(const DNSName& zname, vector<string>* errorMessages = nullptr);

  bool getNSEC3PARAM(const DNSName& zname, NSEC3PARAMRecordContent* n3p=0, bool* narrow=0);
  bool checkNSEC3PARAM(const NSEC3PARAMRecordContent& ns3p, string& msg);
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
  bool getTSIGForAccess(const DNSName& zone, const ComboAddress& master, DNSName* keyname);
  
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
  bool unSecureZone(const DNSName& zone, std::string& error, std::string& info);
  bool rectifyZone(const DNSName& zone, std::string& error, std::string& info, bool doTransaction);
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

public:
  void preRemoval(const KeyCacheEntry&)
  {
  }
  void preRemoval(const METACacheEntry&)
  {
  }
};

class DNSPacket;
uint32_t localtime_format_YYYYMMDDSS(time_t t, uint32_t seq);
// for SOA-EDIT
uint32_t calculateEditSOA(uint32_t old_serial, DNSSECKeeper& dk, const DNSName& zonename);
uint32_t calculateEditSOA(uint32_t old_serial, const string& kind, const DNSName& zonename);
// for SOA-EDIT-DNSUPDATE/API
bool increaseSOARecord(DNSResourceRecord& dr, const string& increaseKind, const string& editKind);
bool makeIncreasedSOARecord(SOAData& sd, const string& increaseKind, const string& editKind, DNSResourceRecord& rrout);
DNSZoneRecord makeEditedDNSZRFromSOAData(DNSSECKeeper& dk, const SOAData& sd, DNSResourceRecord::Place place=DNSResourceRecord::ANSWER);
