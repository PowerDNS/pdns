#ifndef PDNSDNSSECKEEPER_HH
#define PDNSDNSSECKEEPER_HH
/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

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
  struct KeyMetaData
  {
    string fname;
    unsigned int id;
    bool active;
    bool keyOrZone;
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
  bool isSecuredZone(const DNSName& zone);
  static uint64_t dbdnssecCacheSizes(const std::string& str);  
  keyset_t getKeys(const DNSName& zone, boost::tribool allOrKeyOrZone = boost::indeterminate, bool useCache = true);
  DNSSECPrivateKey getKeyById(const DNSName& zone, unsigned int id);
  bool addKey(const DNSName& zname, bool keyOrZone, int algorithm=5, int bits=0, bool active=true);
  bool addKey(const DNSName& zname, const DNSSECPrivateKey& dpk, bool active=true);
  bool removeKey(const DNSName& zname, unsigned int id);
  bool activateKey(const DNSName& zname, unsigned int id);
  bool deactivateKey(const DNSName& zname, unsigned int id);

  bool getNSEC3PARAM(const DNSName& zname, NSEC3PARAMRecordContent* n3p=0, bool* narrow=0);
  bool setNSEC3PARAM(const DNSName& zname, const NSEC3PARAMRecordContent& n3p, const bool& narrow=false);
  bool unsetNSEC3PARAM(const DNSName& zname);
  void clearAllCaches();
  void clearCaches(const DNSName& name);
  bool getPreRRSIGs(UeberBackend& db, const DNSName& signer, const DNSName& qname, const DNSName& wildcardname, const QType& qtype, DNSResourceRecord::Place, vector<DNSResourceRecord>& rrsigs, uint32_t signTTL);
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
uint32_t calculateEditSOA(SOAData sd, const string& kind);
bool editSOA(DNSSECKeeper& dk, const DNSName& qname, DNSPacket* dp);
bool editSOARecord(DNSResourceRecord& rr, const string& kind);
// for SOA-EDIT-DNSUPDATE/API
uint32_t calculateIncreaseSOA(SOAData sd, const string& increaseKind, const string& editKind);
bool increaseSOARecord(DNSResourceRecord& rr, const string& increaseKind, const string& editKind);
#endif
