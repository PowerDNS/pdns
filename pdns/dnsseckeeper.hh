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
    unsigned int id;
    bool active;
    bool keyOrZone;
    string fname;
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
  bool isSecuredZone(const std::string& zone);
  static uint64_t dbdnssecCacheSizes(const std::string& str);  
  keyset_t getKeys(const std::string& zone, boost::tribool allOrKeyOrZone = boost::indeterminate, bool useCache = true);
  DNSSECPrivateKey getKeyById(const std::string& zone, unsigned int id);
  bool addKey(const std::string& zname, bool keyOrZone, int algorithm=5, int bits=0, bool active=true);
  bool addKey(const std::string& zname, const DNSSECPrivateKey& dpk, bool active=true);
  bool removeKey(const std::string& zname, unsigned int id);
  bool activateKey(const std::string& zname, unsigned int id);
  bool deactivateKey(const std::string& zname, unsigned int id);

  bool secureZone(const std::string& fname, int algorithm, int size);

  bool getNSEC3PARAM(const std::string& zname, NSEC3PARAMRecordContent* n3p=0, bool* narrow=0);
  bool setNSEC3PARAM(const std::string& zname, const NSEC3PARAMRecordContent& n3p, const bool& narrow=false);
  bool unsetNSEC3PARAM(const std::string& zname);
  void clearAllCaches();
  void clearCaches(const std::string& name);
  bool getPreRRSIGs(UeberBackend& db, const std::string& signer, const std::string& qname, const std::string& wildcardname, const QType& qtype, DNSPacketWriter::Place, vector<DNSResourceRecord>& rrsigs, uint32_t signTTL);
  bool isPresigned(const std::string& zname);
  bool setPresigned(const std::string& zname);
  bool unsetPresigned(const std::string& zname);

  bool TSIGGrantsAccess(const string& zone, const string& keyname);
  bool getTSIGForAccess(const string& zone, const string& master, string* keyname);
  
  void startTransaction()
  {
    (*d_keymetadb->backends.begin())->startTransaction("", -1);
  }
  
  void commitTransaction()
  {
    (*d_keymetadb->backends.begin())->commitTransaction();
  }
  
  void getFromMeta(const std::string& zname, const std::string& key, std::string& value);
private:


  struct KeyCacheEntry
  {
    typedef vector<DNSSECKeeper::keymeta_t> keys_t;
  
    uint32_t getTTD() const
    {
      return d_ttd;
    }
  
    string d_domain;
    unsigned int d_ttd;
    mutable keys_t d_keys;
  };
  
  struct METACacheEntry
  {
    uint32_t getTTD() const
    {
      return d_ttd;
    }
  
    string d_domain;
    unsigned int d_ttd;
  
    mutable std::string d_key, d_value;
  };
  
  
  typedef multi_index_container<
    KeyCacheEntry,
    indexed_by<
      ordered_unique<member<KeyCacheEntry, std::string, &KeyCacheEntry::d_domain>, CIStringCompare >,
      sequenced<>
    >
  > keycache_t;
  typedef multi_index_container<
    METACacheEntry,
    indexed_by<
      ordered_unique<
        composite_key< 
          METACacheEntry, 
          member<METACacheEntry, std::string, &METACacheEntry::d_domain> ,
          member<METACacheEntry, std::string, &METACacheEntry::d_key>
        >, composite_key_compare<CIStringCompare, CIStringCompare> >,
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
bool editSOA(DNSSECKeeper& dk, const string& qname, DNSPacket* dp);
bool editSOARecord(DNSResourceRecord& rr, const string& kind);
// for SOA-EDIT-DNSUPDATE/API
uint32_t calculateIncreaseSOA(SOAData sd, const string& increaseKind, const string& editKind);
bool increaseSOARecord(DNSResourceRecord& rr, const string& increaseKind, const string& editKind);
#endif
