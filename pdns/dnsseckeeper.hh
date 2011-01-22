#ifndef PDNSDNSSECKEEPER_HH
#define PDNSDNSSECKEEPER_HH
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

class DNSSECKeeper
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
  UeberBackend d_db;
public:
  DNSSECKeeper() : d_db("key-only"){}
  bool isSecuredZone(const std::string& zone);
  
  keyset_t getKeys(const std::string& zone, boost::tribool allOrKeyOrZone = boost::indeterminate);
  DNSSECPrivateKey getKeyById(const std::string& zone, unsigned int id);
  void addKey(const std::string& zname, bool keyOrZone, int algorithm=5, int bits=0, bool active=true);
  void addKey(const std::string& zname, const DNSSECPrivateKey& dpk, bool active=true);
  void removeKey(const std::string& zname, unsigned int id);
  void activateKey(const std::string& zname, unsigned int id);
  void deactivateKey(const std::string& zname, unsigned int id);

  void secureZone(const std::string& fname, int algorithm);

  bool getNSEC3PARAM(const std::string& zname, NSEC3PARAMRecordContent* n3p=0, bool* narrow=0);
  void setNSEC3PARAM(const std::string& zname, const NSEC3PARAMRecordContent& n3p, const bool& narrow=false);
  void unsetNSEC3PARAM(const std::string& zname);
  void clearCaches(const std::string& name);
  bool getPreRRSIGs(const std::string& signer, const std::string& qname, const QType& qtype, DNSPacketWriter::Place, vector<DNSResourceRecord>& rrsigs);
  bool isPresigned(const std::string& zname);
  void setPresigned(const std::string& zname);
  void unsetPresigned(const std::string& zname);
private:
  void getFromMeta(const std::string& zname, const std::string& key, std::string& value);
  
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

  static keycache_t s_keycache;
  static metacache_t s_metacache;
  static pthread_mutex_t s_keycachelock;
  static pthread_mutex_t s_metacachelock;
};

#endif
