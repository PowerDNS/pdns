/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    
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
#ifndef PACKETCACHE_HH
#define PACKETCACHE_HH

#include <string>
#include <utility>
#include <map>
#include <map>
#include "dns.hh"
#include <boost/version.hpp>
#include "namespaces.hh"
using namespace ::boost::multi_index;

#include "namespaces.hh"
#include "dnspacket.hh"
#include "lock.hh"
#include "statbag.hh"

/** This class performs 'whole packet caching'. Feed it a question packet and it will
    try to find an answer. If you have an answer, insert it to have it cached for later use. 
    Take care not to replace existing cache entries. While this works, it is wasteful. Only
    insert packets that where not found by get()

    Locking! 

    The cache itself is protected by a read/write lock. Because deleting is a two step process, which 
    first marks and then sweeps, a second lock is present to prevent simultaneous inserts and deletes.
*/

class PacketCache : public boost::noncopyable
{
public:
  PacketCache();
  ~PacketCache();
  enum CacheEntryType { PACKETCACHE, QUERYCACHE};

  void insert(DNSPacket *q, DNSPacket *r, bool recursive, unsigned int maxttl=UINT_MAX);  //!< We copy the contents of *p into our cache. Do not needlessly call this to insert questions already in the cache as it wastes resources

  void insert(const DNSName &qname, const QType& qtype, CacheEntryType cet, const string& value, unsigned int ttl, int zoneID=-1, bool meritsRecursion=false,
    unsigned int maxReplyLen=512, bool dnssecOk=false, bool EDNS=false);

  void insert(const DNSName &qname, const QType& qtype, CacheEntryType cet, const vector<DNSResourceRecord>& content, unsigned int ttl, int zoneID=-1);

  int get(DNSPacket *p, DNSPacket *q, bool recursive); //!< We return a dynamically allocated copy out of our cache. You need to delete it. You also need to spoof in the right ID with the DNSPacket.spoofID() method.
  bool getEntry(const DNSName &qname, const QType& qtype, CacheEntryType cet, string& entry, int zoneID=-1,
    bool meritsRecursion=false, unsigned int maxReplyLen=512, bool dnssecOk=false, bool hasEDNS=false, unsigned int *age=0);
  bool getEntry(const DNSName &qname, const QType& qtype, CacheEntryType cet, vector<DNSResourceRecord>& entry, int zoneID=-1);
  

  int size(); //!< number of entries in the cache
  void cleanup(); //!< force the cache to preen itself from expired packets
  int purge();
  int purge(const std::string& match); // could be $ terminated. Is not a dnsname!

  map<char,int> getCounts();
private:
  bool getEntryLocked(const DNSName &content, const QType& qtype, CacheEntryType cet, string& entry, int zoneID=-1,
    bool meritsRecursion=false, unsigned int maxReplyLen=512, bool dnssecOk=false, bool hasEDNS=false, unsigned int *age=0);
  bool getEntryLocked(const DNSName &content, const QType& qtype, CacheEntryType cet, vector<DNSResourceRecord>& entry, int zoneID=-1);


  struct CacheEntry
  {
    CacheEntry() { qtype = ctype = 0; zoneID = -1; meritsRecursion=false; dnssecOk=false; hasEDNS=false; created=0; ttd=0; maxReplyLen=512;}

    DNSName qname;
    string value;
    vector<DNSResourceRecord> drs;
    time_t created;
    time_t ttd;

    uint16_t qtype;
    uint16_t ctype;
    int zoneID;
    unsigned int maxReplyLen;

    bool meritsRecursion;
    bool dnssecOk;
    bool hasEDNS;
  };

  void getTTLS();

  typedef multi_index_container<
    CacheEntry,
    indexed_by <
                ordered_unique<
                      composite_key< 
                        CacheEntry,
                        member<CacheEntry,DNSName,&CacheEntry::qname>,
                        member<CacheEntry,uint16_t,&CacheEntry::qtype>,
                        member<CacheEntry,uint16_t, &CacheEntry::ctype>,
                        member<CacheEntry,int, &CacheEntry::zoneID>,
                        member<CacheEntry,bool, &CacheEntry::meritsRecursion>,
                        member<CacheEntry,unsigned int, &CacheEntry::maxReplyLen>,
                        member<CacheEntry,bool, &CacheEntry::dnssecOk>,
                        member<CacheEntry,bool, &CacheEntry::hasEDNS>
                        >,
		       composite_key_compare<CanonDNSNameCompare, std::less<uint16_t>, std::less<uint16_t>, std::less<int>, std::less<bool>, 
                          std::less<unsigned int>, std::less<bool>, std::less<bool> >
                            >,
                           sequenced<>
                           >
  > cmap_t;


  struct MapCombo
  {
    pthread_rwlock_t d_mut;    
    cmap_t d_map;
  };

  vector<MapCombo> d_maps;
  MapCombo& getMap(const DNSName& qname) 
  {
    return d_maps[qname.hash() % d_maps.size()];
  }

  AtomicCounter d_ops;
  AtomicCounter *d_statnumhit;
  AtomicCounter *d_statnummiss;
  AtomicCounter *d_statnumentries;

  int d_ttl;
  int d_recursivettl;
  bool d_doRecursion;
};



#endif /* PACKETCACHE_HH */

