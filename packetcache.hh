/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2008  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    

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

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/version.hpp>
using namespace std;
using namespace ::boost::multi_index;

using namespace boost;
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

struct CIBackwardsStringCompare: public binary_function<string, string, bool>  
{
  bool operator()(const string& a, const string& b) const
  {
    const unsigned char *p1 = (const unsigned char *) a.c_str() + a.length();
    const unsigned char *p2 = (const unsigned char *) b.c_str() + b.length();
    int result;
    
    if (p1 == p2) {
      return 0;
    }
    
    while ((result = dns_tolower (*p1--) - dns_tolower (*p2--)) == 0)
      if (p1 == (unsigned char*)a.c_str() || p2 == (unsigned char*) b.c_str())
	break;
    
    if(result==0) { // one of our strings ended, the shortest one is smaller then
      return a.length() < b.length();
    }

    return result < 0;
  }
};


class PacketCache
{
public:
  PacketCache();
  enum CacheEntryType { PACKETCACHE, QUERYCACHE, NEGCACHE};


  void insert(DNSPacket *q, DNSPacket *r);  //!< We copy the contents of *p into our cache. Do not needlessly call this to insert questions already in the cache as it wastes resources

  void insert(const string &qname, const QType& qtype, CacheEntryType cet, const string& value, unsigned int ttl, int zoneID=-1, bool meritsRecursion=false);

  int get(DNSPacket *p, DNSPacket *q); //!< We return a dynamically allocated copy out of our cache. You need to delete it. You also need to spoof in the right ID with the DNSPacket.spoofID() method.
  bool getEntry(const string &content, const QType& qtype, CacheEntryType cet, string& entry, int zoneID=-1, bool meritsRecursion=false);

  int size(); //!< number of entries in the cache
  void cleanup(); //!< force the cache to preen itself from expired packets
  int purge(const vector<string>&matches= vector<string>());

  map<char,int> getCounts();
private:
  struct CacheEntry
  {
    CacheEntry() { qtype = ctype = 0; zoneID = -1; meritsRecursion=false;}

    string qname;
    uint16_t qtype;
    uint16_t ctype;
    int zoneID;
    time_t ttd;
    bool meritsRecursion;
    string value;
  };

  void getTTLS();

  typedef multi_index_container<
    CacheEntry,
    indexed_by <
                ordered_unique<
                      composite_key< 
                        CacheEntry,
                        member<CacheEntry,string,&CacheEntry::qname>,
                        member<CacheEntry,uint16_t,&CacheEntry::qtype>,
			member<CacheEntry,uint16_t, &CacheEntry::ctype>,
			member<CacheEntry,int, &CacheEntry::zoneID>,
			member<CacheEntry,bool, &CacheEntry::meritsRecursion>
                      >,
		  composite_key_compare<CIBackwardsStringCompare, std::less<uint16_t>, std::less<uint16_t>, std::less<int>, std::less<bool> >
                >,
               sequenced<>
               >
  > cmap_t;


  cmap_t d_map;

  pthread_rwlock_t d_mut;

  int d_hit;
  int d_miss;
  int d_ttl;
  int d_recursivettl;
  bool d_doRecursion;
  int *statnumhit;
  int *statnummiss;
  int *statnumentries;
};



#endif /* PACKETCACHE_HH */

