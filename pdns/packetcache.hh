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

struct CIBackwardsStringCompare: public std::binary_function<string, string, bool>  
{
  bool operator()(const string& str_a, const string& str_b) const
  {
    string::const_reverse_iterator ra, rb;
    char a=0, b=0;
    for(ra = str_a.rbegin(), rb = str_b.rbegin();
        ra < str_a.rend() && rb < str_b.rend() && (a=dns_tolower(*ra)) == (b=dns_tolower(*rb));
        ra++, rb++);
    
    if (ra < str_a.rend() && rb==str_b.rend()) { a=*(ra++); b=0; return false; } // we are at the beginning of b -> b smaller
    if (rb < str_b.rend() && ra==str_a.rend()) { b=*(rb++); a=0; return true; } // we are at the beginning of a -> a smaller
    // if BOTH are at their ends, a and b will be equal, and we should return false, which we will
    return a < b;
  }
};

// compares labels reversed, as in:
//  if you have 'www.powerdns.com' and 'dns.powerdns.com', they
//  are compared as 'com.powerdns.www' and 'com.powerdns.dns' unlike
//  the older function above which would compare them as 
//  'moc.sndrewop.www' and 'moc.sndrewop.snd'
//  will actually order the labels correctly.
struct CIBackwardsLabelCompare: public std::binary_function<string, string, bool>
{
  bool operator()(const string& str_a, const string& str_b) const
  {
    string::const_reverse_iterator ra, rb, ptra, ptrb;
    char a=0, b=0;
    ra = str_a.rbegin(); rb = str_b.rbegin();
    while(ra < str_a.rend() && rb < str_b.rend()) {
       // looking from right, find the next delimiting dot.
       ra = ptra = std::find (ra, str_a.rend(), '.');
       rb = ptrb = std::find (rb, str_b.rend(), '.');
       // move before the dot
       ptra--; ptrb--;
       // to make sure these get set even if the loop never runs
       a = dns_tolower(*ptra); b = dns_tolower(*ptrb);
       // scan to *left* until dot, start of string, or first inequality is hit
       while(ptra > str_a.rbegin() && ptrb > str_b.rbegin() && a == b && *ptra != '.') { a = dns_tolower(*(--ptra)); b = dns_tolower(*(--ptrb)); }
       // check if the label component being compared is shorter than the other
       if (ptra > str_a.rbegin() && ptrb==str_b.rbegin()) { return false; } // label on b is smaller
       if (ptrb > str_b.rbegin() && ptra==str_a.rbegin()) { return true; } // label on a is smaller
       if (a != b) return (a < b); // the current byte differs
       // move past the dot unless at the end
       if (ra < str_a.rend()) ra++;
       if (rb < str_b.rend()) rb++;
    }
    // check the last label component
    if (ra < str_a.rend() && rb==str_b.rend()) { return false; } // we are at the beginning of b -> b smaller
    if (rb < str_b.rend() && ra==str_a.rend()) { return true; } // we are at the beginning of a -> a smaller
    if (ra == str_a.rend() && rb==str_b.rend()) { return false; } // c++ end() or rend() is not valid location
    return dns_tolower(*ra) < dns_tolower(*rb);
  }
};

class PacketCache : public boost::noncopyable
{
public:
  PacketCache();
  ~PacketCache();
  enum CacheEntryType { PACKETCACHE, QUERYCACHE};

  void insert(DNSPacket *q, DNSPacket *r, bool recursive, unsigned int maxttl=UINT_MAX);  //!< We copy the contents of *p into our cache. Do not needlessly call this to insert questions already in the cache as it wastes resources

  void insert(const string &qname, const QType& qtype, CacheEntryType cet, const string& value, unsigned int ttl, int zoneID=-1, bool meritsRecursion=false,
    unsigned int maxReplyLen=512, bool dnssecOk=false, bool EDNS=false);

  int get(DNSPacket *p, DNSPacket *q, bool recursive); //!< We return a dynamically allocated copy out of our cache. You need to delete it. You also need to spoof in the right ID with the DNSPacket.spoofID() method.
  bool getEntry(const string &content, const QType& qtype, CacheEntryType cet, string& entry, int zoneID=-1,
    bool meritsRecursion=false, unsigned int maxReplyLen=512, bool dnssecOk=false, bool hasEDNS=false, unsigned int *age=0);

  int size(); //!< number of entries in the cache
  void cleanup(); //!< force the cache to preen itself from expired packets
  int purge();
  int purge(const string &match);

  map<char,int> getCounts();
private:
  bool getEntryLocked(const string &content, const QType& qtype, CacheEntryType cet, string& entry, int zoneID=-1,
    bool meritsRecursion=false, unsigned int maxReplyLen=512, bool dnssecOk=false, bool hasEDNS=false, unsigned int *age=0);
  struct CacheEntry
  {
    CacheEntry() { qtype = ctype = 0; zoneID = -1; meritsRecursion=false; dnssecOk=false; hasEDNS=false;}

    string qname;
    uint16_t qtype;
    uint16_t ctype;
    int zoneID;
    time_t created;
    time_t ttd;
    bool meritsRecursion;
    unsigned int maxReplyLen;
    bool dnssecOk;
    bool hasEDNS;
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
                        member<CacheEntry,bool, &CacheEntry::meritsRecursion>,
                        member<CacheEntry,unsigned int, &CacheEntry::maxReplyLen>,
                        member<CacheEntry,bool, &CacheEntry::dnssecOk>,
                        member<CacheEntry,bool, &CacheEntry::hasEDNS>
                        >,
                        composite_key_compare<CIBackwardsLabelCompare, std::less<uint16_t>, std::less<uint16_t>, std::less<int>, std::less<bool>, 
                          std::less<unsigned int>, std::less<bool>, std::less<bool> >
                            >,
                           sequenced<>
                           >
  > cmap_t;


  cmap_t d_map;

  pthread_rwlock_t d_mut;

  AtomicCounter d_ops;
  int d_ttl;
  int d_recursivettl;
  bool d_doRecursion;
  unsigned int *d_statnumhit;
  unsigned int *d_statnummiss;
  unsigned int *d_statnumentries;
};



#endif /* PACKETCACHE_HH */

