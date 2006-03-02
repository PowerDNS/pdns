/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#ifndef PACKETCACHE_HH
#define PACKETCACHE_HH

#include <string>
#include <utility>
#include <map>

#ifndef WIN32
# if __GNUC__ >= 3
#   include <ext/hash_map>
using namespace __gnu_cxx;
# else
#   include <hash_map>
# endif // __GNUC__

#else
# include <map>

#endif // WIN32

using namespace std;

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

    Overloading!

    The packet cache contains packets but also negative UeberBackend queries. Those last are recognized
    because they start with a | and have empty content. One day, this content may also contain queries.

*/
class PacketCache
{
public:
  PacketCache();
  void insert(DNSPacket *q, DNSPacket *r);  //!< We copy the contents of *p into our cache. Do not needlessly call this to insert questions already in the cache as it wastes resources
  void insert(const char *packet, int length);

  inline int get(DNSPacket *p, DNSPacket *q); //!< We return a dynamically allocated copy out of our cache. You need to delete it. You also need to spoof in the right ID with the DNSPacket.spoofID() method.
  bool getKey(const string &key, string &content);
  int size(); //!< number of entries in the cache
  void cleanup(); //!< force the cache to preen itself from expired packets
  int purge(const string &prefix="");
  void insert(const string &key, const string &packet, unsigned int ttl);
  map<char,int> getCounts();
private:
  typedef string ckey_t;

  class CacheContent
  {
  public:
    time_t ttd;
    string value;
  };

  typedef CacheContent cvalue_t;
  void getTTLS();
#ifndef WIN32

  struct compare_string
  {
    bool operator()(const string& s1, const string& s2) const
    {
      return s1 == s2;
    }
  };

  struct hash_string
  {
    size_t operator()(const string& s) const
    {
      return __stl_hash_string(s.c_str());
    }
  };

  typedef hash_map<ckey_t,cvalue_t, hash_string, compare_string > cmap_t;

#else
  typedef map< ckey_t, cvalue_t > cmap_t;

#endif // WIN32

  cmap_t d_map;

  pthread_rwlock_t d_mut;
  pthread_mutex_t d_dellock;

  int d_hit;
  int d_miss;
  int d_ttl;
  int d_recursivettl;
  bool d_doRecursion;
  int *statnumhit;
  int *statnummiss;
  int *statnumentries;
};

inline int PacketCache::get(DNSPacket *p, DNSPacket *cached)
{
  extern StatBag S;
  if(!((d_hit+d_miss)%5000)) {
    cleanup();
  }

  if(d_ttl<0) 
    getTTLS();

  if(d_doRecursion && p->d.rd) { // wants recursion
    if(!d_recursivettl) {
      (*statnummiss)++;
      d_miss++;
      return 0;
    }
  }
  else { // does not
    if(!d_ttl) {
      (*statnummiss)++;
      d_miss++;
      return 0;
    }
  }
    
  bool packetMeritsRecursion=d_doRecursion && p->d.rd;
  char ckey[512];
  int len=p->qdomain.length();
  memcpy(ckey,p->qdomain.c_str(),len); // add TOLOWER HERE FIXME XXX
  ckey[len]='|';
  ckey[len+1]=packetMeritsRecursion ? 'r' : 'n';
  ckey[len+2]=(p->qtype.getCode()>>8)&0xff;
  ckey[len+3]=(p->qtype.getCode())&0xff;
  string key;

  key.assign(ckey,p->qdomain.length()+4);
  //  cout<<"key lookup: '"<<key<<"'"<<endl;
  //  string key=toLower(p->qdomain+"|"+(packetMeritsRecursion ? "R" : "N")+ "|"+p->qtype.getName());

  if(ntohs(p->d.qdcount)!=1) // we get confused by packets with more than one question
    return 0;

  {
    TryReadLock l(&d_mut); // take a readlock here
    if(!l.gotIt()) {
      S.inc("deferred-cache-lookup");
      return 0;
    }

    if(!((d_hit+d_miss)%1000)) {
      *statnumentries=d_map.size(); // needs lock
    }
    cmap_t::const_iterator i;
    if((i=d_map.find(key))!=d_map.end()) { // HIT!

      if(i->second.ttd>time(0)) { // it is still fresh
	(*statnumhit)++;
	d_hit++;
	cached->parse(i->second.value.c_str(),i->second.value.size());  
	cached->spoofQuestion(p->qdomain); // for correct case
	return 1;
      }
    }
  }
  (*statnummiss)++;
  d_miss++;
  return 0; // bummer
}


#endif /* PACKETCACHE_HH */

