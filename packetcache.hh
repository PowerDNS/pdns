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

  void insert(const string &key, const string &packet, unsigned int ttl);

  int get(DNSPacket *p, DNSPacket *q); //!< We return a dynamically allocated copy out of our cache. You need to delete it. You also need to spoof in the right ID with the DNSPacket.spoofID() method.
  bool getKey(const string &key, string &content);
  int size(); //!< number of entries in the cache
  void cleanup(); //!< force the cache to preen itself from expired packets
  int purge(const string &prefix="");

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
  typedef map< ckey_t, cvalue_t > cmap_t;

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



#endif /* PACKETCACHE_HH */

