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

#include <atomic>
#include <unordered_map>
#include "lock.hh"

struct DNSQuestion;

class DNSDistPacketCache : boost::noncopyable
{
public:
  DNSDistPacketCache(size_t maxEntries, uint32_t maxTTL=86400, uint32_t minTTL=0, uint32_t tempFailureTTL=60, uint32_t staleTTL=60);
  ~DNSDistPacketCache();

  void insert(uint32_t key, const DNSName& qname, uint16_t qtype, uint16_t qclass, const char* response, uint16_t responseLen, bool tcp, uint8_t rcode);
  bool get(const DNSQuestion& dq, uint16_t consumed, uint16_t queryId, char* response, uint16_t* responseLen, uint32_t* keyOut, uint32_t allowExpired=0, bool skipAging=false);
  void purgeExpired(size_t upTo=0);
  void expunge(size_t upTo=0);
  void expungeByName(const DNSName& name, uint16_t qtype=QType::ANY);
  bool isFull();
  string toString();
  uint64_t getSize() const { return d_map.size(); }
  uint64_t getHits() const { return d_hits; }
  uint64_t getMisses() const { return d_misses; }
  uint64_t getDeferredLookups() const { return d_deferredLookups; }
  uint64_t getDeferredInserts() const { return d_deferredInserts; }
  uint64_t getLookupCollisions() const { return d_lookupCollisions; }
  uint64_t getInsertCollisions() const { return d_insertCollisions; }
  uint64_t getMaxEntries() const { return d_maxEntries; }
  uint64_t getTTLTooShorts() const { return d_ttlTooShorts; }
  uint64_t getEntriesCount();

  static uint32_t getMinTTL(const char* packet, uint16_t length);

private:

  struct CacheValue
  {
    time_t getTTD() const { return validity; }
    std::string value;
    DNSName qname;
    uint16_t qtype{0};
    uint16_t qclass{0};
    time_t added{0};
    time_t validity{0};
    uint16_t len{0};
    bool tcp{false};
  };

  static uint32_t getKey(const DNSName& qname, uint16_t consumed, const unsigned char* packet, uint16_t packetLen, bool tcp);
  static bool cachedValueMatches(const CacheValue& cachedValue, const DNSName& qname, uint16_t qtype, uint16_t qclass, bool tcp);

  pthread_rwlock_t d_lock;
  std::unordered_map<uint32_t,CacheValue> d_map;
  std::atomic<uint64_t> d_deferredLookups{0};
  std::atomic<uint64_t> d_deferredInserts{0};
  std::atomic<uint64_t> d_hits{0};
  std::atomic<uint64_t> d_misses{0};
  std::atomic<uint64_t> d_insertCollisions{0};
  std::atomic<uint64_t> d_lookupCollisions{0};
  std::atomic<uint64_t> d_ttlTooShorts{0};
  size_t d_maxEntries;
  uint32_t d_maxTTL;
  uint32_t d_tempFailureTTL;
  uint32_t d_minTTL;
  uint32_t d_staleTTL;
};
