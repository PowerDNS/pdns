#include "dnsdist.hh"
#include "dolog.hh"
#include "dnsparser.hh"
#include "dnsdist-cache.hh"

DNSDistPacketCache::DNSDistPacketCache(size_t maxEntries, uint32_t maxTTL, uint32_t minTTL, uint32_t servFailTTL, uint32_t staleTTL): d_maxEntries(maxEntries), d_maxTTL(maxTTL), d_servFailTTL(servFailTTL), d_minTTL(minTTL), d_staleTTL(staleTTL)
{
  pthread_rwlock_init(&d_lock, 0);
  /* we reserve maxEntries + 1 to avoid rehashing from occuring
     when we get to maxEntries, as it means a load factor of 1 */
  d_map.reserve(maxEntries + 1);
}

DNSDistPacketCache::~DNSDistPacketCache()
{
  WriteLock l(&d_lock);
}

bool DNSDistPacketCache::cachedValueMatches(const CacheValue& cachedValue, const DNSName& qname, uint16_t qtype, uint16_t qclass, bool tcp)
{
  if (cachedValue.tcp != tcp || cachedValue.qtype != qtype || cachedValue.qclass != qclass || cachedValue.qname != qname)
    return false;
  return true;
}

void DNSDistPacketCache::insert(uint32_t key, const DNSName& qname, uint16_t qtype, uint16_t qclass, const char* response, uint16_t responseLen, bool tcp, bool servFail)
{
  if (responseLen < sizeof(dnsheader))
    return;

  uint32_t minTTL;

  if (servFail) {
    minTTL = d_servFailTTL;
  }
  else {
    minTTL = getMinTTL(response, responseLen);
    if (minTTL > d_maxTTL)
      minTTL = d_maxTTL;

    if (minTTL < d_minTTL) {
      d_ttlTooShorts++;
      return;
    }
  }

  {
    TryReadLock r(&d_lock);
    if (!r.gotIt()) {
      d_deferredInserts++;
      return;
    }
    if (d_map.size() >= d_maxEntries) {
      return;
    }
  }

  const time_t now = time(NULL);
  std::unordered_map<uint32_t,CacheValue>::iterator it;
  bool result;
  time_t newValidity = now + minTTL;
  CacheValue newValue;
  newValue.qname = qname;
  newValue.qtype = qtype;
  newValue.qclass = qclass;
  newValue.len = responseLen;
  newValue.validity = newValidity;
  newValue.added = now;
  newValue.tcp = tcp;
  newValue.value = std::string(response, responseLen);

  {
    TryWriteLock w(&d_lock);

    if (!w.gotIt()) {
      d_deferredInserts++;
      return;
    }

    tie(it, result) = d_map.insert({key, newValue});

    if (result) {
      return;
    }

    /* in case of collision, don't override the existing entry
       except if it has expired */
    CacheValue& value = it->second;
    bool wasExpired = value.validity <= now;

    if (!wasExpired && !cachedValueMatches(value, qname, qtype, qclass, tcp)) {
      d_insertCollisions++;
      return;
    }

    /* if the existing entry had a longer TTD, keep it */
    if (newValidity <= value.validity) {
      return;
    }

    value = newValue;
  }
}

bool DNSDistPacketCache::get(const DNSQuestion& dq, uint16_t consumed, uint16_t queryId, char* response, uint16_t* responseLen, uint32_t* keyOut, uint32_t allowExpired, bool skipAging)
{
  uint32_t key = getKey(*dq.qname, consumed, (const unsigned char*)dq.dh, dq.len, dq.tcp);
  if (keyOut)
    *keyOut = key;

  time_t now = time(NULL);
  time_t age;
  bool stale = false;
  {
    TryReadLock r(&d_lock);
    if (!r.gotIt()) {
      d_deferredLookups++;
      return false;
    }

    std::unordered_map<uint32_t,CacheValue>::const_iterator it = d_map.find(key);
    if (it == d_map.end()) {
      d_misses++;
      return false;
    }

    const CacheValue& value = it->second;
    if (value.validity < now) {
      if ((now - value.validity) >= static_cast<time_t>(allowExpired)) {
        d_misses++;
        return false;
      }
      else {
        stale = true;
      }
    }

    if (*responseLen < value.len) {
      return false;
    }

    /* check for collision */
    if (!cachedValueMatches(value, *dq.qname, dq.qtype, dq.qclass, dq.tcp)) {
      d_lookupCollisions++;
      return false;
    }

    string dnsQName(dq.qname->toDNSString());
    const size_t dnsQNameLen = dnsQName.length();
    if (value.len < (sizeof(dnsheader) + dnsQNameLen)) {
      return false;
    }

    memcpy(response, &queryId, sizeof(queryId));
    memcpy(response + sizeof(queryId), value.value.c_str() + sizeof(queryId), sizeof(dnsheader) - sizeof(queryId));
    memcpy(response + sizeof(dnsheader), dnsQName.c_str(), dnsQNameLen);
    if (value.len > (sizeof(dnsheader) + dnsQNameLen)) {
      memcpy(response + sizeof(dnsheader) + dnsQNameLen, value.value.c_str() + sizeof(dnsheader) + dnsQNameLen, value.len - (sizeof(dnsheader) + dnsQNameLen));
    }
    *responseLen = value.len;
    if (!stale) {
      age = now - value.added;
    }
    else {
      age = (value.validity - value.added) - d_staleTTL;
    }
  }

  if (!skipAging) {
    ageDNSPacket(response, *responseLen, age);
  }

  d_hits++;
  return true;
}

/* Remove expired entries, until the cache has at most
   upTo entries in it.
*/
void DNSDistPacketCache::purgeExpired(size_t upTo)
{
  time_t now = time(NULL);
  WriteLock w(&d_lock);
  if (upTo >= d_map.size()) {
    return;
  }

  size_t toRemove = d_map.size() - upTo;
  for(auto it = d_map.begin(); toRemove > 0 && it != d_map.end(); ) {
    const CacheValue& value = it->second;

    if (value.validity < now) {
        it = d_map.erase(it);
        --toRemove;
    } else {
      ++it;
    }
  }
}

/* Remove all entries, keeping only upTo
   entries in the cache */
void DNSDistPacketCache::expunge(size_t upTo)
{
  WriteLock w(&d_lock);

  if (upTo >= d_map.size()) {
    return;
  }

  size_t toRemove = d_map.size() - upTo;
  auto beginIt = d_map.begin();
  auto endIt = beginIt;
  std::advance(endIt, toRemove);
  d_map.erase(beginIt, endIt);
}

void DNSDistPacketCache::expungeByName(const DNSName& name, uint16_t qtype)
{
  WriteLock w(&d_lock);

  for(auto it = d_map.begin(); it != d_map.end(); ) {
    const CacheValue& value = it->second;
    uint16_t cqtype = 0;
    uint16_t cqclass = 0;
    DNSName cqname(value.value.c_str(), value.len, sizeof(dnsheader), false, &cqtype, &cqclass, nullptr);

    if (cqname == name && (qtype == QType::ANY || qtype == cqtype)) {
        it = d_map.erase(it);
    } else {
      ++it;
    }
  }
}

bool DNSDistPacketCache::isFull()
{
    ReadLock r(&d_lock);
    return (d_map.size() >= d_maxEntries);
}

uint32_t DNSDistPacketCache::getMinTTL(const char* packet, uint16_t length)
{
  return getDNSPacketMinTTL(packet, length);
}

uint32_t DNSDistPacketCache::getKey(const DNSName& qname, uint16_t consumed, const unsigned char* packet, uint16_t packetLen, bool tcp)
{
  uint32_t result = 0;
  /* skip the query ID */
  if (packetLen < sizeof(dnsheader))
    throw std::range_error("Computing packet cache key for an invalid packet size");
  result = burtle(packet + 2, sizeof(dnsheader) - 2, result);
  string lc(qname.toDNSStringLC());
  result = burtle((const unsigned char*) lc.c_str(), lc.length(), result);
  if (packetLen < sizeof(dnsheader) + consumed) {
    throw std::range_error("Computing packet cache key for an invalid packet");
  }
  if (packetLen > ((sizeof(dnsheader) + consumed))) {
    result = burtle(packet + sizeof(dnsheader) + consumed, packetLen - (sizeof(dnsheader) + consumed), result);
  }
  result = burtle((const unsigned char*) &tcp, sizeof(tcp), result);
  return result;
}

string DNSDistPacketCache::toString()
{
  ReadLock r(&d_lock);
  return std::to_string(d_map.size()) + "/" + std::to_string(d_maxEntries);
}

uint64_t DNSDistPacketCache::getEntriesCount()
{
  ReadLock r(&d_lock);
  return d_map.size();
}
