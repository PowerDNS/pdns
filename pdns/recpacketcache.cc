#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <iostream>

#include "recpacketcache.hh"
#include "cachecleaner.hh"
#include "dns.hh"
#include "dnsparser.hh"
#include "namespaces.hh"
#include "lock.hh"
#include "dnswriter.hh"
#include "ednsoptions.hh"

RecursorPacketCache::RecursorPacketCache()
{
  d_hits = d_misses = 0;
}

int RecursorPacketCache::doWipePacketCache(const DNSName& name, uint16_t qtype, bool subtree)
{
  int count=0;
  auto& idx = d_packetCache.get<NameTag>();
  for(auto iter = idx.lower_bound(name); iter != idx.end(); ) {
    if(subtree) {
      if(!iter->d_name.isPartOf(name)) {   // this is case insensitive
	break;
      }
    }
    else {
      if(iter->d_name != name)
	break;
    }
    
    if(qtype==0xffff || iter->d_type == qtype) {
      iter=idx.erase(iter);
      count++;
    }
    else
      ++iter;
  }
  return count;
}

static bool queryHeaderMatches(const std::string& cachedQuery, const std::string& query)
{
  if (cachedQuery.size() != query.size()) {
    return false;
  }

  return (cachedQuery.compare(/* skip the ID */ 2, sizeof(dnsheader) - 2, query, 2, sizeof(dnsheader) - 2) == 0);
}

bool RecursorPacketCache::queryMatches(const std::string& cachedQuery, const std::string& query, const DNSName& qname, uint16_t ecsBegin, uint16_t ecsEnd)
{
  if (!queryHeaderMatches(cachedQuery, query)) {
    return false;
  }

  size_t pos = sizeof(dnsheader) + qname.wirelength();

  if (ecsBegin != 0 && ecsBegin >= pos && ecsEnd > ecsBegin) {
    if (cachedQuery.compare(pos, ecsBegin - pos, query, pos, ecsBegin - pos) != 0) {
      return false;
    }

    if (cachedQuery.compare(ecsEnd, cachedQuery.size() - ecsEnd, query, ecsEnd, query.size() - ecsEnd) != 0) {
      return false;
    }
  }
  else {
    if (cachedQuery.compare(pos, cachedQuery.size() - pos, query, pos, query.size() - pos) != 0) {
      return false;
    }
  }

  return true;
}

// one day this function could be really fast by doing only a case insensitive compare
bool RecursorPacketCache::qrMatch(const packetCache_t::index<HashTag>::type::iterator& iter, const std::string& queryPacket, uint16_t ecsBegin, uint16_t ecsEnd)
{
  uint16_t qqtype, qqclass;
  DNSName queryname(queryPacket.c_str(), queryPacket.length(), sizeof(dnsheader), false, &qqtype, &qqclass, 0);
  // this ignores checking on the EDNS subnet flags! 
  if (qqtype != iter->d_type || qqclass != iter->d_class || queryname != iter->d_name) {
    return false;
  }

  if (iter->d_ecsBegin != ecsBegin || iter->d_ecsEnd != ecsEnd) {
    return false;
  }

  return queryMatches(iter->d_query, queryPacket, queryname, ecsBegin, ecsEnd);
}

uint32_t RecursorPacketCache::canHashPacket(const std::string& origPacket, uint16_t* ecsBegin, uint16_t* ecsEnd)
{
  //  return 42; // should still work if you do this!
  uint32_t ret=0;
  ret = burtle(reinterpret_cast<const unsigned char*>(origPacket.c_str()) + 2, sizeof(dnsheader) - 2, ret); // rest of dnsheader, skip id
  const char* end = origPacket.c_str() + origPacket.size();
  const char* p = origPacket.c_str() + sizeof(dnsheader);

  for(; p < end && *p; ++p) { // XXX if you embed a 0 in your qname we'll stop lowercasing there
    const char l = dns_tolower(*p); // label lengths can safely be lower cased
    ret=burtle((const unsigned char*)&l, 1, ret);
  }                           // XXX the embedded 0 in the qname will break the subnet stripping

  const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(origPacket.c_str());
  const char* skipBegin = p;
  const char* skipEnd = p;
  if (ecsBegin != nullptr && ecsEnd != nullptr) {
    *ecsBegin = 0;
    *ecsEnd = 0;
  }
  /* we need at least 1 (final empty label) + 2 (QTYPE) + 2 (QCLASS)
     + OPT root label (1), type (2), class (2) and ttl (4)
     + the OPT RR rdlen (2)
     = 16
  */
  if(ntohs(dh->arcount)==1 && (p+16) < end) {
    char* optionBegin = nullptr;
    size_t optionLen = 0;
    /* skip the final empty label (1), the qtype (2), qclass (2) */
    /* root label (1), type (2), class (2) and ttl (4) */
    int res = getEDNSOption(const_cast<char*>(reinterpret_cast<const char*>(p)) + 14, end - (p + 14), EDNSOptionCode::ECS, &optionBegin, &optionLen);
    if (res == 0) {
      skipBegin = optionBegin;
      skipEnd = optionBegin + optionLen;
      if (ecsBegin != nullptr && ecsEnd != nullptr) {
        *ecsBegin = optionBegin - origPacket.c_str();
        *ecsEnd = *ecsBegin + optionLen;
      }
    }
  }
  if (skipBegin > p) {
    //cout << "Hashing from " << (p-origPacket.c_str()) << " for " << skipBegin-p << "bytes, end is at "<< end-origPacket.c_str() << endl;
    ret = burtle(reinterpret_cast<const unsigned char*>(p), skipBegin-p, ret);
  }
  if (skipEnd < end) {
    //cout << "Hashing from " << (skipEnd-origPacket.c_str()) << " for " << end-skipEnd << "bytes, end is at " << end-origPacket.c_str() << endl;
    ret = burtle(reinterpret_cast<const unsigned char*>(skipEnd), end-skipEnd, ret);
  }
  return ret;
}

bool RecursorPacketCache::getResponsePacket(unsigned int tag, const std::string& queryPacket, time_t now,
                                            std::string* responsePacket, uint32_t* age, RecProtoBufMessage* protobufMessage)
{
  uint16_t ecsBegin = 0;
  uint16_t ecsEnd = 0;
  uint32_t h = canHashPacket(queryPacket, &ecsBegin, &ecsEnd);
  auto& idx = d_packetCache.get<HashTag>();
  auto range = idx.equal_range(tie(tag,h)); 

  if(range.first == range.second) {
    d_misses++;
    return false;
  }

  for(auto iter = range.first ; iter != range.second ; ++ iter) {
    // the possibility is VERY real that we get hits that are not right - birthday paradox
    if(!qrMatch(iter, queryPacket, ecsBegin, ecsEnd)) {
      continue;
    }

    if((uint32_t)now < iter->d_ttd) { // it is right, it is fresh!
      *age = now - iter->d_creation;
      *responsePacket = iter->d_packet;
      responsePacket->replace(0, 2, queryPacket.c_str(), 2);
    
      string::size_type i=sizeof(dnsheader);
      
      for(;;) {
        int labellen = (unsigned char)queryPacket[i];
        if(!labellen || i + labellen > responsePacket->size()) break;
        i++;
        responsePacket->replace(i, labellen, queryPacket, i, labellen);
        i = i + labellen;
      }

      d_hits++;
      moveCacheItemToBack(d_packetCache, iter);
#ifdef HAVE_PROTOBUF
      if (protobufMessage) {
        *protobufMessage = iter->d_protobufMessage;
      }
#endif
      
      return true;
    }
    else {
      moveCacheItemToFront(d_packetCache, iter); 
      d_misses++;
      break;
    }
  }

  return false;
}


void RecursorPacketCache::insertResponsePacket(unsigned int tag, const DNSName& qname, uint16_t qtype, uint16_t qclass, const std::string& queryPacket, const std::string& responsePacket, time_t now, uint32_t ttl, const RecProtoBufMessage* protobufMessage)
{
  uint16_t ecsBegin = 0;
  uint16_t ecsEnd = 0;
  auto qhash = canHashPacket(queryPacket, &ecsBegin, &ecsEnd);
  auto& idx = d_packetCache.get<HashTag>();
  auto range = idx.equal_range(tie(tag,qhash));
  auto iter = range.first;

  for( ; iter != range.second ; ++iter)  {
    if(iter->d_type != qtype || iter->d_class != qclass) {
      continue;
    }

    // this only happens on insert which is relatively rare and does not need to be super fast
    DNSName respname(iter->d_packet.c_str(), iter->d_packet.length(), sizeof(dnsheader), false, 0, 0, 0);
    if(qname != respname) {
      continue;
    }
    moveCacheItemToBack(d_packetCache, iter);
    iter->d_packet = responsePacket;
    iter->d_query = queryPacket;
    iter->d_ecsBegin = ecsBegin;
    iter->d_ecsEnd = ecsEnd;
    iter->d_ttd = now + ttl;
    iter->d_creation = now;
#ifdef HAVE_PROTOBUF
    if (protobufMessage) {
      iter->d_protobufMessage = *protobufMessage;
    }
#endif

    break;
  }
  
  if(iter == range.second) { // nothing to refresh
    struct Entry e;
    e.d_packet = responsePacket;
    e.d_query = queryPacket;
    e.d_name = qname;
    e.d_qhash = qhash;
    e.d_type = qtype;
    e.d_class = qclass;
    e.d_ecsBegin = ecsBegin;
    e.d_ecsEnd = ecsEnd;
    e.d_ttd = now+ttl;
    e.d_creation = now;
    e.d_tag = tag;
#ifdef HAVE_PROTOBUF
    if (protobufMessage) {
      e.d_protobufMessage = *protobufMessage;
    }
#endif
    d_packetCache.insert(e);
  }
}

uint64_t RecursorPacketCache::size()
{
  return d_packetCache.size();
}

uint64_t RecursorPacketCache::bytes()
{
  uint64_t sum=0;
  for(const auto& e :  d_packetCache) {
    sum += sizeof(e) + e.d_packet.length() + 4;
  }
  return sum;
}

void RecursorPacketCache::doPruneTo(unsigned int maxCached)
{
  pruneCollection(d_packetCache, maxCached);
}

uint64_t RecursorPacketCache::doDump(int fd)
{
  FILE* fp=fdopen(dup(fd), "w");
  if(!fp) { // dup probably failed
    return 0;
  }
  fprintf(fp, "; main packet cache dump from thread follows\n;\n");
  const auto& sidx=d_packetCache.get<1>();

  uint64_t count=0;
  time_t now=time(0);
  for(auto i=sidx.cbegin(); i != sidx.cend(); ++i) {
    count++;
    try {
      fprintf(fp, "%s %d %s  ; tag %d\n", i->d_name.toString().c_str(), (int32_t)(i->d_ttd - now), DNSRecordContent::NumberToType(i->d_type).c_str(), i->d_tag);
    }
    catch(...) {
      fprintf(fp, "; error printing '%s'\n", i->d_name.empty() ? "EMPTY" : i->d_name.toString().c_str());
    }
  }
  fclose(fp);
  return count;

}
