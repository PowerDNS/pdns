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

// one day this function could be really fast by doing only a case insensitive compare
static bool qrMatch(const std::string& query, const std::string& response)
{
  uint16_t rqtype, rqclass, qqtype, qqclass;
  DNSName queryname(query.c_str(), query.length(), sizeof(dnsheader), false, &qqtype, &qqclass, 0);
  DNSName respname(response.c_str(), response.length(), sizeof(dnsheader), false, &rqtype, &rqclass, 0);
  // this ignores checking on the EDNS subnet flags! 
  return queryname==respname && rqtype == qqtype && rqclass == qqclass;
}

uint32_t RecursorPacketCache::canHashPacket(const std::string& origPacket)
{
  //  return 42; // should still work if you do this!
  uint32_t ret=0;
  ret=burtle((const unsigned char*)origPacket.c_str() + 2, 10, ret); // rest of dnsheader, skip id
  const char* end = origPacket.c_str() + origPacket.size();
  const char* p = origPacket.c_str() + 12;

  for(; p < end && *p; ++p) { // XXX if you embed a 0 in your qname we'll stop lowercasing there
    const char l = dns_tolower(*p); // label lengths can safely be lower cased
    ret=burtle((const unsigned char*)&l, 1, ret);
  }                           // XXX the embedded 0 in the qname will break the subnet stripping

  struct dnsheader* dh = (struct dnsheader*)origPacket.c_str();
  const char* skipBegin = p;
  const char* skipEnd = p;
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
    int res = getEDNSOption((char*) p + 14, end - (p + 14), EDNSOptionCode::ECS, &optionBegin, &optionLen);
    if (res == 0) {
      skipBegin = optionBegin;
      skipEnd = optionBegin + optionLen;
    }
  }
  if (skipBegin > p) {
    //cout << "Hashing from " << (p-origPacket.c_str()) << " for " << skipBegin-p << "bytes, end is at "<< end-origPacket.c_str() << endl;
    ret = burtle((const unsigned char*)p, skipBegin-p, ret);
  }
  if (skipEnd < end) {
    //cout << "Hashing from " << (skipEnd-origPacket.c_str()) << " for " << end-skipEnd << "bytes, end is at " << end-origPacket.c_str() << endl;
    ret = burtle((const unsigned char*) skipEnd, end-skipEnd, ret);
  }
  return ret;
}

bool RecursorPacketCache::getResponsePacket(unsigned int tag, const std::string& queryPacket, time_t now,
                                            std::string* responsePacket, uint32_t* age)
{
  return getResponsePacket(tag, queryPacket, now, responsePacket, age, nullptr);
}

bool RecursorPacketCache::getResponsePacket(unsigned int tag, const std::string& queryPacket, time_t now,
                                            std::string* responsePacket, uint32_t* age, RecProtoBufMessage* protobufMessage)
{
  uint32_t h = canHashPacket(queryPacket);
  auto& idx = d_packetCache.get<HashTag>();
  auto range = idx.equal_range(tie(tag,h)); 

  if(range.first == range.second) {
    d_misses++;
    return false;
  }
    
  for(auto iter = range.first ; iter != range.second ; ++ iter) {
    // the possibility is VERY real that we get hits that are not right - birthday paradox
    if(!qrMatch(queryPacket, iter->d_packet))
      continue;
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


void RecursorPacketCache::insertResponsePacket(unsigned int tag, const DNSName& qname, uint16_t qtype, const std::string& queryPacket, const std::string& responsePacket, time_t now, uint32_t ttl)
{
  insertResponsePacket(tag, qname, qtype, queryPacket, responsePacket, now, ttl, nullptr);
}

void RecursorPacketCache::insertResponsePacket(unsigned int tag, const DNSName& qname, uint16_t qtype, const std::string& queryPacket, const std::string& responsePacket, time_t now, uint32_t ttl, const RecProtoBufMessage* protobufMessage)
{
  auto qhash = canHashPacket(queryPacket);
  auto& idx = d_packetCache.get<HashTag>();
  auto range = idx.equal_range(tie(tag,qhash));
  auto iter = range.first;

  for( ; iter != range.second ; ++iter)  {
    if(iter->d_type != qtype)
      continue;
    // this only happens on insert which is relatively rare and does not need to be super fast
    DNSName respname(iter->d_packet.c_str(), iter->d_packet.length(), sizeof(dnsheader), false, 0, 0, 0);
    if(qname != respname)
      continue;
    moveCacheItemToBack(d_packetCache, iter);
    iter->d_packet = responsePacket;
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
    e.d_name = qname;
    e.d_qhash = qhash;
    e.d_type = qtype;
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
  for(const struct Entry& e :  d_packetCache) {
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
