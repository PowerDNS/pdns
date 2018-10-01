#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <iostream>
#include <cinttypes>

#include "recpacketcache.hh"
#include "cachecleaner.hh"
#include "dns.hh"
#include "namespaces.hh"

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

static bool qrMatch(const DNSName& qname, uint16_t qtype, uint16_t qclass, const DNSName& rname, uint16_t rtype, uint16_t rclass)
{
  // this ignores checking on the EDNS subnet flags! 
  return qname==rname && rtype == qtype && rclass == qclass;
}

bool RecursorPacketCache::checkResponseMatches(std::pair<packetCache_t::index<HashTag>::type::iterator, packetCache_t::index<HashTag>::type::iterator> range, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, time_t now, std::string* responsePacket, uint32_t* age, vState* valState, RecProtoBufMessage* protobufMessage)
{
  for(auto iter = range.first ; iter != range.second ; ++ iter) {
    // the possibility is VERY real that we get hits that are not right - birthday paradox
    if(!qrMatch(qname, qtype, qclass, iter->d_name, iter->d_type, iter->d_class))
      continue;
    if(now < iter->d_ttd) { // it is right, it is fresh!
      *age = static_cast<uint32_t>(now - iter->d_creation);
      *responsePacket = iter->d_packet;
      responsePacket->replace(0, 2, queryPacket.c_str(), 2);
      *valState = iter->d_vstate;
    
      string::size_type i=sizeof(dnsheader);
      
      for(;;) {
        unsigned int labellen = (unsigned char)queryPacket[i];
        if(!labellen || i + labellen > responsePacket->size()) break;
        i++;
        responsePacket->replace(i, labellen, queryPacket, i, labellen);
        i = i + labellen;
      }

      d_hits++;
      moveCacheItemToBack(d_packetCache, iter);
#ifdef HAVE_PROTOBUF
      if (protobufMessage) {
        if (iter->d_protobufMessage) {
          *protobufMessage = *(iter->d_protobufMessage);
        }
        else {
          *protobufMessage = RecProtoBufMessage(DNSProtoBufMessage::DNSProtoBufMessageType::Response);
        }
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

bool RecursorPacketCache::getResponsePacket(unsigned int tag, const std::string& queryPacket, time_t now,
                                            std::string* responsePacket, uint32_t* age, uint32_t* qhash)
{
  DNSName qname;
  uint16_t qtype, qclass;
  vState valState;
  return getResponsePacket(tag, queryPacket, qname, &qtype, &qclass, now, responsePacket, age, &valState, qhash, nullptr);
}

bool RecursorPacketCache::getResponsePacket(unsigned int tag, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, time_t now,
                                            std::string* responsePacket, uint32_t* age, uint32_t* qhash)
{
  vState valState;
  return getResponsePacket(tag, queryPacket, qname, qtype, qclass, now, responsePacket, age, &valState, qhash, nullptr);
}

bool RecursorPacketCache::getResponsePacket(unsigned int tag, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, time_t now,
                                            std::string* responsePacket, uint32_t* age, vState* valState, uint32_t* qhash, RecProtoBufMessage* protobufMessage)
{
  *qhash = canHashPacket(queryPacket, true);
  const auto& idx = d_packetCache.get<HashTag>();
  auto range = idx.equal_range(tie(tag,*qhash));

  if(range.first == range.second) {
    d_misses++;
    return false;
  }
  return checkResponseMatches(range, queryPacket, qname, qtype, qclass, now, responsePacket, age, valState, protobufMessage);
}

bool RecursorPacketCache::getResponsePacket(unsigned int tag, const std::string& queryPacket, DNSName& qname, uint16_t* qtype, uint16_t* qclass, time_t now,
                                            std::string* responsePacket, uint32_t* age, vState* valState, uint32_t* qhash, RecProtoBufMessage* protobufMessage)
{
  *qhash = canHashPacket(queryPacket, true);
  const auto& idx = d_packetCache.get<HashTag>();
  auto range = idx.equal_range(tie(tag,*qhash));

  if(range.first == range.second) {
    d_misses++;
    return false;
  }

  qname = DNSName(queryPacket.c_str(), queryPacket.length(), sizeof(dnsheader), false, qtype, qclass, 0);

  return checkResponseMatches(range, queryPacket, qname, *qtype, *qclass, now, responsePacket, age, valState, protobufMessage);
}


void RecursorPacketCache::insertResponsePacket(unsigned int tag, uint32_t qhash, const DNSName& qname, uint16_t qtype, uint16_t qclass, const std::string& responsePacket, time_t now, uint32_t ttl)
{
  vState valState;
  boost::optional<RecProtoBufMessage> pb(boost::none);
  insertResponsePacket(tag, qhash, qname, qtype, qclass, responsePacket, now, ttl, valState, pb);
}

void RecursorPacketCache::insertResponsePacket(unsigned int tag, uint32_t qhash, const DNSName& qname, uint16_t qtype, uint16_t qclass, const std::string& responsePacket, time_t now, uint32_t ttl, const vState& valState, const boost::optional<RecProtoBufMessage>& protobufMessage)
{
  auto& idx = d_packetCache.get<HashTag>();
  auto range = idx.equal_range(tie(tag,qhash));
  auto iter = range.first;

  for( ; iter != range.second ; ++iter)  {
    if(iter->d_type != qtype || iter->d_class != qclass || iter->d_name != qname)
      continue;

    moveCacheItemToBack(d_packetCache, iter);
    iter->d_packet = responsePacket;
    iter->d_ttd = now + ttl;
    iter->d_creation = now;
    iter->d_vstate = valState;
#ifdef HAVE_PROTOBUF
    if (protobufMessage) {
      iter->d_protobufMessage = *protobufMessage;
    }
#endif

    break;
  }
  
  if(iter == range.second) { // nothing to refresh
    struct Entry e(qname, responsePacket);
    e.d_qhash = qhash;
    e.d_type = qtype;
    e.d_class = qclass;
    e.d_ttd = now+ttl;
    e.d_creation = now;
    e.d_tag = tag;
    e.d_vstate = valState;
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
  pruneCollection(*this, d_packetCache, maxCached);
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
      fprintf(fp, "%s %" PRId64 " %s  ; tag %d\n", i->d_name.toString().c_str(), static_cast<int64_t>(i->d_ttd - now), DNSRecordContent::NumberToType(i->d_type).c_str(), i->d_tag);
    }
    catch(...) {
      fprintf(fp, "; error printing '%s'\n", i->d_name.empty() ? "EMPTY" : i->d_name.toString().c_str());
    }
  }
  fclose(fp);
  return count;

}
