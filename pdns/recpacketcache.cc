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

bool RecursorPacketCache::qrMatch(const packetCache_t::index<HashTag>::type::iterator& iter, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, uint16_t ecsBegin, uint16_t ecsEnd)
{
  // this ignores checking on the EDNS subnet flags! 
  if (qname != iter->d_name || iter->d_type != qtype || iter->d_class != qclass) {
    return false;
  }

  if (iter->d_ecsBegin != ecsBegin || iter->d_ecsEnd != ecsEnd) {
    return false;
  }

  return queryMatches(iter->d_query, queryPacket, qname, ecsBegin, ecsEnd);
}

bool RecursorPacketCache::checkResponseMatches(std::pair<packetCache_t::index<HashTag>::type::iterator, packetCache_t::index<HashTag>::type::iterator> range, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, time_t now, std::string* responsePacket, uint32_t* age, vState* valState, RecProtoBufMessage* protobufMessage, uint16_t ecsBegin, uint16_t ecsEnd)
{
  for(auto iter = range.first ; iter != range.second ; ++iter) {
    // the possibility is VERY real that we get hits that are not right - birthday paradox
    if (!qrMatch(iter, queryPacket, qname, qtype, qclass, ecsBegin, ecsEnd)) {
      continue;
    }

    if (now < iter->d_ttd) { // it is right, it is fresh!
      *age = static_cast<uint32_t>(now - iter->d_creation);
      *responsePacket = iter->d_packet;
      responsePacket->replace(0, 2, queryPacket.c_str(), 2);
      *valState = iter->d_vstate;
    
      const size_t wirelength = qname.wirelength();
      if (responsePacket->size() > (sizeof(dnsheader) + wirelength)) {
        responsePacket->replace(sizeof(dnsheader), wirelength, queryPacket, sizeof(dnsheader), wirelength);
      }

      d_hits++;
      moveCacheItemToBack(d_packetCache, iter);
#ifdef HAVE_PROTOBUF
      if (protobufMessage) {
        if (iter->d_protobufMessage) {
          protobufMessage->copyFrom(*(iter->d_protobufMessage));
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
  uint16_t ecsBegin;
  uint16_t ecsEnd;
  vState valState;
  return getResponsePacket(tag, queryPacket, qname, &qtype, &qclass, now, responsePacket, age, &valState, qhash, &ecsBegin, &ecsEnd, nullptr);
}

bool RecursorPacketCache::getResponsePacket(unsigned int tag, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, time_t now,
                                            std::string* responsePacket, uint32_t* age, uint32_t* qhash)
{
  vState valState;
  uint16_t ecsBegin;
  uint16_t ecsEnd;
  return getResponsePacket(tag, queryPacket, qname, qtype, qclass, now, responsePacket, age, &valState, qhash, &ecsBegin, &ecsEnd, nullptr);
}

bool RecursorPacketCache::getResponsePacket(unsigned int tag, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, time_t now,
                                            std::string* responsePacket, uint32_t* age, vState* valState, uint32_t* qhash, uint16_t* ecsBegin, uint16_t* ecsEnd, RecProtoBufMessage* protobufMessage)
{
  *qhash = canHashPacket(queryPacket, ecsBegin, ecsEnd);
  const auto& idx = d_packetCache.get<HashTag>();
  auto range = idx.equal_range(tie(tag,*qhash));

  if(range.first == range.second) {
    d_misses++;
    return false;
  }

  return checkResponseMatches(range, queryPacket, qname, qtype, qclass, now, responsePacket, age, valState, protobufMessage, *ecsBegin, *ecsEnd);
}

bool RecursorPacketCache::getResponsePacket(unsigned int tag, const std::string& queryPacket, DNSName& qname, uint16_t* qtype, uint16_t* qclass, time_t now,
                                            std::string* responsePacket, uint32_t* age, vState* valState, uint32_t* qhash, uint16_t* ecsBegin, uint16_t* ecsEnd, RecProtoBufMessage* protobufMessage)
{
  *qhash = canHashPacket(queryPacket, ecsBegin, ecsEnd);
  const auto& idx = d_packetCache.get<HashTag>();
  auto range = idx.equal_range(tie(tag,*qhash));

  if(range.first == range.second) {
    d_misses++;
    return false;
  }

  qname = DNSName(queryPacket.c_str(), queryPacket.length(), sizeof(dnsheader), false, qtype, qclass, 0);

  return checkResponseMatches(range, queryPacket, qname, *qtype, *qclass, now, responsePacket, age, valState, protobufMessage, *ecsBegin, *ecsEnd);
}


void RecursorPacketCache::insertResponsePacket(unsigned int tag, uint32_t qhash, std::string&& query, const DNSName& qname, uint16_t qtype, uint16_t qclass, std::string&& responsePacket, time_t now, uint32_t ttl, const vState& valState, uint16_t ecsBegin, uint16_t ecsEnd, boost::optional<RecProtoBufMessage>&& protobufMessage)
{
  auto& idx = d_packetCache.get<HashTag>();
  auto range = idx.equal_range(tie(tag,qhash));
  auto iter = range.first;

  for( ; iter != range.second ; ++iter)  {
    if (iter->d_type != qtype || iter->d_class != qclass || iter->d_name != qname) {
      continue;
    }

    moveCacheItemToBack(d_packetCache, iter);
    iter->d_packet = std::move(responsePacket);
    iter->d_query = std::move(query);
    iter->d_ecsBegin = ecsBegin;
    iter->d_ecsEnd = ecsEnd;
    iter->d_ttd = now + ttl;
    iter->d_creation = now;
    iter->d_vstate = valState;
#ifdef HAVE_PROTOBUF
    if (protobufMessage) {
      iter->d_protobufMessage = std::move(*protobufMessage);
    }
#endif

    break;
  }
  
  if(iter == range.second) { // nothing to refresh
    struct Entry e(qname, std::move(responsePacket), std::move(query));
    e.d_qhash = qhash;
    e.d_ecsBegin = ecsBegin;
    e.d_ecsEnd = ecsEnd;
    e.d_type = qtype;
    e.d_class = qclass;
    e.d_ttd = now+ttl;
    e.d_creation = now;
    e.d_tag = tag;
    e.d_vstate = valState;
#ifdef HAVE_PROTOBUF
    if (protobufMessage) {
      e.d_protobufMessage = std::move(*protobufMessage);
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
  auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fdopen(dup(fd), "w"), fclose);
  if(!fp) { // dup probably failed
    return 0;
  }
  fprintf(fp.get(), "; main packet cache dump from thread follows\n;\n");
  const auto& sidx=d_packetCache.get<1>();

  uint64_t count=0;
  time_t now=time(0);
  for(auto i=sidx.cbegin(); i != sidx.cend(); ++i) {
    count++;
    try {
      fprintf(fp.get(), "%s %" PRId64 " %s  ; tag %d\n", i->d_name.toString().c_str(), static_cast<int64_t>(i->d_ttd - now), DNSRecordContent::NumberToType(i->d_type).c_str(), i->d_tag);
    }
    catch(...) {
      fprintf(fp.get(), "; error printing '%s'\n", i->d_name.empty() ? "EMPTY" : i->d_name.toString().c_str());
    }
  }
  return count;

}
