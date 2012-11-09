#include <iostream>
#include <boost/foreach.hpp>
#include "recpacketcache.hh"
#include "cachecleaner.hh"
#include "dns.hh"
#include "namespaces.hh"
#include "lock.hh"


RecursorPacketCache::RecursorPacketCache()
{
  d_hits = d_misses = 0;
}

int RecursorPacketCache::doWipePacketCache(const string& name, uint16_t qtype)
{
  int count=0;
  for(packetCache_t::iterator iter = d_packetCache.begin(); iter != d_packetCache.end();)
  {
    const struct dnsheader* packet = reinterpret_cast<const struct dnsheader*>((*iter).d_packet.c_str());
    if (packet->qdcount > 0) 
    {
	// find out type
	const struct dnsrecordheader *header = reinterpret_cast<const struct dnsrecordheader*>((*iter).d_packet.c_str()+sizeof(struct dnsheader));
	uint16_t type = header->d_type;
	std::string domain=questionExpand((*iter).d_packet.c_str(), (*iter).d_packet.size(), type); 	
	if (pdns_iequals(name,domain)) 
	{ 
  	  iter = d_packetCache.erase(iter);
	  count++;
	} else iter++;
    }
  }
  return count;
}

bool RecursorPacketCache::getResponsePacket(const std::string& queryPacket, time_t now, 
  std::string* responsePacket, uint32_t* age)
{
  struct Entry e;
  e.d_packet=queryPacket;
  
  packetCache_t::const_iterator iter = d_packetCache.find(e);
  
  if(iter == d_packetCache.end()) {
    d_misses++;
    return false;
  }
    
  if((uint32_t)now < iter->d_ttd) { // it is fresh!
//    cerr<<"Fresh for another "<<iter->d_ttd - now<<" seconds!"<<endl;
    *age = now - iter->d_creation;
    uint16_t id;
    memcpy(&id, queryPacket.c_str(), 2); 
    *responsePacket = iter->d_packet;
    responsePacket->replace(0, 2, (char*)&id, 2);
    d_hits++;
    moveCacheItemToBack(d_packetCache, iter);

    return true;
  }
  moveCacheItemToFront(d_packetCache, iter);
  d_misses++;
  return false;
}

void RecursorPacketCache::insertResponsePacket(const std::string& responsePacket, time_t now, uint32_t ttl)
{
  struct Entry e;
  e.d_packet = responsePacket;
  e.d_ttd = now+ttl;
  e.d_creation = now;
  packetCache_t::iterator iter = d_packetCache.find(e);
  
  if(iter != d_packetCache.end()) {
    iter->d_packet = responsePacket;
    iter->d_ttd = now + ttl;
    iter->d_creation = now;
  }
  else 
    d_packetCache.insert(e);
}

uint64_t RecursorPacketCache::size()
{
  return d_packetCache.size();
}

uint64_t RecursorPacketCache::bytes()
{
  uint64_t sum=0;
  BOOST_FOREACH(const struct Entry& e, d_packetCache) {
    sum += sizeof(e) + e.d_packet.length() + 4;
  }
  return sum;
}


void RecursorPacketCache::doPruneTo(unsigned int maxCached)
{
  pruneCollection(d_packetCache, maxCached);
}

