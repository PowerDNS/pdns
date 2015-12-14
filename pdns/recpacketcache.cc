#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <iostream>

#include "recpacketcache.hh"
#include "cachecleaner.hh"
#include "dns.hh"
#include "namespaces.hh"
#include "lock.hh"
#include "dnswriter.hh"

RecursorPacketCache::RecursorPacketCache()
{
  d_hits = d_misses = 0;
}

int RecursorPacketCache::doWipePacketCache(const DNSName& name, uint16_t qtype, bool subtree)
{
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, name, 0);
  pw.getHeader()->rd=1;
  Entry e;
  e.d_packet.assign((const char*)&*packet.begin(), packet.size());
  e.d_wantsDNSSEC=false;
  // so the idea is, we search for a packet with qtype=0, which is ahead of anything with that name

  int count=0;
  for(auto iter = d_packetCache.lower_bound(e); iter != d_packetCache.end(); ) {
    const struct dnsheader* packet = reinterpret_cast<const struct dnsheader*>((*iter).d_packet.c_str());
    if(packet->qdcount==0)
      break;
    uint16_t t;

    DNSName found(iter->d_packet.c_str(), iter->d_packet.size(), 12, false, &t);
    //    cout<<"At record "<<found<<" while searching for "<<name<<", subtree= "<<subtree<<endl;
    if(subtree) {
      if(!found.isPartOf(name)) {   // this is case insensitive
	break;
      }
    }
    else {
      if(found != name)
	break;
    }

    if(t==qtype || qtype==0xffff) {
      iter=d_packetCache.erase(iter);
      count++;
    }
    else
      ++iter;
  }
  //  cout<<"Wiped "<<count<<" packets from cache"<<endl;
  return count;
}

bool RecursorPacketCache::getResponsePacket(const std::string& queryPacket, bool wantsDNSSEC, time_t now, 
  std::string* responsePacket, uint32_t* age)
{
  struct Entry e;
  e.d_packet=queryPacket;
  e.d_wantsDNSSEC = wantsDNSSEC;
  
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

    return true;
  }
  moveCacheItemToFront(d_packetCache, iter);
  d_misses++;
  return false;
}

void RecursorPacketCache::insertResponsePacket(const std::string& responsePacket, bool wantsDNSSEC, time_t now, uint32_t ttl)
{
  struct Entry e;
  e.d_packet = responsePacket;
  e.d_wantsDNSSEC = wantsDNSSEC;
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
  for(const struct Entry& e :  d_packetCache) {
    sum += sizeof(e) + e.d_packet.length() + 4;
  }
  return sum;
}


void RecursorPacketCache::doPruneTo(unsigned int maxCached)
{
  pruneCollection(d_packetCache, maxCached);
}

