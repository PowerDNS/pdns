#include <iostream>
#include "recpacketcache.hh"
#include "dns.hh"
#include "namespaces.hh"
#include "lock.hh"


RecursorPacketCache::RecursorPacketCache()
{
  d_hits = d_misses = 0;
}

bool RecursorPacketCache::getResponsePacket(const std::string& queryPacket, time_t now, std::string* responsePacket)
{
  struct Entry e;
  e.d_packet=queryPacket;
  
  
  packetCache_t::const_iterator iter = d_packetCache.find(e);
  
  if(iter == d_packetCache.end()) {
    d_misses++;
    return false;
  }
  typedef packetCache_t::nth_index<1>::type sequence_t;
  sequence_t& sidx=d_packetCache.get<1>();
  sequence_t::iterator si=d_packetCache.project<1>(iter);
    
  if((uint32_t)now < iter->d_ttd) { // it is fresh!
    uint16_t id = ((struct dnsheader*)queryPacket.c_str())->id;
    *responsePacket = iter->d_packet;
    ((struct dnsheader*)responsePacket->c_str())->id=id;
    d_hits++;

    sidx.relocate(sidx.end(), si); // put it at the end of the delete queue

    return true;
  }
  sidx.relocate(sidx.begin(), si); // at the beginning of the delete queue
  d_misses++;
  return false;
}

void RecursorPacketCache::insertResponsePacket(const std::string& responsePacket, time_t now, uint32_t ttl)
{
  struct Entry e;
  e.d_packet = responsePacket;
  e.d_ttd = now+ttl;
  packetCache_t::iterator iter = d_packetCache.find(e);
  
  if(iter != d_packetCache.end()) {
    iter->d_packet = responsePacket;
    iter->d_ttd = now + ttl;
  }
  else 
    d_packetCache.insert(e);
}

uint64_t RecursorPacketCache::size()
{
  return d_packetCache.size();
}

// this code is almost a copy of the one in recursor_cache.cc
void RecursorPacketCache::doPruneTo(unsigned int maxCached)
{
  uint32_t now=(uint32_t)time(0);
  unsigned int toTrim=0;
  
  unsigned int cacheSize=d_packetCache.size();

  if(maxCached && cacheSize > maxCached) {
    toTrim = cacheSize - maxCached;
  }

//  cout<<"Need to trim "<<toTrim<<" from cache to meet target!\n";

  typedef packetCache_t::nth_index<1>::type sequence_t;
  sequence_t& sidx=d_packetCache.get<1>();

  unsigned int tried=0, lookAt, erased=0;

  // two modes - if toTrim is 0, just look through 10000 records and nuke everything that is expired
  // otherwise, scan first 5*toTrim records, and stop once we've nuked enough
  if(toTrim)
    lookAt=5*toTrim;
  else
    lookAt=cacheSize/1000;


  sequence_t::iterator iter=sidx.begin(), eiter;
  for(; iter != sidx.end() && tried < lookAt ; ++tried) {
    if(iter->d_ttd < now) { 
      sidx.erase(iter++);
      erased++;
    }
    else
      ++iter;

    if(toTrim && erased > toTrim)
      break;
  }

  //cout<<"erased "<<erased<<" records based on ttd\n";
  
  if(erased >= toTrim) // done
    return;


  toTrim -= erased;

  //if(toTrim)
    // cout<<"Still have "<<toTrim - erased<<" entries left to erase to meet target\n"; 

  eiter=iter=sidx.begin();
  std::advance(eiter, toTrim); 
  sidx.erase(iter, eiter);      // just lob it off from the beginning
}

