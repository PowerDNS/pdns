#include <iostream>
#include "recpacketcache.hh"
#include "dns.hh"
#include "namespaces.hh"
#include "lock.hh"


RecursorPacketCache::RecursorPacketCache()
{
  pthread_rwlock_init(&d_rwlock, 0);
}

bool RecursorPacketCache::getResponsePacket(const std::string& queryPacket, time_t now, std::string* responsePacket)
{
  TryReadLock l(&d_rwlock);
  if(!l.gotIt())
    return false; 

  struct Entry e;
  e.d_packet=queryPacket;
  
  packetCache_t::const_iterator iter = d_packetCache.find(e);
  if(iter != d_packetCache.end() && (uint32_t)now < iter->d_ttd) {
    uint16_t id = ((struct dnsheader*)queryPacket.c_str())->id;
    *responsePacket = iter->d_packet;
    ((struct dnsheader*)responsePacket->c_str())->id=id;
    return true;
  }
  return false;
}

void RecursorPacketCache::insertResponsePacket(const std::string& responsePacket, time_t now, uint32_t ttl)
{
  TryWriteLock l(&d_rwlock);
  if(!l.gotIt())
    return;
    
  struct Entry e;
  e.d_packet = responsePacket;
  e.d_ttd = now+ttl;
  packetCache_t::iterator iter = d_packetCache.find(e);
  if(iter != d_packetCache.end()) {
    iter->d_packet = responsePacket;
    iter->d_ttd = now +ttl;
  }
  else 
    d_packetCache.insert(e);
}


// needs to take into account: qname, qtype, opcode, rd, qdcount, EDNS size
bool RecursorPacketCache::Entry::operator<(const struct RecursorPacketCache::Entry &rhs) const
{
  const struct dnsheader* 
    dh=(const struct dnsheader*) d_packet.c_str(), 
    *rhsdh=(const struct dnsheader*)rhs.d_packet.c_str();
  if(make_tuple(dh->opcode, dh->rd, dh->qdcount) < 
     make_tuple(rhsdh->opcode, rhsdh->rd, rhsdh->qdcount))
    return true;

  uint16_t qtype, rhsqtype;
  string qname=questionExpand(d_packet.c_str(), d_packet.length(), qtype);
  string rhsqname=questionExpand(rhs.d_packet.c_str(), rhs.d_packet.length(), rhsqtype);

  return tie(qtype, qname) < tie(rhsqtype, rhsqname);
}
