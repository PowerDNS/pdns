#ifndef PDNS_RECPACKETCACHE_HH
#define PDNS_RECPACKETCACHE_HH
#include <string>
#include <set>
#include <inttypes.h>
#include "dns.hh"
#include "namespaces.hh"
#include <iostream>

class RecursorPacketCache
{
public:
  RecursorPacketCache();
  bool getResponsePacket(const std::string& queryPacket, time_t now, std::string* responsePacket);
  void insertResponsePacket(const std::string& responsePacket, time_t now, uint32_t ttd);
  
  void prune();
private:

  struct Entry 
  {
    mutable uint32_t d_ttd;
    mutable std::string d_packet; // "I know what I am doing"

    inline bool operator<(const struct Entry& rhs) const;
  };
  typedef std::set<struct Entry> packetCache_t;
  packetCache_t d_packetCache;
};

// needs to take into account: qname, qtype, opcode, rd, qdcount, EDNS size
inline bool RecursorPacketCache::Entry::operator<(const struct RecursorPacketCache::Entry &rhs) const
{
  const struct dnsheader* 
    dh=(const struct dnsheader*) d_packet.c_str(), 
    *rhsdh=(const struct dnsheader*)rhs.d_packet.c_str();
  if(make_tuple(dh->opcode, dh->rd, dh->qdcount) < 
     make_tuple(rhsdh->opcode, rhsdh->rd, rhsdh->qdcount))
    return true;

  return dnspacketLessThan(d_packet, rhs.d_packet);
}



#endif
