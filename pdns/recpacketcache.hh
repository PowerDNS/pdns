#ifndef PDNS_RECPACKETCACHE_HH
#define PDNS_RECPACKETCACHE_HH
#include <string>
#include <set>
#include <inttypes.h>
#include "dns.hh"
#include "namespaces.hh"
#include <iostream>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index/sequenced_index.hpp>


using namespace ::boost::multi_index;

//! Stores whole packets, ready for lobbing back at the client. Not threadsafe.
class RecursorPacketCache
{
public:
  RecursorPacketCache();
  bool getResponsePacket(const std::string& queryPacket, time_t now, std::string* responsePacket);
  void insertResponsePacket(const std::string& responsePacket, time_t now, uint32_t ttd);
  void doPruneTo(unsigned int maxSize=250000);
  
  void prune();
  uint64_t d_hits, d_misses;
  uint64_t size();

private:

  struct Entry 
  {
    mutable uint32_t d_ttd;
    mutable std::string d_packet; // "I know what I am doing"

    inline bool operator<(const struct Entry& rhs) const;
  };
 
 
  
  typedef multi_index_container<
    Entry,
    indexed_by  <
                  ordered_unique<identity<Entry> >, 
                  sequenced<> 
               >
  > packetCache_t;
  
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
