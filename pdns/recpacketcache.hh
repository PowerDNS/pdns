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
/* Note: we store answers as value AND KEY, and with careful work, we make sure that
   you can use a query as a key too. But query and answer must compare as identical! 
   
   This precludes doing anything smart with EDNS directly from the packet */
class RecursorPacketCache
{
public:
  RecursorPacketCache();
  bool getResponsePacket(const std::string& queryPacket, bool wantsDNSSEC, time_t now, std::string* responsePacket, uint32_t* age);
  void insertResponsePacket(const std::string& responsePacket, bool wantsDNSSEC, time_t now, uint32_t ttd);
  void doPruneTo(unsigned int maxSize=250000);
  int doWipePacketCache(const DNSName& name, uint16_t qtype=0xffff, bool subtree=false);
  
  void prune();
  uint64_t d_hits, d_misses;
  uint64_t size();
  uint64_t bytes();

private:

  struct Entry 
  {
    mutable uint32_t d_ttd;
    mutable uint32_t d_creation;
    mutable std::string d_packet; // "I know what I am doing"
    bool d_wantsDNSSEC;
    inline bool operator<(const struct Entry& rhs) const;
    
    uint32_t getTTD() const
    {
      return d_ttd;
    }
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
  if(std::tie(d_wantsDNSSEC, dh->opcode, dh->rd, dh->qdcount) < 
     std::tie(rhs.d_wantsDNSSEC, rhsdh->opcode, rhsdh->rd, rhsdh->qdcount))
    return true;

  if(std::tie(d_wantsDNSSEC, dh->opcode, dh->rd, dh->qdcount) >
     std::tie(rhs.d_wantsDNSSEC, rhsdh->opcode, rhsdh->rd, rhsdh->qdcount))
    return false;

  return dnspacketLessThan(d_packet, rhs.d_packet);
}



#endif
