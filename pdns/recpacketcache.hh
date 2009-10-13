#ifndef PDNS_RECPACKETCACHE_HH
#define PDNS_RECPACKETCACHE_HH
#include <string>
#include <set>
#include <inttypes.h>


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

    bool operator<(const struct Entry& rhs) const;
  };
  typedef std::set<struct Entry> packetCache_t;
  packetCache_t d_packetCache;
  pthread_rwlock_t d_rwlock;  
};

#endif
