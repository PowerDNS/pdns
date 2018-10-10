/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef PDNS_RECPACKETCACHE_HH
#define PDNS_RECPACKETCACHE_HH
#include <string>
#include <set>
#include <inttypes.h>
#include <iostream>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index/sequenced_index.hpp>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "rec-protobuf.hh"

#include "dns.hh"
#include "namespaces.hh"

using namespace ::boost::multi_index;

//! Stores whole packets, ready for lobbing back at the client. Not threadsafe.
/* Note: we store answers as value AND KEY, and with careful work, we make sure that
   you can use a query as a key too. But query and answer must compare as identical! 
   
   This precludes doing anything smart with EDNS directly from the packet */
class RecursorPacketCache
{
public:
  RecursorPacketCache();
  bool getResponsePacket(unsigned int tag, const std::string& queryPacket, time_t now, std::string* responsePacket, uint32_t* age);
  void insertResponsePacket(unsigned int tag, const DNSName& qname, uint16_t qtype, const std::string& queryPacket, const std::string& responsePacket, time_t now, uint32_t ttd);
  bool getResponsePacket(unsigned int tag, const std::string& queryPacket, time_t now, std::string* responsePacket, uint32_t* age, RecProtoBufMessage* protobufMessage);
  void insertResponsePacket(unsigned int tag, const DNSName& qname, uint16_t qtype, const std::string& queryPacket, const std::string& responsePacket, time_t now, uint32_t ttd, const RecProtoBufMessage* protobufMessage);
  void doPruneTo(unsigned int maxSize=250000);
  uint64_t doDump(int fd);
  int doWipePacketCache(const DNSName& name, uint16_t qtype=0xffff, bool subtree=false);
  
  void prune();
  uint64_t d_hits, d_misses;
  uint64_t size();
  uint64_t bytes();

private:
  struct HashTag {};
  struct NameTag {};
  struct Entry 
  {
    mutable uint32_t d_ttd;
    mutable uint32_t d_creation; // so we can 'age' our packets
    DNSName d_name;
    uint16_t d_type;
    mutable std::string d_packet; // "I know what I am doing"
#ifdef HAVE_PROTOBUF
    mutable RecProtoBufMessage d_protobufMessage;
#endif
    uint32_t d_qhash;
    uint32_t d_tag;
    inline bool operator<(const struct Entry& rhs) const;
    
    uint32_t getTTD() const
    {
      return d_ttd;
    }
  };
  uint32_t canHashPacket(const std::string& origPacket);
  typedef multi_index_container<
    Entry,
    indexed_by  <
      hashed_non_unique<tag<HashTag>, composite_key<Entry, member<Entry,uint32_t,&Entry::d_tag>, member<Entry,uint32_t,&Entry::d_qhash> > >,
      sequenced<> ,
      ordered_non_unique<tag<NameTag>, member<Entry,DNSName,&Entry::d_name>, CanonDNSNameCompare >
      >
  > packetCache_t;
  
  packetCache_t d_packetCache;
};

#endif
