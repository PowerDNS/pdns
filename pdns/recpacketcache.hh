a/*
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
#pragma once
#include <string>
#include <inttypes.h>
#include "dns.hh"
#include "namespaces.hh"
#include <iostream>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/optional.hpp>

#include "packetcache.hh"
#include "validate.hh"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

using namespace ::boost::multi_index;

//! Stores whole packets, ready for lobbing back at the client. Not threadsafe.
/* Note: we store answers as value AND KEY, and with careful work, we make sure that
   you can use a query as a key too. But query and answer must compare as identical! 
   
   This precludes doing anything smart with EDNS directly from the packet */
class RecursorPacketCache: public PacketCache
{
public:
  static unsigned int s_refresh_ttlperc;

  struct PBData {
    std::string d_message;
    std::string d_response;
    bool d_tagged;
  };
  typedef std::optional<PBData> OptPBData;

  RecursorPacketCache();
  bool getResponsePacket(unsigned int tag, const std::string& queryPacket, time_t now, std::string* responsePacket, uint32_t* age, uint32_t* qhash);
  bool getResponsePacket(unsigned int tag, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, time_t now, std::string* responsePacket, uint32_t* age, uint32_t* qhash);
  bool getResponsePacket(unsigned int tag, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, time_t now, std::string* responsePacket, uint32_t* age, vState* valState, uint32_t* qhash, OptPBData* pbdata, bool tcp);
  bool getResponsePacket(unsigned int tag, const std::string& queryPacket, DNSName& qname, uint16_t *qtype, uint16_t* qclass, time_t now, std::string* responsePacket, uint32_t* age, vState* valState, uint32_t* qhash, OptPBData* pbdata, bool tcp);
  
  void insertResponsePacket(unsigned int tag, uint32_t qhash, std::string&& query, const DNSName& qname, uint16_t qtype, uint16_t qclass, std::string&& responsePacket, time_t now, uint32_t ttl, const vState& valState, OptPBData&& pbdata, bool tcp);
  void doPruneTo(size_t maxSize=250000);
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
    Entry(const DNSName& qname, std::string&& packet, std::string&& query, bool tcp): d_name(qname), d_packet(std::move(packet)), d_query(std::move(query)), d_tcp(tcp)
    {
    }

    DNSName d_name;
    mutable std::string d_packet;
    mutable std::string d_query;
    mutable OptPBData d_pbdata;
    mutable time_t d_ttd;
    mutable time_t d_creation;  // so we can 'age' our packets
    uint32_t d_qhash;
    uint32_t d_tag;
    uint16_t d_type;
    uint16_t d_class;
    mutable vState d_vstate;
    mutable bool d_submitted{false}; // whether this entry has been queued for refetch
    bool d_tcp;                      // whether this entry was created from a TCP query
    inline bool operator<(const struct Entry& rhs) const;

    time_t getTTD() const
    {
      return d_ttd;
    }

    uint32_t getOrigTTL() const {
      return d_ttd - d_creation;
    }
  };

  struct SequencedTag{};
  typedef multi_index_container<
    Entry,
    indexed_by <
      hashed_non_unique<tag<HashTag>,
                        composite_key<Entry,
                                      member<Entry, uint32_t, &Entry::d_tag>,
                                      member<Entry, uint32_t, &Entry::d_qhash>,
                                      member<Entry, bool, &Entry::d_tcp>
                                      >
                        >,
      sequenced<tag<SequencedTag>>,
      ordered_non_unique<tag<NameTag>, member<Entry,DNSName, &Entry::d_name>, CanonDNSNameCompare>
      >
    > packetCache_t;

  packetCache_t d_packetCache;

  static bool qrMatch(const packetCache_t::index<HashTag>::type::iterator& iter, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass);
  bool checkResponseMatches(std::pair<packetCache_t::index<HashTag>::type::iterator, packetCache_t::index<HashTag>::type::iterator> range, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, time_t now, std::string* responsePacket, uint32_t* age, vState* valState, OptPBData* pbdata);
};
