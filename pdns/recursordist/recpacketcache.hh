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
#pragma once
#include <string>
#include <cinttypes>
#include "dns.hh"
#include "namespaces.hh"
#include <iostream>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/optional.hpp>

#include "packetcache.hh"
#include "validate.hh"
#include "lock.hh"
#include "stat_t.hh"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

using namespace ::boost::multi_index;

class RecursorPacketCache : public PacketCache
{
public:
  static unsigned int s_refresh_ttlperc;

  struct PBData
  {
    std::string d_message;
    std::string d_response;
    bool d_tagged;
  };
  using OptPBData = std::optional<PBData>;

  RecursorPacketCache(size_t maxsize, size_t shards = 1024) :
    d_maps(shards)
  {
    setMaxSize(maxsize);
  }

  bool getResponsePacket(unsigned int tag, const std::string& queryPacket, time_t now,
                         std::string* responsePacket, uint32_t* age, uint32_t* qhash)
  {
    DNSName qname;
    uint16_t qtype{0};
    uint16_t qclass{0};
    vState valState{vState::Indeterminate};
    return getResponsePacket(tag, queryPacket, qname, &qtype, &qclass, now, responsePacket, age, &valState, qhash, nullptr, false);
  }

  bool getResponsePacket(unsigned int tag, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, time_t now,
                         std::string* responsePacket, uint32_t* age, uint32_t* qhash)
  {
    vState valState{vState::Indeterminate};
    return getResponsePacket(tag, queryPacket, qname, qtype, qclass, now, responsePacket, age, &valState, qhash, nullptr, false);
  }

  bool getResponsePacket(unsigned int tag, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, time_t now, std::string* responsePacket, uint32_t* age, vState* valState, uint32_t* qhash, OptPBData* pbdata, bool tcp);
  bool getResponsePacket(unsigned int tag, const std::string& queryPacket, DNSName& qname, uint16_t* qtype, uint16_t* qclass, time_t now, std::string* responsePacket, uint32_t* age, vState* valState, uint32_t* qhash, OptPBData* pbdata, bool tcp);

  void insertResponsePacket(unsigned int tag, uint32_t qhash, std::string&& query, const DNSName& qname, uint16_t qtype, uint16_t qclass, std::string&& responsePacket, time_t now, uint32_t ttl, const vState& valState, OptPBData&& pbdata, bool tcp);
  void doPruneTo(time_t now, size_t maxSize);
  uint64_t doDump(int file);
  uint64_t doWipePacketCache(const DNSName& name, uint16_t qtype = 0xffff, bool subtree = false);

  void setMaxSize(size_t size)
  {
    if (size < d_maps.size()) {
      size = d_maps.size();
    }
    setShardSizes(size / d_maps.size());
  }

  [[nodiscard]] uint64_t size() const;
  [[nodiscard]] uint64_t bytes();
  [[nodiscard]] uint64_t getHits();
  [[nodiscard]] uint64_t getMisses();
  [[nodiscard]] pair<uint64_t, uint64_t> stats();

private:
  struct Entry
  {
    Entry(DNSName&& qname, uint16_t qtype, uint16_t qclass, std::string&& packet, std::string&& query, bool tcp,
          // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
          uint32_t qhash, time_t ttd, time_t now, uint32_t tag, vState vstate) :
      d_name(std::move(qname)),
      d_packet(std::move(packet)),
      d_query(std::move(query)),
      d_ttd(ttd),
      d_creation(now),
      d_qhash(qhash),
      d_tag(tag),
      d_type(qtype),
      d_class(qclass),
      d_vstate(vstate),
      d_tcp(tcp)
    {
    }

    DNSName d_name;
    mutable std::string d_packet;
    mutable std::string d_query;
    mutable OptPBData d_pbdata;
    mutable time_t d_ttd;
    mutable time_t d_creation; // so we can 'age' our packets
    uint32_t d_qhash;
    uint32_t d_tag;
    uint16_t d_type;
    uint16_t d_class;
    mutable vState d_vstate;
    mutable bool d_submitted{false}; // whether this entry has been queued for refetch
    bool d_tcp; // whether this entry was created from a TCP query
    inline bool operator<(const struct Entry& rhs) const;

    bool isStale(time_t now) const
    {
      return d_ttd < now;
    }

    uint32_t getOrigTTL() const
    {
      return d_ttd - d_creation;
    }
  };

  struct HashTag
  {
  };
  struct NameTag
  {
  };
  struct SequencedTag
  {
  };
  using packetCache_t = multi_index_container<Entry,
                                              indexed_by<hashed_non_unique<tag<HashTag>,
                                                                           composite_key<Entry,
                                                                                         member<Entry, uint32_t, &Entry::d_tag>,
                                                                                         member<Entry, uint32_t, &Entry::d_qhash>,
                                                                                         member<Entry, bool, &Entry::d_tcp>>>,
                                                         sequenced<tag<SequencedTag>>,
                                                         ordered_non_unique<tag<NameTag>, member<Entry, DNSName, &Entry::d_name>, CanonDNSNameCompare>>>;

  struct MapCombo
  {
    MapCombo() = default;
    ~MapCombo() = default;
    MapCombo(const MapCombo&) = delete;
    MapCombo(MapCombo&&) = delete;
    MapCombo& operator=(const MapCombo&) = delete;
    MapCombo& operator=(MapCombo&&) = delete;

    struct LockedContent
    {
      packetCache_t d_map;
      size_t d_shardSize{0};
      uint64_t d_hits{0};
      uint64_t d_misses{0};
      uint64_t d_contended_count{0};
      uint64_t d_acquired_count{0};
      void invalidate() {}
      void preRemoval(const Entry& /* entry */) {}
    };

    LockGuardedTryHolder<MapCombo::LockedContent> lock()
    {
      auto locked = d_content.try_lock();
      if (!locked.owns_lock()) {
        locked.lock();
        ++locked->d_contended_count;
      }
      ++locked->d_acquired_count;
      return locked;
    }

    [[nodiscard]] auto getEntriesCount() const
    {
      return d_entriesCount.load();
    }

    void incEntriesCount()
    {
      ++d_entriesCount;
    }

    void decEntriesCount()
    {
      --d_entriesCount;
    }

  private:
    LockGuarded<LockedContent> d_content;
    pdns::stat_t d_entriesCount{0};
  };

  vector<MapCombo> d_maps;

  static size_t combine(unsigned int tag, uint32_t hash, bool tcp)
  {
    size_t ret = 0;
    boost::hash_combine(ret, tag);
    boost::hash_combine(ret, hash);
    boost::hash_combine(ret, tcp);
    return ret;
  }

  MapCombo& getMap(unsigned int tag, uint32_t hash, bool tcp)
  {
    return d_maps.at(combine(tag, hash, tcp) % d_maps.size());
  }

  [[nodiscard]] const MapCombo& getMap(unsigned int tag, uint32_t hash, bool tcp) const
  {
    return d_maps.at(combine(tag, hash, tcp) % d_maps.size());
  }

  static bool qrMatch(const packetCache_t::index<HashTag>::type::iterator& iter, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass);
  static bool checkResponseMatches(MapCombo::LockedContent& shard, std::pair<packetCache_t::index<HashTag>::type::iterator, packetCache_t::index<HashTag>::type::iterator> range, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, time_t now, std::string* responsePacket, uint32_t* age, vState* valState, OptPBData* pbdata);

  void setShardSizes(size_t shardSize);
};
