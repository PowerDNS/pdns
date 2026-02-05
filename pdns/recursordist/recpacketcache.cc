#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <iostream>
#include <cinttypes>

#include "recpacketcache.hh"
#include "cachecleaner.hh"
#include "dns.hh"
#include "namespaces.hh"
#include "rec-taskqueue.hh"

unsigned int RecursorPacketCache::s_refresh_ttlperc{0};

void RecursorPacketCache::setShardSizes(size_t shardSize)
{
  for (auto& shard : d_maps) {
    auto lock = shard.lock();
    lock->d_shardSize = shardSize;
  }
}

uint64_t RecursorPacketCache::size() const
{
  uint64_t count = 0;
  for (const auto& map : d_maps) {
    count += map.getEntriesCount();
  }
  return count;
}

uint64_t RecursorPacketCache::bytes()
{
  uint64_t sum = 0;
  for (auto& shard : d_maps) {
    auto lock = shard.lock();
    for (const auto& entry : lock->d_map) {
      sum += sizeof(entry) + entry.d_packet.length() + 4;
    }
  }
  return sum;
}

uint64_t RecursorPacketCache::getHits()
{
  uint64_t sum = 0;
  for (auto& shard : d_maps) {
    auto lock = shard.lock();
    sum += lock->d_hits;
  }
  return sum;
}

uint64_t RecursorPacketCache::getMisses()
{
  uint64_t sum = 0;
  for (auto& shard : d_maps) {
    auto lock = shard.lock();
    sum += lock->d_misses;
  }
  return sum;
}

pair<uint64_t, uint64_t> RecursorPacketCache::stats()
{
  uint64_t contended = 0;
  uint64_t acquired = 0;
  for (auto& shard : d_maps) {
    auto content = shard.lock();
    contended += content->d_contended_count;
    acquired += content->d_acquired_count;
  }
  return {contended, acquired};
}

uint64_t RecursorPacketCache::doWipePacketCache(const DNSName& name, uint16_t qtype, bool subtree)
{
  uint64_t count = 0;
  for (auto& map : d_maps) {
    auto shard = map.lock();
    auto& idx = shard->d_map.get<NameTag>();
    for (auto iter = idx.lower_bound(name); iter != idx.end();) {
      if (subtree) {
        if (!iter->d_name.isPartOf(name)) { // this is case insensitive
          break;
        }
      }
      else {
        if (iter->d_name != name) {
          break;
        }
      }
      if (qtype == 0xffff || iter->d_type == qtype) {
        iter = idx.erase(iter);
        map.decEntriesCount();
        count++;
      }
      else {
        ++iter;
      }
    }
  }
  return count;
}

static const std::unordered_set<uint16_t> s_skipOptions = {EDNSOptionCode::ECS, EDNSOptionCode::COOKIE, EDNSOptionCode::TRACEPARENT};

bool RecursorPacketCache::qrMatch(const packetCache_t::index<HashTag>::type::iterator& iter, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass)
{
  // this ignores checking on the EDNS subnet flags!
  if (qname != iter->d_name || iter->d_type != qtype || iter->d_class != qclass) {
    return false;
  }

  return queryMatches(iter->d_query, queryPacket, qname, s_skipOptions);
}

bool RecursorPacketCache::checkResponseMatches(MapCombo::LockedContent& shard, std::pair<packetCache_t::index<HashTag>::type::iterator, packetCache_t::index<HashTag>::type::iterator> range, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, time_t now, std::string* responsePacket, uint32_t* age, vState* valState, OptPBData* pbdata)
{
  for (auto iter = range.first; iter != range.second; ++iter) {
    // the possibility is VERY real that we get hits that are not right - birthday paradox
    if (!qrMatch(iter, queryPacket, qname, qtype, qclass)) {
      continue;
    }

    if (now < iter->d_ttd) { // it is right, it is fresh!
      // coverity[store_truncates_time_t]
      *age = static_cast<uint32_t>(now - iter->d_creation);
      // we know ttl is > 0
      auto ttl = static_cast<uint32_t>(iter->d_ttd - now);
      if (s_refresh_ttlperc > 0 && !iter->d_submitted && taskQTypeIsSupported(qtype)) {
        const dnsheader_aligned header(iter->d_packet.data());
        const auto* headerPtr = header.get();
        if (headerPtr->rcode == RCode::NoError) {
          const uint32_t deadline = iter->getOrigTTL() * s_refresh_ttlperc / 100;
          const bool almostExpired = ttl <= deadline;
          if (almostExpired) {
            iter->d_submitted = true;
            pushAlmostExpiredTask(qname, qtype, iter->d_ttd, Netmask());
          }
        }
      }
      *responsePacket = iter->d_packet;
      responsePacket->replace(0, 2, queryPacket.c_str(), 2);
      *valState = iter->d_vstate;

      const size_t wirelength = qname.wirelength();
      if (responsePacket->size() > (sizeof(dnsheader) + wirelength)) {
        responsePacket->replace(sizeof(dnsheader), wirelength, queryPacket, sizeof(dnsheader), wirelength);
      }

      shard.d_hits++;
      moveCacheItemToBack<SequencedTag>(shard.d_map, iter);

      if (pbdata != nullptr) {
        if (iter->d_pbdata) {
          *pbdata = iter->d_pbdata;
        }
        else {
          *pbdata = std::nullopt;
        }
      }

      return true;
    }
    // We used to move the item to the front of "the to be deleted" sequence,
    // but we very likely will update the entry very soon, so leave it
    shard.d_misses++;
    break;
  }

  return false;
}

bool RecursorPacketCache::getResponsePacket(unsigned int tag, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, time_t now,
                                            std::string* responsePacket, uint32_t* age, vState* valState, uint32_t* qhash, OptPBData* pbdata, bool tcp)
{
  *qhash = canHashPacket(queryPacket, s_skipOptions);
  auto& map = getMap(tag, *qhash, tcp);
  auto shard = map.lock();
  const auto& idx = shard->d_map.get<HashTag>();
  auto range = idx.equal_range(std::tie(tag, *qhash, tcp));

  if (range.first == range.second) {
    shard->d_misses++;
    return false;
  }

  return checkResponseMatches(*shard, range, queryPacket, qname, qtype, qclass, now, responsePacket, age, valState, pbdata);
}

bool RecursorPacketCache::getResponsePacket(unsigned int tag, const std::string& queryPacket, DNSName& qname, uint16_t* qtype, uint16_t* qclass, time_t now,
                                            std::string* responsePacket, uint32_t* age, vState* valState, uint32_t* qhash, OptPBData* pbdata, bool tcp)
{
  *qhash = canHashPacket(queryPacket, s_skipOptions);
  auto& map = getMap(tag, *qhash, tcp);
  auto shard = map.lock();
  const auto& idx = shard->d_map.get<HashTag>();
  auto range = idx.equal_range(std::tie(tag, *qhash, tcp));

  if (range.first == range.second) {
    shard->d_misses++;
    return false;
  }

  qname = DNSName(queryPacket.c_str(), static_cast<int>(queryPacket.length()), sizeof(dnsheader), false, qtype, qclass);

  return checkResponseMatches(*shard, range, queryPacket, qname, *qtype, *qclass, now, responsePacket, age, valState, pbdata);
}

void RecursorPacketCache::insertResponsePacket(unsigned int tag, uint32_t qhash, std::string&& query, const DNSName& qname, uint16_t qtype, uint16_t qclass, std::string&& responsePacket, time_t now, uint32_t ttl, const vState& valState, OptPBData&& pbdata, bool tcp)
{
  auto& map = getMap(tag, qhash, tcp);
  auto shard = map.lock();
  auto& idx = shard->d_map.get<HashTag>();
  auto range = idx.equal_range(std::tie(tag, qhash, tcp));
  auto iter = range.first;

  for (; iter != range.second; ++iter) {
    if (iter->d_type != qtype || iter->d_class != qclass || iter->d_name != qname) {
      continue;
    }

    moveCacheItemToBack<SequencedTag>(shard->d_map, iter);
    iter->d_packet = std::move(responsePacket);
    iter->d_query = std::move(query);
    iter->d_ttd = now + ttl;
    iter->d_creation = now;
    iter->d_vstate = valState;
    iter->d_submitted = false;
    if (pbdata) {
      iter->d_pbdata = std::move(*pbdata);
    }

    return;
  }

  struct Entry entry(DNSName(qname), qtype, qclass, std::move(responsePacket), std::move(query), tcp, qhash, now + ttl, now, tag, valState);
  if (pbdata) {
    entry.d_pbdata = std::move(*pbdata);
  }

  shard->d_map.insert(entry);
  map.incEntriesCount();

  if (shard->d_map.size() > shard->d_shardSize) {
    auto& seq_idx = shard->d_map.get<SequencedTag>();
    seq_idx.erase(seq_idx.begin());
    map.decEntriesCount();
  }
  assert(map.getEntriesCount() == shard->d_map.size()); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay): clib implementation
}

void RecursorPacketCache::doPruneTo(time_t now, size_t maxSize)
{
  size_t cacheSize = size();
  pruneMutexCollectionsVector<SequencedTag>(now, d_maps, maxSize, cacheSize);
}

uint64_t RecursorPacketCache::doDump(int file)
{
  int fdupped = dup(file);
  if (fdupped == -1) {
    return 0;
  }
  auto filePtr = pdns::UniqueFilePtr(fdopen(fdupped, "w"));
  if (!filePtr) {
    close(fdupped);
    return 0;
  }

  uint64_t count = 0;
  time_t now = time(nullptr);

  size_t shardNum = 0;
  size_t min = std::numeric_limits<size_t>::max();
  size_t max = 0;
  uint64_t maxSize = 0;

  for (auto& shard : d_maps) {
    auto lock = shard.lock();
    const auto& sidx = lock->d_map.get<SequencedTag>();
    const auto shardSize = lock->d_map.size();
    fprintf(filePtr.get(), "; packetcache shard %zu; size %zu/%zu\n", shardNum, shardSize, lock->d_shardSize);
    min = std::min(min, shardSize);
    max = std::max(max, shardSize);
    maxSize += lock->d_shardSize;
    shardNum++;
    for (const auto& entry : sidx) {
      count++;
      try {
        fprintf(filePtr.get(), "%s %" PRId64 " %s  ; tag %d %s\n", entry.d_name.toString().c_str(), static_cast<int64_t>(entry.d_ttd - now), DNSRecordContent::NumberToType(entry.d_type).c_str(), entry.d_tag, entry.d_tcp ? "tcp" : "udp");
      }
      catch (...) {
        fprintf(filePtr.get(), "; error printing '%s'\n", entry.d_name.empty() ? "EMPTY" : entry.d_name.toString().c_str());
      }
    }
  }
  fprintf(filePtr.get(), "; packetcache size: %" PRIu64 "/%" PRIu64 " shards: %zu min/max shard size: %zu/%zu\n", size(), maxSize, d_maps.size(), min, max);
  return count;
}
