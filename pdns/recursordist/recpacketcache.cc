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

int RecursorPacketCache::doWipePacketCache(const DNSName& name, uint16_t qtype, bool subtree)
{
  int count = 0;
  auto& idx = d_packetCache.get<NameTag>();
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
      count++;
    }
    else {
      ++iter;
    }
  }
  return count;
}

bool RecursorPacketCache::qrMatch(const packetCache_t::index<HashTag>::type::iterator& iter, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass)
{
  // this ignores checking on the EDNS subnet flags!
  if (qname != iter->d_name || iter->d_type != qtype || iter->d_class != qclass) {
    return false;
  }

  static const std::unordered_set<uint16_t> optionsToSkip{EDNSOptionCode::COOKIE, EDNSOptionCode::ECS};
  return queryMatches(iter->d_query, queryPacket, qname, optionsToSkip);
}

bool RecursorPacketCache::checkResponseMatches(std::pair<packetCache_t::index<HashTag>::type::iterator, packetCache_t::index<HashTag>::type::iterator> range, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, time_t now, std::string* responsePacket, uint32_t* age, vState* valState, OptPBData* pbdata)
{
  for (auto iter = range.first; iter != range.second; ++iter) {
    // the possibility is VERY real that we get hits that are not right - birthday paradox
    if (!qrMatch(iter, queryPacket, qname, qtype, qclass)) {
      continue;
    }

    if (now < iter->d_ttd) { // it is right, it is fresh!
      *age = static_cast<uint32_t>(now - iter->d_creation);
      // we know ttl is > 0
      auto ttl = static_cast<uint32_t>(iter->d_ttd - now);
      if (s_refresh_ttlperc > 0 && !iter->d_submitted) {
        const uint32_t deadline = iter->getOrigTTL() * s_refresh_ttlperc / 100;
        const bool almostExpired = ttl <= deadline;
        if (almostExpired) {
          iter->d_submitted = true;
          pushAlmostExpiredTask(qname, qtype, iter->d_ttd, Netmask());
        }
      }
      *responsePacket = iter->d_packet;
      responsePacket->replace(0, 2, queryPacket.c_str(), 2);
      *valState = iter->d_vstate;

      const size_t wirelength = qname.wirelength();
      if (responsePacket->size() > (sizeof(dnsheader) + wirelength)) {
        responsePacket->replace(sizeof(dnsheader), wirelength, queryPacket, sizeof(dnsheader), wirelength);
      }

      d_hits++;
      moveCacheItemToBack<SequencedTag>(d_packetCache, iter);

      if (pbdata != nullptr) {
        if (iter->d_pbdata) {
          *pbdata = iter->d_pbdata;
        }
        else {
          *pbdata = boost::none;
        }
      }

      return true;
    }
    // We used to move the item to the front of "the to be deleted" sequence,
    // but we very likely will update the entry very soon, so leave it
    d_misses++;
    break;
  }

  return false;
}

static const std::unordered_set<uint16_t> s_skipOptions = {EDNSOptionCode::ECS, EDNSOptionCode::COOKIE};

bool RecursorPacketCache::getResponsePacket(unsigned int tag, const std::string& queryPacket, const DNSName& qname, uint16_t qtype, uint16_t qclass, time_t now,
                                            std::string* responsePacket, uint32_t* age, vState* valState, uint32_t* qhash, OptPBData* pbdata, bool tcp)
{
  *qhash = canHashPacket(queryPacket, s_skipOptions);
  const auto& idx = d_packetCache.get<HashTag>();
  auto range = idx.equal_range(std::tie(tag, *qhash, tcp));

  if (range.first == range.second) {
    d_misses++;
    return false;
  }

  return checkResponseMatches(range, queryPacket, qname, qtype, qclass, now, responsePacket, age, valState, pbdata);
}

bool RecursorPacketCache::getResponsePacket(unsigned int tag, const std::string& queryPacket, DNSName& qname, uint16_t* qtype, uint16_t* qclass, time_t now,
                                            std::string* responsePacket, uint32_t* age, vState* valState, uint32_t* qhash, OptPBData* pbdata, bool tcp)
{
  *qhash = canHashPacket(queryPacket, s_skipOptions);
  const auto& idx = d_packetCache.get<HashTag>();
  auto range = idx.equal_range(std::tie(tag, *qhash, tcp));

  if (range.first == range.second) {
    d_misses++;
    return false;
  }

  qname = DNSName(queryPacket.c_str(), static_cast<int>(queryPacket.length()), sizeof(dnsheader), false, qtype, qclass);

  return checkResponseMatches(range, queryPacket, qname, *qtype, *qclass, now, responsePacket, age, valState, pbdata);
}

void RecursorPacketCache::insertResponsePacket(unsigned int tag, uint32_t qhash, std::string&& query, const DNSName& qname, uint16_t qtype, uint16_t qclass, std::string&& responsePacket, time_t now, uint32_t ttl, const vState& valState, OptPBData&& pbdata, bool tcp)
{
  auto& idx = d_packetCache.get<HashTag>();
  auto range = idx.equal_range(std::tie(tag, qhash, tcp));
  auto iter = range.first;

  for (; iter != range.second; ++iter) {
    if (iter->d_type != qtype || iter->d_class != qclass || iter->d_name != qname) {
      continue;
    }

    moveCacheItemToBack<SequencedTag>(d_packetCache, iter);
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

  struct Entry entry(qname, qtype, qclass, std::move(responsePacket), std::move(query), tcp, qhash, now + ttl, now, tag, valState);
  if (pbdata) {
    entry.d_pbdata = std::move(*pbdata);
  }

  d_packetCache.insert(entry);

  if (d_packetCache.size() > d_maxSize) {
    auto& seq_idx = d_packetCache.get<SequencedTag>();
    seq_idx.erase(seq_idx.begin());
  }
}

uint64_t RecursorPacketCache::bytes() const
{
  uint64_t sum = 0;
  for (const auto& entry : d_packetCache) {
    sum += sizeof(entry) + entry.d_packet.length() + 4;
  }
  return sum;
}

void RecursorPacketCache::doPruneTo(size_t maxSize)
{
  pruneCollection<SequencedTag>(d_packetCache, maxSize);
}

uint64_t RecursorPacketCache::doDump(int file)
{
  int fdupped = dup(file);
  if (fdupped == -1) {
    return 0;
  }
  auto filePtr = std::unique_ptr<FILE, decltype(&fclose)>(fdopen(fdupped, "w"), fclose);
  if (!filePtr) {
    close(fdupped);
    return 0;
  }

  fprintf(filePtr.get(), "; main packet cache dump from thread follows\n;\n");

  const auto& sidx = d_packetCache.get<SequencedTag>();
  uint64_t count = 0;
  time_t now = time(nullptr);

  for (const auto& entry : sidx) {
    count++;
    try {
      fprintf(filePtr.get(), "%s %" PRId64 " %s  ; tag %d %s\n", entry.d_name.toString().c_str(), static_cast<int64_t>(entry.d_ttd - now), DNSRecordContent::NumberToType(entry.d_type).c_str(), entry.d_tag, entry.d_tcp ? "tcp" : "udp");
    }
    catch (...) {
      fprintf(filePtr.get(), "; error printing '%s'\n", entry.d_name.empty() ? "EMPTY" : entry.d_name.toString().c_str());
    }
  }
  return count;
}
