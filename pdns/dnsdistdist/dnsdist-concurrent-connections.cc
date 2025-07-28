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

#include "dnsdist-concurrent-connections.hh"

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/key_extractors.hpp>

#include <utility>

#include "circular_buffer.hh"
#include "dnsdist-configuration.hh"
#include "dolog.hh"
#include "lock.hh"

namespace dnsdist
{

static constexpr size_t NB_SHARDS = 16;

struct ClientActivity
{
  uint64_t tcpConnections{0};
  uint64_t tlsNewSessions{0}; /* without resumption */
  uint64_t tlsResumedSessions{0};
  time_t bucketEndTime{0};
};

struct ClientEntry
{
  mutable boost::circular_buffer<ClientActivity> d_activity;
  AddressAndPortRange d_addr;
  mutable uint64_t d_concurrentConnections{0};
  mutable time_t d_bannedUntil{0};
  time_t d_lastSeen{0};
};

struct TimeTag
{
};
struct AddressTag
{
};

using map_t = boost::multi_index_container<
  ClientEntry,
  boost::multi_index::indexed_by<
    boost::multi_index::hashed_unique<boost::multi_index::tag<AddressTag>,
                                      boost::multi_index::member<ClientEntry, AddressAndPortRange, &ClientEntry::d_addr>, AddressAndPortRange::hash>,
    boost::multi_index::ordered_non_unique<boost::multi_index::tag<TimeTag>,
                                           boost::multi_index::member<ClientEntry, time_t, &ClientEntry::d_lastSeen>>>>;

static std::vector<LockGuarded<map_t>> s_tcpClientsConnectionMetrics{NB_SHARDS};
static std::atomic<time_t> s_nextCleanup{0};
static constexpr time_t INACTIVITY_DELAY{60};

static AddressAndPortRange getRange(const ComboAddress& from)
{
  const auto& immutable = dnsdist::configuration::getImmutableConfiguration();
  return AddressAndPortRange(from, from.isIPv4() ? immutable.d_tcpConnectionsMaskV4 : immutable.d_tcpConnectionsMaskV6, from.isIPv4() && immutable.d_tcpConnectionsMaskV4 == 32 ? immutable.d_tcpConnectionsMaskV4Port : 0);
}

static size_t getShardID(const AddressAndPortRange& from)
{
  auto hash = AddressAndPortRange::hash()(from);
  return hash % NB_SHARDS;
}

static bool checkTCPConnectionsRate(const boost::circular_buffer<ClientActivity>& activity, time_t now, uint64_t maxTCPRate, uint64_t maxTLSNewRate, uint64_t maxTLSResumedRate, uint64_t interval, bool isTLS)
{
  if (maxTCPRate == 0 && (!isTLS || (maxTLSNewRate == 0 && maxTLSResumedRate == 0))) {
    return true;
  }
  uint64_t bucketsConsidered = 0;
  uint64_t connectionsSeen = 0;
  uint64_t tlsNewSeen = 0;
  uint64_t tlsResumedSeen = 0;
  time_t cutOff = now - (interval * 60); // interval is in seconds
  for (const auto& entry : activity) {
    if (entry.bucketEndTime < cutOff) {
      continue;
    }
    ++bucketsConsidered;
    connectionsSeen += entry.tcpConnections;
    tlsNewSeen += entry.tlsNewSessions;
    tlsResumedSeen += entry.tlsResumedSessions;
  }
  if (bucketsConsidered == 0) {
    return true;
  }
  if (maxTCPRate > 0) {
    auto rate = connectionsSeen / bucketsConsidered;
    if (rate > maxTCPRate) {
      return false;
    }
  }
  if (maxTLSNewRate > 0 && isTLS) {
    auto rate = tlsNewSeen / bucketsConsidered;
    if (rate > maxTLSNewRate) {
      return false;
    }
  }
  if (maxTLSResumedRate > 0 && isTLS) {
    auto rate = tlsResumedSeen / bucketsConsidered;
    if (rate > maxTLSResumedRate) {
      return false;
    }
  }
  return true;
}

void IncomingConcurrentTCPConnectionsManager::cleanup(time_t now)
{
  if (s_nextCleanup.load() > now) {
    return;
  }
  s_nextCleanup.store(now + 60);

  const auto& immutable = dnsdist::configuration::getImmutableConfiguration();
  const auto interval = immutable.d_tcpConnectionsRatePerClientInterval;
  time_t cutOff = now - (interval * 60); // interval in minutes
  for (auto& shard : s_tcpClientsConnectionMetrics) {
    auto db = shard.lock();
    auto& index = db->get<TimeTag>();
    for (auto entry = index.begin(); entry != index.end();) {
      if (entry->d_lastSeen >= cutOff) {
        /* this index is ordered on timestamps,
           so the first valid entry we see means we are done */
        break;
      }

      entry = index.erase(entry);
    }
  }
}

static ClientActivity& getCurrentClientActivity(const ClientEntry& entry, time_t now)
{
  auto& activity = entry.d_activity;
  if (activity.empty() || activity.front().bucketEndTime < now) {
    activity.push_front(ClientActivity{1, 0, 0, now + INACTIVITY_DELAY});
  }
  return activity.front();
}

IncomingConcurrentTCPConnectionsManager::NewConnectionResult IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(const ComboAddress& from, bool isTLS)
{
  const auto& immutable = dnsdist::configuration::getImmutableConfiguration();
  const auto maxConnsPerClient = immutable.d_maxTCPConnectionsPerClient;
  const auto threshold = immutable.d_tcpConnectionsOverloadThreshold;
  const auto tcpRate = immutable.d_maxTCPConnectionsRatePerClient;
  const auto tlsNewRate = immutable.d_maxTLSNewSessionsRatePerClient;
  const auto tlsResumedRate = immutable.d_maxTLSResumedSessionsRatePerClient;
  const auto interval = immutable.d_tcpConnectionsRatePerClientInterval;
  if (maxConnsPerClient == 0 && tcpRate == 0 && tlsResumedRate == 0 && tlsNewRate == 0 && immutable.d_maxTCPReadIOsPerQuery == 0) {
    return NewConnectionResult::Allowed;
  }

  auto now = time(nullptr);
  auto updateActivity = [now](ClientEntry& entry) {
    ++entry.d_concurrentConnections;
    entry.d_lastSeen = now;
    auto& activity = getCurrentClientActivity(entry, now);
    ++activity.tcpConnections;
  };

  auto checkConnectionAllowed = [now, from, maxConnsPerClient, threshold, tcpRate, tlsNewRate, tlsResumedRate, interval, isTLS, &immutable](const ClientEntry& entry) {
    if (entry.d_bannedUntil != 0 && entry.d_bannedUntil >= now) {
      vinfolog("Refusing TCP connection from %s: banned", from.toStringWithPort());
      return NewConnectionResult::Denied;
    }
    if (maxConnsPerClient > 0 && entry.d_concurrentConnections >= maxConnsPerClient) {
      vinfolog("Refusing TCP connection from %s: too many connections", from.toStringWithPort());
      return NewConnectionResult::Denied;
    }
    if (!checkTCPConnectionsRate(entry.d_activity, now, tcpRate, tlsNewRate, tlsResumedRate, interval, isTLS)) {
      entry.d_bannedUntil = now + immutable.d_tcpBanDurationForExceedingTCPTLSRate;
      vinfolog("Banning TCP connections from %s for %d seconds: too many new TCP/TLS connections per second", from.toStringWithPort(), immutable.d_tcpBanDurationForExceedingTCPTLSRate);
      return NewConnectionResult::Denied;
    }

    if (maxConnsPerClient == 0 || threshold == 0) {
      return NewConnectionResult::Allowed;
    }

    auto current = (100 * entry.d_concurrentConnections) / maxConnsPerClient;
    if (current < threshold) {
      return NewConnectionResult::Allowed;
    }
    vinfolog("Restricting TCP connection from %s: nearly reaching the maximum number of concurrent TCP connections", from.toStringWithPort());
    return NewConnectionResult::Restricted;
  };

  auto addr = getRange(from);
  {
    auto shardID = getShardID(addr);
    auto db = s_tcpClientsConnectionMetrics.at(shardID).lock();
    const auto& entry = db->find(addr);
    if (entry == db->end()) {
      ClientEntry newEntry;
      newEntry.d_activity.set_capacity(interval);
      newEntry.d_addr = addr;
      newEntry.d_concurrentConnections = 1;
      newEntry.d_lastSeen = now;
      db->insert(std::move(newEntry));
      return NewConnectionResult::Allowed;
    }
    auto result = checkConnectionAllowed(*entry);
    if (result != NewConnectionResult::Denied) {
      db->modify(entry, updateActivity);
    }
    return result;
  }
}

bool IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(const ComboAddress& from)
{
  const auto& immutable = dnsdist::configuration::getImmutableConfiguration();
  const auto maxConnsPerClient = immutable.d_maxTCPConnectionsPerClient;
  if (maxConnsPerClient == 0 || immutable.d_tcpConnectionsOverloadThreshold == 0) {
    return false;
  }

  size_t count = 0;
  auto addr = getRange(from);
  auto shardID = getShardID(addr);
  {
    auto db = s_tcpClientsConnectionMetrics.at(shardID).lock();
    auto it = db->find(addr);
    if (it == db->end()) {
      return false;
    }
    count = it->d_concurrentConnections;
  }

  auto current = (100 * count) / maxConnsPerClient;
  return current >= immutable.d_tcpConnectionsOverloadThreshold;
}

void IncomingConcurrentTCPConnectionsManager::banClientFor(const ComboAddress& from, time_t now, uint32_t seconds)
{
  auto addr = getRange(from);
  auto shardID = getShardID(addr);
  {
    auto db = s_tcpClientsConnectionMetrics.at(shardID).lock();
    auto it = db->find(addr);
    if (it == db->end()) {
      return;
    }
    db->modify(it, [now, seconds](ClientEntry& entry) {
      entry.d_lastSeen = now;
      entry.d_bannedUntil = now + seconds;
    });
  }
  vinfolog("Banned TCP client %s for %d seconds", from.toStringWithPort(), seconds);
}

static void editEntryIfPresent(const ComboAddress& from, const std::function<void(const ClientEntry& entry)>& callback)
{
  auto addr = getRange(from);
  auto shardID = getShardID(addr);
  {
    auto db = s_tcpClientsConnectionMetrics.at(shardID).lock();
    auto it = db->find(addr);
    if (it == db->end()) {
      return;
    }
    callback(*it);
  }
}

void IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(const ComboAddress& from)
{
  const auto maxConnsPerClient = dnsdist::configuration::getImmutableConfiguration().d_maxTCPConnectionsPerClient;
  if (maxConnsPerClient == 0) {
    return;
  }
  editEntryIfPresent(from, [](const ClientEntry& entry) {
    auto& count = entry.d_concurrentConnections;
    count--;
  });
}

void IncomingConcurrentTCPConnectionsManager::accountTLSNewSession(const ComboAddress& from)
{
  const auto maxRate = dnsdist::configuration::getImmutableConfiguration().d_maxTLSNewSessionsRatePerClient;
  if (maxRate == 0) {
    return;
  }
  editEntryIfPresent(from, [](const ClientEntry& entry) {
    auto& count = getCurrentClientActivity(entry, time(nullptr)).tlsNewSessions;
    count++;
  });
}

void IncomingConcurrentTCPConnectionsManager::accountTLSResumedSession(const ComboAddress& from)
{
  const auto maxRate = dnsdist::configuration::getImmutableConfiguration().d_maxTLSResumedSessionsRatePerClient;
  if (maxRate == 0) {
    return;
  }
  editEntryIfPresent(from, [](const ClientEntry& entry) {
    auto& count = getCurrentClientActivity(entry, time(nullptr)).tlsResumedSessions;
    count++;
  });
}

}
