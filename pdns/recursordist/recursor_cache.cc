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

#include "config.h"

#include <cinttypes>
#include <protozero/pbf_builder.hpp>
#include <protozero/pbf_message.hpp>

#include "recursor_cache.hh"
#include "misc.hh"
#include "dnsrecords.hh"
#include "syncres.hh"
#include "namespaces.hh"
#include "cachecleaner.hh"
#include "rec-taskqueue.hh"
#include "version.hh"
#include "protozero-helpers.hh"

/*
 * SERVE-STALE: the general approach
 *
 * The general switch to enable serve-stale is s_maxServedStaleExtensions. If this value is zero, no
 * serve-stale is done. If it is positive, it determines how many times the serve-stale status of a
 * record can be extended.
 *
 * Each record in the cache has a field d_servedStale. If this value is zero, no special handling is
 * done. If it is positive, the record is being served stale. The value determines how many times
 * the serve-stale status was extended. Each time an extension happens, the value is incremented and
 * a task to see if the record resolves will be pushed. When the served-stale status is extended,
 * the TTD of a record is also changed so the record will be considered not-expired by the get()
 * function. The TTD will be s_serveStaleExtensionPeriod in the future, unless the original TTL was
 * smaller than that. If d_servedStale reaches s_maxServedStaleExtensions the serve-stale status
 * will no longer be extended and the record will be considered really expired.
 *
 * With s_serveStaleExtensionPeriod of 30 seconds, setting s_maxServedStaleExtensions to 1440 will
 * cause a record to be served stale a maximum of 30s * 1440 = 12 hours. If the original TTL is
 * smaller than 30, this period will be shorter. If there was a long time between serve-stale
 * extensions, the value of d_servedStale will be incremented by more than one to account for the
 * longer period.
 *
 * If serve-stale is enabled, the resolving process first will try to resolve a record in the
 * ordinary way, with the difference that a timeout will not lead to an ImmediateServFailException
 * being passed to the caller, but the resolving will be tried again with a flag to allow marking
 * records as served-stale. If the second time around a timeout happens, an
 * ImmediateServFailException *will* be passed to the caller.
 *
 * When serving stale, records are only wiped from the cache if they are older than
 * s_maxServedStaleExtensions * s_serveStaleExtensionPeriod. See isStale(). This is to have a good
 * chance of records being available for marking stale if a name server has an issue.
 *
 * The tasks to see if nameservers are reachable again do a resolve in refresh mode, considering
 * served-stale records as expired. When a record resolves again, the d_servedStale field will be
 * reset.
 */

uint16_t MemRecursorCache::s_maxServedStaleExtensions;
uint16_t MemRecursorCache::s_maxRRSetSize = 256;
bool MemRecursorCache::s_limitQTypeAny = true;

const MemRecursorCache::AuthRecs MemRecursorCache::s_emptyAuthRecs = std::make_shared<MemRecursorCache::AuthRecsVec>();
const MemRecursorCache::SigRecs MemRecursorCache::s_emptySigRecs = std::make_shared<MemRecursorCache::SigRecsVec>();

void MemRecursorCache::resetStaticsForTests()
{
  s_maxServedStaleExtensions = 0;
  SyncRes::s_refresh_ttlperc = 0;
  SyncRes::s_locked_ttlperc = 0;
  SyncRes::s_minimumTTL = 0;
  s_maxRRSetSize = 256;
  s_limitQTypeAny = true;
}

MemRecursorCache::MemRecursorCache(size_t mapsCount) :
  d_maps(mapsCount == 0 ? 1 : mapsCount)
{
}

size_t MemRecursorCache::size() const
{
  size_t count = 0;
  for (const auto& shard : d_maps) {
    count += shard.getEntriesCount();
  }
  return count;
}

pair<uint64_t, uint64_t> MemRecursorCache::stats()
{
  uint64_t contended = 0;
  uint64_t acquired = 0;
  for (auto& shard : d_maps) {
    auto lockedShard = shard.lock();
    contended += lockedShard->d_contended_count;
    acquired += lockedShard->d_acquired_count;
  }
  return {contended, acquired};
}

size_t MemRecursorCache::ecsIndexSize()
{
  // XXX!
  size_t count = 0;
  for (auto& shard : d_maps) {
    auto lockedShard = shard.lock();
    count += lockedShard->d_ecsIndex.size();
  }
  return count;
}

size_t MemRecursorCache::CacheEntry::authRecsSizeEstimate() const
{
  size_t ret = 0;
  if (d_authorityRecs) {
    for (const auto& record : *d_authorityRecs) {
      ret += record.sizeEstimate();
    }
  }
  return ret;
}

size_t MemRecursorCache::CacheEntry::sigRecsSizeEstimate() const
{
  size_t ret = 0;
  if (d_signatures) {
    for (const auto& record : *d_signatures) {
      ret += record->sizeEstimate();
    }
  }
  return ret;
}

size_t MemRecursorCache::CacheEntry::sizeEstimate() const
{
  auto ret = sizeof(struct CacheEntry);
  ret += d_qname.sizeEstimate();
  ret += d_authZone.sizeEstimate();
  for (const auto& record : d_records) {
    ret += record->sizeEstimate();
  }
  ret += authRecsSizeEstimate();
  ret += sigRecsSizeEstimate();
  return ret;
}

// this function is too slow to poll!
size_t MemRecursorCache::bytes()
{
  size_t ret = 0;
  for (auto& shard : d_maps) {
    auto lockedShard = shard.lock();
    for (const auto& entry : lockedShard->d_map) {
      ret += entry.sizeEstimate();
    }
  }
  return ret;
}

static void updateDNSSECValidationStateFromCache(boost::optional<vState>& state, const vState stateUpdate)
{
  // if there was no state it's easy */
  if (state == boost::none) {
    state = stateUpdate;
    return;
  }

  if (stateUpdate == vState::TA) {
    state = vState::Secure;
  }
  else if (stateUpdate == vState::NTA) {
    state = vState::Insecure;
  }
  else if (vStateIsBogus(stateUpdate) || stateUpdate == vState::Indeterminate) {
    state = stateUpdate;
  }
  else if (stateUpdate == vState::Insecure || stateUpdate == vState::Secure) {
    if (!vStateIsBogus(*state) && *state != vState::Indeterminate) {
      state = stateUpdate;
    }
  }
}

template <typename T>
static void ptrAssign(T* ptr, const T& value)
{
  if (ptr != nullptr) {
    *ptr = value;
  }
}

time_t MemRecursorCache::handleHit(time_t now, MapCombo::LockedContent& content, OrderedTagIterator_t& entry, const DNSName& qname, uint32_t& origTTL, vector<DNSRecord>* res, SigRecs* signatures, AuthRecs* authorityRecs, bool* variable, boost::optional<vState>& state, bool* wasAuth, DNSName* fromAuthZone, Extra* extra)
{
  // MUTEX SHOULD BE ACQUIRED (as indicated by the reference to the content which is protected by a lock)
  if (entry->d_tooBig) {
    throw ImmediateServFailException("too many records in RRSet");
  }
  time_t ttd = entry->d_ttd;
  if (ttd <= now) {
    // Expired, don't bother returning contents. Callers *MUST* check return value of get(), and only look at the entry
    // if it returned > 0
    return ttd;
  }
  origTTL = entry->d_orig_ttl;

  if (!entry->d_netmask.empty() || entry->d_rtag) {
    ptrAssign(variable, true);
  }

  if (res != nullptr) {
    if (s_limitQTypeAny && res->size() + entry->d_records.size() > s_maxRRSetSize) {
      throw ImmediateServFailException("too many records in result");
    }

    res->reserve(res->size() + entry->d_records.size());

    for (const auto& record : entry->d_records) {
      DNSRecord result;
      result.d_name = qname;
      result.d_type = entry->d_qtype;
      result.d_class = QClass::IN;
      result.setContent(record);
      // coverity[store_truncates_time_t]
      result.d_ttl = static_cast<uint32_t>(entry->d_ttd);
      result.d_place = DNSResourceRecord::ANSWER;
      res->push_back(std::move(result));
    }
  }

  if (signatures != nullptr) {
    if (*signatures && !(*signatures)->empty() && entry->d_signatures && !entry->d_signatures->empty()) {
      // Return a new vec if we need to append to a non-empty vector
      SigRecsVec vec(**signatures);
      vec.insert(vec.end(), entry->d_signatures->cbegin(), entry->d_signatures->cend());
      *signatures = std::make_shared<SigRecsVec>(std::move(vec));
    }
    else {
      *signatures = entry->d_signatures ? entry->d_signatures : s_emptySigRecs;
    }
  }

  if (authorityRecs != nullptr) {
    // XXX Might need to be adapted like sigs to handle a non-empty incoming authorityRecs
    assert(*authorityRecs == nullptr || (*authorityRecs)->empty());
    *authorityRecs = entry->d_authorityRecs ? entry->d_authorityRecs : s_emptyAuthRecs;
  }

  updateDNSSECValidationStateFromCache(state, entry->d_state);

  if (wasAuth != nullptr) {
    *wasAuth = *wasAuth && entry->d_auth;
  }
  ptrAssign(fromAuthZone, entry->d_authZone);
  if (extra != nullptr) {
    extra->d_address = entry->d_from;
    extra->d_tcp = entry->d_tcp;
  }

  moveCacheItemToBack<SequencedTag>(content.d_map, entry);

  return ttd;
}

static void pushRefreshTask(const DNSName& qname, QType qtype, time_t deadline, const Netmask& netmask)
{
  if (qtype == QType::ADDR) {
    pushAlmostExpiredTask(qname, QType::A, deadline, netmask);
    pushAlmostExpiredTask(qname, QType::AAAA, deadline, netmask);
  }
  else {
    pushAlmostExpiredTask(qname, qtype, deadline, netmask);
  }
}

void MemRecursorCache::updateStaleEntry(time_t now, MemRecursorCache::OrderedTagIterator_t& entry)
{
  // We need to take care an infrequently access stale item cannot be extended past
  // s_maxServedStaleExtension * s_serveStaleExtensionPeriod
  // We look how old the entry is, and increase d_servedStale accordingly, taking care not to overflow
  const time_t howlong = std::max(static_cast<time_t>(1), now - entry->d_ttd);
  const uint32_t extension = std::max(1U, std::min(entry->d_orig_ttl, s_serveStaleExtensionPeriod));
  entry->d_servedStale = std::min(entry->d_servedStale + 1 + howlong / extension, static_cast<time_t>(s_maxServedStaleExtensions));
  entry->d_ttd = now + extension;

  pushRefreshTask(entry->d_qname, entry->d_qtype, entry->d_ttd, entry->d_netmask);
}

// If we are serving this record stale (or *should*) and the ttd has
// passed increase ttd to the future and remember that we did. Also
// push a refresh task.
void MemRecursorCache::handleServeStaleBookkeeping(time_t now, bool serveStale, MemRecursorCache::OrderedTagIterator_t& entry)
{
  if ((serveStale || entry->d_servedStale > 0) && entry->d_ttd <= now && entry->d_servedStale < s_maxServedStaleExtensions) {
    updateStaleEntry(now, entry);
  }
}

MemRecursorCache::cache_t::const_iterator MemRecursorCache::getEntryUsingECSIndex(MapCombo::LockedContent& map, time_t now, const DNSName& qname, const QType qtype, bool requireAuth, const ComboAddress& who, bool serveStale)
{
  // MUTEX SHOULD BE ACQUIRED (as indicated by the reference to the content which is protected by a lock)
  auto ecsIndexKey = std::tie(qname, qtype);
  auto ecsIndex = map.d_ecsIndex.find(ecsIndexKey);
  if (ecsIndex != map.d_ecsIndex.end() && !ecsIndex->isEmpty()) {
    /* we have netmask-specific entries, let's see if we match one */
    while (true) {
      const Netmask best = ecsIndex->lookupBestMatch(who);
      if (best.empty()) {
        /* we have nothing more specific for you */
        break;
      }
      auto key = std::tuple(qname, qtype, boost::none, best);
      auto entry = map.d_map.find(key);
      if (entry == map.d_map.end()) {
        /* ecsIndex is not up-to-date */
        ecsIndex->removeNetmask(best);
        if (ecsIndex->isEmpty()) {
          map.d_ecsIndex.erase(ecsIndex);
          break;
        }
        continue;
      }
      handleServeStaleBookkeeping(now, serveStale, entry);

      if (entry->d_ttd > now) {
        if (!requireAuth || entry->d_auth) {
          return entry;
        }
        /* we need auth data and the best match is not authoritative */
        return map.d_map.end();
      }
      /* this netmask-specific entry has expired */
      moveCacheItemToFront<SequencedTag>(map.d_map, entry);
      // XXX when serving stale, it should be kept, but we don't want a match wth lookupBestMatch()...
      ecsIndex->removeNetmask(best);
      if (ecsIndex->isEmpty()) {
        map.d_ecsIndex.erase(ecsIndex);
        break;
      }
    }
  }

  /* we have nothing specific, let's see if we have a generic one */
  auto key = std::tuple(qname, qtype, boost::none, Netmask());
  auto entry = map.d_map.find(key);
  if (entry != map.d_map.end()) {
    handleServeStaleBookkeeping(now, serveStale, entry);
    if (entry->d_ttd > now) {
      if (!requireAuth || entry->d_auth) {
        return entry;
      }
    }
    else {
      moveCacheItemToFront<SequencedTag>(map.d_map, entry);
    }
  }

  /* nothing for you, sorry */
  return map.d_map.end();
}

MemRecursorCache::Entries MemRecursorCache::getEntries(MapCombo::LockedContent& map, const DNSName& qname, const QType /* qtype */, const OptTag& rtag)
{
  // MUTEX SHOULD BE ACQUIRED
  if (!map.d_cachecachevalid || map.d_cachedqname != qname || map.d_cachedrtag != rtag) {
    map.d_cachedqname = qname;
    map.d_cachedrtag = rtag;
    const auto& idx = map.d_map.get<NameAndRTagOnlyHashedTag>();
    map.d_cachecache = idx.equal_range(std::tie(qname, rtag));
    map.d_cachecachevalid = true;
  }
  return map.d_cachecache;
}

bool MemRecursorCache::entryMatches(MemRecursorCache::OrderedTagIterator_t& entry, const QType qtype, bool requireAuth, const ComboAddress& who)
{
  // This code assumes that if a routing tag is present, it matches
  // MUTEX SHOULD BE ACQUIRED
  if (requireAuth && !entry->d_auth) {
    return false;
  }

  bool match = (entry->d_qtype == qtype || qtype == QType::ANY || (qtype == QType::ADDR && (entry->d_qtype == QType::A || entry->d_qtype == QType::AAAA)))
    && (entry->d_netmask.empty() || entry->d_netmask.match(who));
  return match;
}

// Fake a cache miss if more than refreshTTLPerc of the original TTL has passed
time_t MemRecursorCache::fakeTTD(MemRecursorCache::OrderedTagIterator_t& entry, const DNSName& qname, QType qtype, time_t ret, time_t now, uint32_t origTTL, bool refresh)
{
  time_t ttl = ret - now;
  // If we are checking an entry being served stale in refresh mode,
  // we always consider it stale so a real refresh attempt will be
  // kicked by SyncRes
  if (refresh && entry->d_servedStale > 0) {
    return -1;
  }
  if (ttl > 0 && SyncRes::s_refresh_ttlperc > 0) {
    const uint32_t deadline = origTTL * SyncRes::s_refresh_ttlperc / 100;
    // coverity[store_truncates_time_t]
    const bool almostExpired = static_cast<uint32_t>(ttl) <= deadline;
    if (almostExpired && qname != g_rootdnsname) {
      if (refresh) {
        return -1;
      }
      if (!entry->d_submitted) {
        pushRefreshTask(qname, qtype, entry->d_ttd, entry->d_netmask);
        entry->d_submitted = true;
      }
    }
  }
  return ttl;
}

// returns -1 for no hits
time_t MemRecursorCache::get(time_t now, const DNSName& qname, const QType qtype, Flags flags, vector<DNSRecord>* res, const ComboAddress& who, const OptTag& routingTag, SigRecs* signatures, AuthRecs* authorityRecs, bool* variable, vState* state, bool* wasAuth, DNSName* fromAuthZone, Extra* extra) // NOLINT(readability-function-cognitive-complexity)
{
  bool requireAuth = (flags & RequireAuth) != 0;
  bool refresh = (flags & Refresh) != 0;
  bool serveStale = (flags & ServeStale) != 0;

  boost::optional<vState> cachedState{boost::none};
  uint32_t origTTL = 0;

  if (res != nullptr) {
    res->clear();
  }

  // we might retrieve more than one entry, we need to set that to true
  // so it will be set to false if at least one entry is not auth
  ptrAssign(wasAuth, true);

  auto& shard = getMap(qname);
  auto lockedShard = shard.lock();

  /* If we don't have any netmask-specific entries at all, let's just skip this
     to be able to use the nice d_cachecache hack. */
  if (qtype != QType::ANY && !lockedShard->d_ecsIndex.empty() && !routingTag) {
    if (qtype == QType::ADDR) {
      time_t ret = -1;

      auto entryA = getEntryUsingECSIndex(*lockedShard, now, qname, QType::A, requireAuth, who, serveStale);
      if (entryA != lockedShard->d_map.end()) {
        ret = handleHit(now, *lockedShard, entryA, qname, origTTL, res, signatures, authorityRecs, variable, cachedState, wasAuth, fromAuthZone, extra);
      }
      auto entryAAAA = getEntryUsingECSIndex(*lockedShard, now, qname, QType::AAAA, requireAuth, who, serveStale);
      if (entryAAAA != lockedShard->d_map.end()) {
        time_t ttdAAAA = handleHit(now, *lockedShard, entryAAAA, qname, origTTL, res, signatures, authorityRecs, variable, cachedState, wasAuth, fromAuthZone, extra);
        if (ret > 0) {
          ret = std::min(ret, ttdAAAA);
        }
        else {
          ret = ttdAAAA;
        }
      }

      if (cachedState && ret > 0) {
        ptrAssign(state, *cachedState);
      }

      return ret > 0 ? (ret - now) : ret;
    }
    auto entry = getEntryUsingECSIndex(*lockedShard, now, qname, qtype, requireAuth, who, serveStale);
    if (entry != lockedShard->d_map.end()) {
      time_t ret = handleHit(now, *lockedShard, entry, qname, origTTL, res, signatures, authorityRecs, variable, cachedState, wasAuth, fromAuthZone, extra);
      if (cachedState && ret > now) {
        ptrAssign(state, *cachedState);
      }
      return fakeTTD(entry, qname, qtype, ret, now, origTTL, refresh);
    }
    return -1;
  }

  if (routingTag) {
    auto entries = getEntries(*lockedShard, qname, qtype, routingTag);
    unsigned int found = 0;
    time_t ttd{};

    if (entries.first != entries.second) {
      OrderedTagIterator_t firstIndexIterator;
      for (auto i = entries.first; i != entries.second; ++i) {
        firstIndexIterator = lockedShard->d_map.project<OrderedTag>(i);

        // When serving stale, we consider expired records
        if (!i->isEntryUsable(now, serveStale)) {
          moveCacheItemToFront<SequencedTag>(lockedShard->d_map, firstIndexIterator);
          continue;
        }

        if (!entryMatches(firstIndexIterator, qtype, requireAuth, who)) {
          continue;
        }
        ++found;

        handleServeStaleBookkeeping(now, serveStale, firstIndexIterator);

        ttd = handleHit(now, *lockedShard, firstIndexIterator, qname, origTTL, res, signatures, authorityRecs, variable, cachedState, wasAuth, fromAuthZone, extra);

        if (qtype == QType::ADDR && found == 2) {
          break;
        }
        if (qtype != QType::ANY) { // normally if we have a hit, we are done
          break;
        }
      }
      if (found > 0) {
        if (cachedState && ttd > now) {
          ptrAssign(state, *cachedState);
        }
        return fakeTTD(firstIndexIterator, qname, qtype, ttd, now, origTTL, refresh);
      }
      return -1;
    }
  }
  // Try (again) without tag
  auto entries = getEntries(*lockedShard, qname, qtype, boost::none);

  if (entries.first != entries.second) {
    OrderedTagIterator_t firstIndexIterator;
    unsigned int found = 0;
    time_t ttd{};

    for (auto i = entries.first; i != entries.second; ++i) {
      firstIndexIterator = lockedShard->d_map.project<OrderedTag>(i);

      // When serving stale, we consider expired records
      if (!i->isEntryUsable(now, serveStale)) {
        moveCacheItemToFront<SequencedTag>(lockedShard->d_map, firstIndexIterator);
        continue;
      }

      if (!entryMatches(firstIndexIterator, qtype, requireAuth, who)) {
        continue;
      }
      ++found;

      handleServeStaleBookkeeping(now, serveStale, firstIndexIterator);

      ttd = handleHit(now, *lockedShard, firstIndexIterator, qname, origTTL, res, signatures, authorityRecs, variable, cachedState, wasAuth, fromAuthZone, extra);

      if (qtype == QType::ADDR && found == 2) {
        break;
      }
      if (qtype != QType::ANY) { // normally if we have a hit, we are done
        break;
      }
    }
    if (found > 0) {
      if (cachedState && ttd > now) {
        ptrAssign(state, *cachedState);
      }
      return fakeTTD(firstIndexIterator, qname, qtype, ttd, now, origTTL, refresh);
    }
  }
  return -1;
}

bool MemRecursorCache::CacheEntry::shouldReplace(time_t now, bool auth, vState state, bool refresh)
{
  if (!auth && d_auth) { // unauth data came in, we have some auth data, but is it fresh?
    // an auth entry that is going to expire while we are resolving can hurt, as it prevents infra
    // records (which might be unauth) to be updated. So apply a safety margin.
    const time_t margin = 5;
    if (d_ttd - margin > now) { // we still have valid data, ignore unauth data
      return false;
    }
    d_auth = false; // new data won't be auth
  }

  if (auth) {
    /* we don't want to keep a non-auth entry while we have an auth one */
    if (vStateIsBogus(state) && (!vStateIsBogus(d_state) && d_state != vState::Indeterminate) && d_ttd > now) {
      /* the new entry is Bogus, the existing one is not and is still valid, let's keep the existing one */
      return false;
    }
    // Always allow upgrade unauth data to auth
    if (!d_auth) {
      return true;
    }
  }

  if (SyncRes::s_locked_ttlperc > 0) {
    // Override locking if existing data is stale or new data is Secure or refreshing
    if (d_ttd <= now || state == vState::Secure || refresh) {
      return true;
    }
    const uint32_t percentage = 100 - SyncRes::s_locked_ttlperc;
    const time_t ttl = d_ttd - now;
    const uint32_t lockline = d_orig_ttl * percentage / 100;
    // We know ttl is > 0 as d_ttd > now
    // coverity[store_truncates_time_t]
    const bool locked = static_cast<uint32_t>(ttl) > lockline;
    if (locked) {
      return false;
    }
  }

  return true;
}

bool MemRecursorCache::replace(CacheEntry&& entry)
{
  if (!entry.d_netmask.empty() || entry.d_rtag) {
    // We don't handle that yet
    return false;
  }
  auto& shard = getMap(entry.d_qname);
  auto lockedShard = shard.lock();

  lockedShard->d_cachecachevalid = false;
  entry.d_submitted = false;
  if (lockedShard->d_map.emplace(std::move(entry)).second) {
    shard.incEntriesCount();
    return true;
  }
  return false;
}

void MemRecursorCache::replace(time_t now, const DNSName& qname, const QType qtype, const vector<DNSRecord>& content, const SigRecsVec& signatures, const AuthRecsVec& authorityRecs, bool auth, const DNSName& authZone, const boost::optional<Netmask>& ednsmaskArg, const OptTag& routingTag, vState state, const boost::optional<Extra>& extra, bool refresh, time_t ttl_time)
{
  auto& shard = getMap(qname);
  auto lockedShard = shard.lock();

  lockedShard->d_cachecachevalid = false;

  boost::optional<Netmask> ednsmask;
  if (ednsmaskArg) {
    ednsmask = ednsmaskArg->getNormalized();
  }

  // We only store with a tag if we have an ednsmask and the tag is available
  // We only store an ednsmask if we do not have a tag and we do have a mask.
  auto key = std::tuple(qname, qtype.getCode(), ednsmask ? routingTag : boost::none, (ednsmask && !routingTag) ? *ednsmask : Netmask());
  bool isNew = false;
  cache_t::iterator stored = lockedShard->d_map.find(key);
  if (stored == lockedShard->d_map.end()) {
    stored = lockedShard->d_map.insert(CacheEntry(key, auth)).first;
    shard.incEntriesCount();
    isNew = true;
  }

  /* if we are inserting a new entry or updating an expired one (in which case the
     ECS index might have been removed but the entry still exists because it has not
     been garbage collected yet) we might need to update the ECS index.
     Otherwise it should already be indexed and we don't need to update it.
  */
  if (isNew || stored->d_ttd <= now) {
    /* don't bother building an ecsIndex if we don't have any netmask-specific entries */
    if (!routingTag && ednsmask && !ednsmask->empty()) {
      auto ecsIndexKey = std::tuple(qname, qtype.getCode());
      auto ecsIndex = lockedShard->d_ecsIndex.find(ecsIndexKey);
      if (ecsIndex == lockedShard->d_ecsIndex.end()) {
        ecsIndex = lockedShard->d_ecsIndex.insert(ECSIndexEntry(qname, qtype.getCode())).first;
      }
      ecsIndex->addMask(*ednsmask);
    }
  }

  time_t maxTTD = std::numeric_limits<time_t>::max();
  CacheEntry cacheEntry = *stored; // this is a COPY
  cacheEntry.d_qtype = qtype.getCode();

  if (!isNew && !cacheEntry.shouldReplace(now, auth, state, refresh)) {
    return;
  }

  cacheEntry.d_state = state;

  // refuse any attempt to *raise* the TTL of auth NS records, as it would make it possible
  // for an auth to keep a "ghost" zone alive forever, even after the delegation is gone from
  // the parent
  // BUT make sure that we CAN refresh the root
  if (cacheEntry.d_auth && auth && qtype == QType::NS && !isNew && !qname.isRoot()) {
    maxTTD = cacheEntry.d_ttd;
  }

  if (auth) {
    cacheEntry.d_auth = true;
  }

  if (!signatures.empty()) {
    cacheEntry.d_signatures = std::make_shared<const SigRecsVec>(signatures);
  }
  else {
    cacheEntry.d_signatures = nullptr;
  }
  if (!authorityRecs.empty()) {
    cacheEntry.d_authorityRecs = std::make_shared<const AuthRecsVec>(authorityRecs);
  }
  else {
    cacheEntry.d_authorityRecs = nullptr;
  }
  cacheEntry.d_records.clear();
  cacheEntry.d_authZone = authZone;
  if (extra) {
    cacheEntry.d_from = extra->d_address;
    cacheEntry.d_tcp = extra->d_tcp;
  }
  else {
    cacheEntry.d_from = ComboAddress();
    cacheEntry.d_tcp = false;
  }

  size_t toStore = content.size();
  if (toStore <= s_maxRRSetSize) {
    cacheEntry.d_tooBig = false;
  }
  else {
    toStore = 1; // record cache does not like empty RRSets
    cacheEntry.d_tooBig = true;
  }
  cacheEntry.d_records.reserve(toStore);
  for (const auto& record : content) {
    /* Yes, we have altered the d_ttl value by adding time(nullptr) to it
       prior to calling this function, so the TTL actually holds a TTD. */
    cacheEntry.d_ttd = min(maxTTD, static_cast<time_t>(record.d_ttl)); // XXX this does weird things if TTLs differ in the set

    // coverity[store_truncates_time_t]
    cacheEntry.d_orig_ttl = cacheEntry.d_ttd - ttl_time;
    // Even though we record the time the ttd was computed, there still seems to be a case where the computed
    // d_orig_ttl can wrap.
    // So sanitize the computed ce.d_orig_ttl to be on the safe side
    if (cacheEntry.d_orig_ttl < SyncRes::s_minimumTTL || cacheEntry.d_orig_ttl > SyncRes::s_maxcachettl) {
      cacheEntry.d_orig_ttl = SyncRes::s_minimumTTL;
    }
    cacheEntry.d_records.push_back(record.getContent());
    if (--toStore == 0) {
      break;
    }
  }

  if (!isNew) {
    moveCacheItemToBack<SequencedTag>(lockedShard->d_map, stored);
  }
  cacheEntry.d_submitted = false;
  cacheEntry.d_servedStale = 0;
  lockedShard->d_map.replace(stored, cacheEntry);
}

size_t MemRecursorCache::doWipeCache(const DNSName& name, bool sub, const QType qtype)
{
  size_t count = 0;

  if (!sub) {
    auto& shard = getMap(name);
    auto lockedShard = shard.lock();
    lockedShard->d_cachecachevalid = false;
    auto& idx = lockedShard->d_map.get<OrderedTag>();
    auto range = idx.equal_range(name);
    auto iter = range.first;
    while (iter != range.second) {
      if (iter->d_qtype == qtype || qtype == 0xffff) {
        iter = idx.erase(iter);
        count++;
        shard.decEntriesCount();
      }
      else {
        ++iter;
      }
    }

    if (qtype == 0xffff) {
      auto& ecsIdx = lockedShard->d_ecsIndex.get<OrderedTag>();
      auto ecsIndexRange = ecsIdx.equal_range(name);
      ecsIdx.erase(ecsIndexRange.first, ecsIndexRange.second);
    }
    else {
      auto& ecsIdx = lockedShard->d_ecsIndex.get<HashedTag>();
      auto ecsIndexRange = ecsIdx.equal_range(std::tie(name, qtype));
      ecsIdx.erase(ecsIndexRange.first, ecsIndexRange.second);
    }
  }
  else {
    for (auto& content : d_maps) {
      auto map = content.lock();
      map->d_cachecachevalid = false;
      auto& idx = map->d_map.get<OrderedTag>();
      for (auto i = idx.lower_bound(name); i != idx.end();) {
        if (!i->d_qname.isPartOf(name)) {
          break;
        }
        if (i->d_qtype == qtype || qtype == 0xffff) {
          count++;
          i = idx.erase(i);
          content.decEntriesCount();
        }
        else {
          ++i;
        }
      }
      auto& ecsIdx = map->d_ecsIndex.get<OrderedTag>();
      for (auto i = ecsIdx.lower_bound(name); i != ecsIdx.end();) {
        if (!i->d_qname.isPartOf(name)) {
          break;
        }
        if (i->d_qtype == qtype || qtype == 0xffff) {
          i = ecsIdx.erase(i);
        }
        else {
          ++i;
        }
      }
    }
  }
  return count;
}

// Name should be doLimitTime or so
bool MemRecursorCache::doAgeCache(time_t now, const DNSName& name, const QType qtype, uint32_t newTTL)
{
  auto& shard = getMap(name);
  auto lockedShard = shard.lock();
  cache_t::iterator iter = lockedShard->d_map.find(std::tie(name, qtype));
  if (iter == lockedShard->d_map.end()) {
    return false;
  }

  CacheEntry cacheEntry = *iter;
  if (cacheEntry.d_ttd < now) {
    return false; // would be dead anyhow
  }

  // coverity[store_truncates_time_t]
  auto maxTTL = static_cast<uint32_t>(cacheEntry.d_ttd - now);
  if (maxTTL > newTTL) {
    lockedShard->d_cachecachevalid = false;

    time_t newTTD = now + newTTL;

    if (cacheEntry.d_ttd > newTTD) {
      cacheEntry.d_ttd = newTTD;
      lockedShard->d_map.replace(iter, cacheEntry);
    }
    return true;
  }
  return false;
}

bool MemRecursorCache::updateValidationStatus(time_t now, const DNSName& qname, const QType qtype, const ComboAddress& who, const OptTag& routingTag, bool requireAuth, vState newState, boost::optional<time_t> capTTD)
{
  if (qtype == QType::ANY) {
    throw std::runtime_error("Trying to update the DNSSEC validation status of all (via ANY) records for " + qname.toLogString());
  }
  if (qtype == QType::ADDR) {
    throw std::runtime_error("Trying to update the DNSSEC validation status of several (via ADDR) records for " + qname.toLogString());
  }

  auto& content = getMap(qname);
  auto map = content.lock();

  bool updated = false;
  if (!map->d_ecsIndex.empty() && !routingTag) {
    auto entry = getEntryUsingECSIndex(*map, now, qname, qtype, requireAuth, who, false); // XXX serveStale?
    if (entry == map->d_map.end()) {
      return false;
    }

    entry->d_state = newState;
    if (capTTD) {
      entry->d_ttd = std::min(entry->d_ttd, *capTTD);
    }
    return true;
  }

  auto entries = getEntries(*map, qname, qtype, routingTag);

  for (auto i = entries.first; i != entries.second; ++i) {
    auto firstIndexIterator = map->d_map.project<OrderedTag>(i);

    if (!entryMatches(firstIndexIterator, qtype, requireAuth, who)) {
      continue;
    }

    i->d_state = newState;
    if (capTTD) {
      i->d_ttd = std::min(i->d_ttd, *capTTD);
    }
    updated = true;

    break;
  }

  return updated;
}

uint64_t MemRecursorCache::doDump(int fileDesc, size_t maxCacheEntries)
{
  int newfd = dup(fileDesc);
  if (newfd == -1) {
    return 0;
  }
  auto filePtr = pdns::UniqueFilePtr(fdopen(newfd, "w"));
  if (!filePtr) { // dup probably failed
    close(newfd);
    return 0;
  }

  fprintf(filePtr.get(), "; main record cache dump follows\n;\n");
  uint64_t count = 0;
  size_t shardNumber = 0;
  size_t min = std::numeric_limits<size_t>::max();
  size_t max = 0;
  for (auto& shard : d_maps) {
    auto lockedShard = shard.lock();
    const auto shardSize = lockedShard->d_map.size();
    size_t bytes = 0;
    for (const auto& entry : lockedShard->d_map) {
      bytes += entry.sizeEstimate();
    }
    fprintf(filePtr.get(), "; record cache shard %zu; size %zu bytes %zu\n", shardNumber, shardSize, bytes);
    min = std::min(min, shardSize);
    max = std::max(max, shardSize);
    shardNumber++;
    const auto& sidx = lockedShard->d_map.get<SequencedTag>();
    time_t now = time(nullptr);
    for (const auto& recordSet : sidx) {
      for (const auto& record : recordSet.d_records) {
        count++;
        try {
          fprintf(filePtr.get(), "%s %" PRIu32 " %" PRId64 " IN %s %s ; (%s) auth=%i zone=%s from=%s nm=%s rtag=%s ss=%hd%s%s\n", recordSet.d_qname.toString().c_str(), recordSet.d_orig_ttl, static_cast<int64_t>(recordSet.d_ttd - now), recordSet.d_qtype.toString().c_str(), record->getZoneRepresentation().c_str(), vStateToString(recordSet.d_state).c_str(), static_cast<int>(recordSet.d_auth), recordSet.d_authZone.toLogString().c_str(), recordSet.d_from.toString().c_str(), recordSet.d_netmask.empty() ? "" : recordSet.d_netmask.toString().c_str(), !recordSet.d_rtag ? "" : recordSet.d_rtag.get().c_str(), recordSet.d_servedStale, recordSet.d_tooBig ? " (too big!)" : "", recordSet.d_tcp ? " tcp" : "");
        }
        catch (...) {
          fprintf(filePtr.get(), "; error printing '%s'\n", recordSet.d_qname.empty() ? "EMPTY" : recordSet.d_qname.toString().c_str());
        }
      }
      if (recordSet.d_signatures) {
        for (const auto& sig : *recordSet.d_signatures) {
          count++;
          try {
            fprintf(filePtr.get(), "%s %" PRIu32 " %" PRId64 " IN RRSIG %s ; %s\n", recordSet.d_qname.toString().c_str(), recordSet.d_orig_ttl, static_cast<int64_t>(recordSet.d_ttd - now), sig->getZoneRepresentation().c_str(), recordSet.d_netmask.empty() ? "" : recordSet.d_netmask.toString().c_str());
          }
          catch (...) {
            fprintf(filePtr.get(), "; error printing '%s'\n", recordSet.d_qname.empty() ? "EMPTY" : recordSet.d_qname.toString().c_str());
          }
        }
      }
    }
  }
  fprintf(filePtr.get(), "; main record cache size: %zu/%zu shards: %zu min/max shard size: %zu/%zu\n", size(), maxCacheEntries, d_maps.size(), min, max);
  return count;
}

void MemRecursorCache::doPrune(time_t now, size_t keep)
{
  size_t cacheSize = size();
  pruneMutexCollectionsVector<SequencedTag>(now, d_maps, keep, cacheSize);
}

enum class PBCacheDump : protozero::pbf_tag_type
{
  required_string_version = 1,
  required_string_identity = 2,
  required_uint64_protocolVersion = 3,
  required_int64_time = 4,
  required_string_type = 5,
  repeated_message_cacheEntry = 6,
};

enum class PBCacheEntry : protozero::pbf_tag_type
{
  repeated_bytes_record = 1,
  repeated_bytes_sig = 2,
  repeated_message_authRecord = 3,
  required_bytes_name = 4,
  required_bytes_authZone = 5,
  required_message_from = 6,
  optional_bytes_netmask = 7,
  optional_bytes_rtag = 8,
  required_uint32_state = 9,
  required_int64_ttd = 10,
  required_uint32_orig_ttl = 11,
  required_uint32_servedStale = 12,
  required_uint32_qtype = 13,
  required_bool_auth = 14,
  required_bool_submitted = 15,
  required_bool_tooBig = 16,
  optional_bool_tcp = 17,
};

enum class PBAuthRecord : protozero::pbf_tag_type
{
  required_bytes_name = 1,
  required_bytes_rdata = 2,
  required_uint32_type = 3,
  required_uint32_class = 4,
  required_uint32_ttl = 5,
  required_uint32_place = 6,
  required_uint32_clen = 7,
};

template <typename T, typename U>
void MemRecursorCache::getRecordSet(T& message, U recordSet)
{
  // Two fields below must come before the other fields
  message.add_bytes(PBCacheEntry::required_bytes_name, recordSet->d_qname.toString());
  message.add_uint32(PBCacheEntry::required_uint32_qtype, recordSet->d_qtype);
  for (const auto& record : recordSet->d_records) {
    message.add_bytes(PBCacheEntry::repeated_bytes_record, record->serialize(recordSet->d_qname, true));
  }
  if (recordSet->d_signatures) {
    for (const auto& record : *recordSet->d_signatures) {
      message.add_bytes(PBCacheEntry::repeated_bytes_sig, record->serialize(recordSet->d_qname, true));
    }
  }
  if (recordSet->d_authorityRecs) {
    for (const auto& authRec : *recordSet->d_authorityRecs) {
      protozero::pbf_builder<PBAuthRecord> auth(message, PBCacheEntry::repeated_message_authRecord);
      auth.add_bytes(PBAuthRecord::required_bytes_name, authRec.d_name.toString());
      auth.add_bytes(PBAuthRecord::required_bytes_rdata, authRec.getContent()->serialize(authRec.d_name, true));
      auth.add_uint32(PBAuthRecord::required_uint32_type, authRec.d_type);
      auth.add_uint32(PBAuthRecord::required_uint32_class, authRec.d_class);
      auth.add_uint32(PBAuthRecord::required_uint32_ttl, authRec.d_ttl);
      auth.add_uint32(PBAuthRecord::required_uint32_place, authRec.d_place);
      auth.add_uint32(PBAuthRecord::required_uint32_clen, authRec.d_clen);
    }
  }
  message.add_bytes(PBCacheEntry::required_bytes_authZone, recordSet->d_authZone.toString());
  encodeComboAddress(message, PBCacheEntry::required_message_from, recordSet->d_from);
  encodeNetmask(message, PBCacheEntry::optional_bytes_netmask, recordSet->d_netmask);
  if (recordSet->d_rtag) {
    message.add_bytes(PBCacheEntry::optional_bytes_rtag, *recordSet->d_rtag);
  }
  message.add_uint32(PBCacheEntry::required_uint32_state, static_cast<uint32_t>(recordSet->d_state));
  message.add_int64(PBCacheEntry::required_int64_ttd, recordSet->d_ttd);
  message.add_uint32(PBCacheEntry::required_uint32_orig_ttl, recordSet->d_orig_ttl);
  message.add_uint32(PBCacheEntry::required_uint32_servedStale, recordSet->d_servedStale);
  message.add_bool(PBCacheEntry::required_bool_auth, recordSet->d_auth);
  message.add_bool(PBCacheEntry::required_bool_submitted, recordSet->d_submitted);
  message.add_bool(PBCacheEntry::required_bool_tooBig, recordSet->d_tooBig);
  message.add_bool(PBCacheEntry::optional_bool_tcp, recordSet->d_tcp);
}

size_t MemRecursorCache::getRecordSets(size_t perShard, size_t maxSize, std::string& ret)
{
  auto log = g_slog->withName("recordcache")->withValues("perShard", Logging::Loggable(perShard), "maxSize", Logging::Loggable(maxSize));
  log->info(Logr::Info, "Producing cache dump");

  // A size estimate is hard: size() returns the number of record *sets*. Each record set can have
  // multiple records, plus other associated records like signatures. 150 seems to works ok.
  size_t estimate = maxSize == 0 ? size() * 150 : maxSize + 4096; // We may overshoot (will be rolled back)

  if (perShard == 0) {
    perShard = std::numeric_limits<size_t>::max();
  }
  if (maxSize == 0) {
    maxSize = std::numeric_limits<size_t>::max();
  }
  protozero::pbf_builder<PBCacheDump> full(ret);
  full.add_string(PBCacheDump::required_string_version, getPDNSVersion());
  full.add_string(PBCacheDump::required_string_identity, SyncRes::s_serverID);
  full.add_uint64(PBCacheDump::required_uint64_protocolVersion, 1);
  full.add_int64(PBCacheDump::required_int64_time, time(nullptr));
  full.add_string(PBCacheDump::required_string_type, "PBCacheDump");

  size_t count = 0;
  ret.reserve(estimate);

  for (auto& shard : d_maps) {
    auto lockedShard = shard.lock();
    const auto& sidx = lockedShard->d_map.get<SequencedTag>();
    size_t thisShardCount = 0;
    for (auto recordSet = sidx.rbegin(); recordSet != sidx.rend(); ++recordSet) {
      protozero::pbf_builder<PBCacheEntry> message(full, PBCacheDump::repeated_message_cacheEntry);
      getRecordSet(message, recordSet);
      if (ret.size() > maxSize) {
        message.rollback();
        log->info(Logr::Info, "Produced cache dump (max size reached)", "size", Logging::Loggable(ret.size()), "count", Logging::Loggable(count));
        return count;
      }
      ++count;
      ++thisShardCount;
      if (thisShardCount >= perShard) {
        break;
      }
    }
  }
  log->info(Logr::Info, "Produced cache dump", "size", Logging::Loggable(ret.size()), "count", Logging::Loggable(count));
  return count;
}

static void putAuthRecord(protozero::pbf_message<PBCacheEntry>& message, const DNSName& qname, std::vector<DNSRecord>& authRecs)
{
  protozero::pbf_message<PBAuthRecord> auth = message.get_message();
  DNSRecord authRecord;
  while (auth.next()) {
    switch (auth.tag()) {
    case PBAuthRecord::required_bytes_name:
      authRecord.d_name = DNSName(auth.get_bytes());
      break;
    case PBAuthRecord::required_bytes_rdata: {
      auto ptr = DNSRecordContent::deserialize(qname, authRecord.d_type, auth.get_bytes());
      authRecord.setContent(ptr);
      break;
    }
    case PBAuthRecord::required_uint32_class:
      authRecord.d_class = auth.get_uint32();
      break;
    case PBAuthRecord::required_uint32_type:
      authRecord.d_type = auth.get_uint32();
      break;
    case PBAuthRecord::required_uint32_ttl:
      authRecord.d_ttl = auth.get_uint32();
      break;
    case PBAuthRecord::required_uint32_place:
      authRecord.d_place = static_cast<DNSResourceRecord::Place>(auth.get_uint32());
      break;
    case PBAuthRecord::required_uint32_clen:
      authRecord.d_clen = auth.get_uint32();
      break;
    default:
      break;
    }
  }
  authRecs.emplace_back(authRecord);
}

template <typename T>
bool MemRecursorCache::putRecordSet(T& message)
{
  AuthRecsVec authRecs;
  SigRecsVec sigRecs;
  CacheEntry cacheEntry{{g_rootdnsname, QType::A, boost::none, Netmask()}, false};
  while (message.next()) {
    switch (message.tag()) {
    case PBCacheEntry::repeated_bytes_record: {
      auto ptr = DNSRecordContent::deserialize(cacheEntry.d_qname, cacheEntry.d_qtype, message.get_bytes());
      cacheEntry.d_records.emplace_back(ptr);
      break;
    }
    case PBCacheEntry::repeated_bytes_sig: {
      auto ptr = DNSRecordContent::deserialize(cacheEntry.d_qname, QType::RRSIG, message.get_bytes());
      sigRecs.emplace_back(std::dynamic_pointer_cast<RRSIGRecordContent>(ptr));
      break;
    }
    case PBCacheEntry::repeated_message_authRecord:
      putAuthRecord(message, cacheEntry.d_qname, authRecs);
      break;
    case PBCacheEntry::required_bytes_name:
      cacheEntry.d_qname = DNSName(message.get_bytes());
      break;
    case PBCacheEntry::required_bytes_authZone:
      cacheEntry.d_authZone = DNSName(message.get_bytes());
      break;
    case PBCacheEntry::required_message_from:
      decodeComboAddress(message, cacheEntry.d_from);
      break;
    case PBCacheEntry::optional_bytes_netmask:
      decodeNetmask(message, cacheEntry.d_netmask);
      break;
    case PBCacheEntry::optional_bytes_rtag:
      cacheEntry.d_rtag = message.get_bytes();
      break;
    case PBCacheEntry::required_uint32_state:
      cacheEntry.d_state = static_cast<vState>(message.get_uint32());
      break;
    case PBCacheEntry::required_int64_ttd:
      cacheEntry.d_ttd = message.get_int64();
      break;
    case PBCacheEntry::required_uint32_orig_ttl:
      cacheEntry.d_orig_ttl = message.get_uint32();
      break;
    case PBCacheEntry::required_uint32_servedStale:
      cacheEntry.d_servedStale = message.get_uint32();
      break;
    case PBCacheEntry::required_uint32_qtype:
      cacheEntry.d_qtype = message.get_uint32();
      break;
    case PBCacheEntry::required_bool_auth:
      cacheEntry.d_auth = message.get_bool();
      break;
    case PBCacheEntry::required_bool_submitted:
      cacheEntry.d_submitted = message.get_bool();
      cacheEntry.d_submitted = false; // actually not
      break;
    case PBCacheEntry::required_bool_tooBig:
      cacheEntry.d_tooBig = message.get_bool();
      break;
    case PBCacheEntry::optional_bool_tcp:
      cacheEntry.d_tcp = message.get_bool();
      break;
    default:
      break;
    }
  }
  if (!authRecs.empty()) {
    cacheEntry.d_authorityRecs = std::make_shared<const AuthRecsVec>(std::move(authRecs));
  }
  if (!sigRecs.empty()) {
    cacheEntry.d_signatures = std::make_shared<const SigRecsVec>(std::move(sigRecs));
  }
  return replace(std::move(cacheEntry));
}

size_t MemRecursorCache::putRecordSets(const std::string& pbuf)
{
  auto log = g_slog->withName("recordcache")->withValues("size", Logging::Loggable(pbuf.size()));
  log->info(Logr::Debug, "Processing cache dump");

  protozero::pbf_message<PBCacheDump> full(pbuf);
  size_t count = 0;
  size_t inserted = 0;
  try {
    bool protocolVersionSeen = false;
    bool typeSeen = false;
    while (full.next()) {
      switch (full.tag()) {
      case PBCacheDump::required_string_version: {
        auto version = full.get_string();
        log = log->withValues("version", Logging::Loggable(version));
        break;
      }
      case PBCacheDump::required_string_identity: {
        auto identity = full.get_string();
        log = log->withValues("identity", Logging::Loggable(identity));
        break;
      }
      case PBCacheDump::required_uint64_protocolVersion: {
        auto protocolVersion = full.get_uint64();
        log = log->withValues("protocolVersion", Logging::Loggable(protocolVersion));
        if (protocolVersion != 1) {
          throw std::runtime_error("Protocol version mismatch");
        }
        protocolVersionSeen = true;
        break;
      }
      case PBCacheDump::required_int64_time: {
        auto time = full.get_int64();
        log = log->withValues("time", Logging::Loggable(time));
        break;
      }
      case PBCacheDump::required_string_type: {
        auto type = full.get_string();
        if (type != "PBCacheDump") {
          throw std::runtime_error("Data type mismatch");
        }
        typeSeen = true;
        break;
      }
      case PBCacheDump::repeated_message_cacheEntry: {
        if (!protocolVersionSeen || !typeSeen) {
          throw std::runtime_error("Required field missing");
        }
        protozero::pbf_message<PBCacheEntry> message = full.get_message();
        if (putRecordSet(message)) {
          ++inserted;
        }
        ++count;
        break;
      }
      }
    }
    log->info(Logr::Info, "Processed cache dump", "processed", Logging::Loggable(count), "inserted", Logging::Loggable(inserted));
    return inserted;
  }
  catch (const std::runtime_error& e) {
    log->error(Logr::Error, e.what(), "Runtime exception processing cache dump");
  }
  catch (const std::exception& e) {
    log->error(Logr::Error, e.what(), "Exception processing cache dump");
  }
  catch (...) {
    log->error(Logr::Error, "Other exception processing cache dump");
  }
  return 0;
}

namespace boost
{
size_t hash_value(const MemRecursorCache::OptTag& rtag)
{
  return rtag ? hash_value(rtag.get()) : 0xcafebaaf;
}
}
