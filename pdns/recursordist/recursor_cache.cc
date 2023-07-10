#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cinttypes>

#include "recursor_cache.hh"
#include "misc.hh"
#include <iostream>
#include "dnsrecords.hh"
#include "arguments.hh"
#include "syncres.hh"
#include "recursor_cache.hh"
#include "namespaces.hh"
#include "cachecleaner.hh"
#include "rec-taskqueue.hh"

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

MemRecursorCache::MemRecursorCache(size_t mapsCount) :
  d_maps(mapsCount == 0 ? 1 : mapsCount)
{
}

size_t MemRecursorCache::size() const
{
  size_t count = 0;
  for (const auto& shard : d_maps) {
    count += shard.d_entriesCount;
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

// this function is too slow to poll!
size_t MemRecursorCache::bytes()
{
  size_t ret = 0;
  for (auto& shard : d_maps) {
    auto lockedShard = shard.lock();
    for (const auto& entry : lockedShard->d_map) {
      ret += sizeof(struct CacheEntry);
      ret += entry.d_qname.toString().length();
      for (const auto& record : entry.d_records) {
        ret += sizeof(record); // XXX WRONG we don't know the stored size!
      }
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
  else if (vStateIsBogus(stateUpdate)) {
    state = stateUpdate;
  }
  else if (stateUpdate == vState::Indeterminate) {
    state = stateUpdate;
  }
  else if (stateUpdate == vState::Insecure) {
    if (!vStateIsBogus(*state) && *state != vState::Indeterminate) {
      state = stateUpdate;
    }
  }
  else if (stateUpdate == vState::Secure) {
    if (!vStateIsBogus(*state) && *state != vState::Indeterminate) {
      state = stateUpdate;
    }
  }
}

time_t MemRecursorCache::handleHit(MapCombo::LockedContent& content, MemRecursorCache::OrderedTagIterator_t& entry, const DNSName& qname, uint32_t& origTTL, vector<DNSRecord>* res, vector<std::shared_ptr<const RRSIGRecordContent>>* signatures, std::vector<std::shared_ptr<DNSRecord>>* authorityRecs, bool* variable, boost::optional<vState>& state, bool* wasAuth, DNSName* fromAuthZone, ComboAddress* fromAuthIP)
{
  // MUTEX SHOULD BE ACQUIRED (as indicated by the reference to the content which is protected by a lock)
  time_t ttd = entry->d_ttd;
  origTTL = entry->d_orig_ttl;

  if (variable != nullptr && (!entry->d_netmask.empty() || entry->d_rtag)) {
    *variable = true;
  }

  if (res != nullptr) {
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
    signatures->insert(signatures->end(), entry->d_signatures.begin(), entry->d_signatures.end());
  }

  if (authorityRecs != nullptr) {
    authorityRecs->insert(authorityRecs->end(), entry->d_authorityRecs.begin(), entry->d_authorityRecs.end());
  }

  updateDNSSECValidationStateFromCache(state, entry->d_state);

  if (wasAuth != nullptr) {
    *wasAuth = *wasAuth && entry->d_auth;
  }

  if (fromAuthZone != nullptr) {
    *fromAuthZone = entry->d_authZone;
  }

  if (fromAuthIP != nullptr) {
    *fromAuthIP = entry->d_from;
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
  // We need to take care a infrequently access stale item cannot be extended past
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
      auto key = std::make_tuple(qname, qtype, boost::none, best);
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
      else {
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
  }

  /* we have nothing specific, let's see if we have a generic one */
  auto key = std::make_tuple(qname, qtype, boost::none, Netmask());
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

MemRecursorCache::Entries MemRecursorCache::getEntries(MapCombo::LockedContent& map, const DNSName& qname, const QType /* qt */, const OptTag& rtag)
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

bool MemRecursorCache::entryMatches(MemRecursorCache::OrderedTagIterator_t& entry, const QType qt, bool requireAuth, const ComboAddress& who)
{
  // This code assumes that if a routing tag is present, it matches
  // MUTEX SHOULD BE ACQUIRED
  if (requireAuth && !entry->d_auth)
    return false;

  bool match = (entry->d_qtype == qt || qt == QType::ANY || (qt == QType::ADDR && (entry->d_qtype == QType::A || entry->d_qtype == QType::AAAA)))
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
      else {
        if (!entry->d_submitted) {
          pushRefreshTask(qname, qtype, entry->d_ttd, entry->d_netmask);
          entry->d_submitted = true;
        }
      }
    }
  }
  return ttl;
}
// returns -1 for no hits
time_t MemRecursorCache::get(time_t now, const DNSName& qname, const QType qt, Flags flags, vector<DNSRecord>* res, const ComboAddress& who, const OptTag& routingTag, vector<std::shared_ptr<const RRSIGRecordContent>>* signatures, std::vector<std::shared_ptr<DNSRecord>>* authorityRecs, bool* variable, vState* state, bool* wasAuth, DNSName* fromAuthZone, ComboAddress* fromAuthIP)
{
  bool requireAuth = flags & RequireAuth;
  bool refresh = flags & Refresh;
  bool serveStale = flags & ServeStale;

  boost::optional<vState> cachedState{boost::none};
  uint32_t origTTL;

  if (res != nullptr) {
    res->clear();
  }
  const uint16_t qtype = qt.getCode();
  if (wasAuth != nullptr) {
    // we might retrieve more than one entry, we need to set that to true
    // so it will be set to false if at least one entry is not auth
    *wasAuth = true;
  }

  auto& shard = getMap(qname);
  auto lockedShard = shard.lock();

  /* If we don't have any netmask-specific entries at all, let's just skip this
     to be able to use the nice d_cachecache hack. */
  if (qtype != QType::ANY && !lockedShard->d_ecsIndex.empty() && !routingTag) {
    if (qtype == QType::ADDR) {
      time_t ret = -1;

      auto entryA = getEntryUsingECSIndex(*lockedShard, now, qname, QType::A, requireAuth, who, serveStale);
      if (entryA != lockedShard->d_map.end()) {
        ret = handleHit(*lockedShard, entryA, qname, origTTL, res, signatures, authorityRecs, variable, cachedState, wasAuth, fromAuthZone, fromAuthIP);
      }
      auto entryAAAA = getEntryUsingECSIndex(*lockedShard, now, qname, QType::AAAA, requireAuth, who, serveStale);
      if (entryAAAA != lockedShard->d_map.end()) {
        time_t ttdAAAA = handleHit(*lockedShard, entryAAAA, qname, origTTL, res, signatures, authorityRecs, variable, cachedState, wasAuth, fromAuthZone, fromAuthIP);
        if (ret > 0) {
          ret = std::min(ret, ttdAAAA);
        }
        else {
          ret = ttdAAAA;
        }
      }

      if (state && cachedState) {
        *state = *cachedState;
      }

      return ret > 0 ? (ret - now) : ret;
    }
    else {
      auto entry = getEntryUsingECSIndex(*lockedShard, now, qname, qtype, requireAuth, who, serveStale);
      if (entry != lockedShard->d_map.end()) {
        time_t ret = handleHit(*lockedShard, entry, qname, origTTL, res, signatures, authorityRecs, variable, cachedState, wasAuth, fromAuthZone, fromAuthIP);
        if (state && cachedState) {
          *state = *cachedState;
        }
        return fakeTTD(entry, qname, qtype, ret, now, origTTL, refresh);
      }
      return -1;
    }
  }

  if (routingTag) {
    auto entries = getEntries(*lockedShard, qname, qt, routingTag);
    bool found = false;
    time_t ttd;

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
        found = true;

        handleServeStaleBookkeeping(now, serveStale, firstIndexIterator);

        ttd = handleHit(*lockedShard, firstIndexIterator, qname, origTTL, res, signatures, authorityRecs, variable, cachedState, wasAuth, fromAuthZone, fromAuthIP);

        if (qt != QType::ANY && qt != QType::ADDR) { // normally if we have a hit, we are done
          break;
        }
      }
      if (found) {
        if (state && cachedState) {
          *state = *cachedState;
        }
        return fakeTTD(firstIndexIterator, qname, qtype, ttd, now, origTTL, refresh);
      }
      else {
        return -1;
      }
    }
  }
  // Try (again) without tag
  auto entries = getEntries(*lockedShard, qname, qt, boost::none);

  if (entries.first != entries.second) {
    OrderedTagIterator_t firstIndexIterator;
    bool found = false;
    time_t ttd;

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
      found = true;

      handleServeStaleBookkeeping(now, serveStale, firstIndexIterator);

      ttd = handleHit(*lockedShard, firstIndexIterator, qname, origTTL, res, signatures, authorityRecs, variable, cachedState, wasAuth, fromAuthZone, fromAuthIP);

      if (qt != QType::ANY && qt != QType::ADDR) { // normally if we have a hit, we are done
        break;
      }
    }
    if (found) {
      if (state && cachedState) {
        *state = *cachedState;
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

void MemRecursorCache::replace(time_t now, const DNSName& qname, const QType qt, const vector<DNSRecord>& content, const vector<shared_ptr<const RRSIGRecordContent>>& signatures, const std::vector<std::shared_ptr<DNSRecord>>& authorityRecs, bool auth, const DNSName& authZone, boost::optional<Netmask> ednsmask, const OptTag& routingTag, vState state, boost::optional<ComboAddress> from, bool refresh, time_t ttl_time)
{
  auto& shard = getMap(qname);
  auto lockedShard = shard.lock();

  lockedShard->d_cachecachevalid = false;
  if (ednsmask) {
    ednsmask = ednsmask->getNormalized();
  }

  // We only store with a tag if we have an ednsmask and the tag is available
  // We only store an ednsmask if we do not have a tag and we do have a mask.
  auto key = std::make_tuple(qname, qt.getCode(), ednsmask ? routingTag : boost::none, (ednsmask && !routingTag) ? *ednsmask : Netmask());
  bool isNew = false;
  cache_t::iterator stored = lockedShard->d_map.find(key);
  if (stored == lockedShard->d_map.end()) {
    stored = lockedShard->d_map.insert(CacheEntry(key, auth)).first;
    ++shard.d_entriesCount;
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
      auto ecsIndexKey = std::make_tuple(qname, qt.getCode());
      auto ecsIndex = lockedShard->d_ecsIndex.find(ecsIndexKey);
      if (ecsIndex == lockedShard->d_ecsIndex.end()) {
        ecsIndex = lockedShard->d_ecsIndex.insert(ECSIndexEntry(qname, qt.getCode())).first;
      }
      ecsIndex->addMask(*ednsmask);
    }
  }

  time_t maxTTD = std::numeric_limits<time_t>::max();
  CacheEntry ce = *stored; // this is a COPY
  ce.d_qtype = qt.getCode();

  if (!isNew && !ce.shouldReplace(now, auth, state, refresh)) {
    return;
  }

  ce.d_state = state;

  // refuse any attempt to *raise* the TTL of auth NS records, as it would make it possible
  // for an auth to keep a "ghost" zone alive forever, even after the delegation is gone from
  // the parent
  // BUT make sure that we CAN refresh the root
  if (ce.d_auth && auth && qt == QType::NS && !isNew && !qname.isRoot()) {
    maxTTD = ce.d_ttd;
  }

  if (auth) {
    ce.d_auth = true;
  }

  ce.d_signatures = signatures;
  ce.d_authorityRecs = authorityRecs;
  ce.d_records.clear();
  ce.d_records.reserve(content.size());
  ce.d_authZone = authZone;
  if (from) {
    ce.d_from = *from;
  }
  else {
    ce.d_from = ComboAddress();
  }

  for (const auto& i : content) {
    /* Yes, we have altered the d_ttl value by adding time(nullptr) to it
       prior to calling this function, so the TTL actually holds a TTD. */
    ce.d_ttd = min(maxTTD, static_cast<time_t>(i.d_ttl)); // XXX this does weird things if TTLs differ in the set

    ce.d_orig_ttl = ce.d_ttd - ttl_time;
    // Even though we record the time the ttd was computed, there still seems to be a case where the computed
    // d_orig_ttl can wrap.
    // So santize the computed ce.d_orig_ttl to be on the safe side
    if (ce.d_orig_ttl < SyncRes::s_minimumTTL || ce.d_orig_ttl > SyncRes::s_maxcachettl) {
      ce.d_orig_ttl = SyncRes::s_minimumTTL;
    }
    ce.d_records.push_back(i.getContent());
  }

  if (!isNew) {
    moveCacheItemToBack<SequencedTag>(lockedShard->d_map, stored);
  }
  ce.d_submitted = false;
  ce.d_servedStale = 0;
  lockedShard->d_map.replace(stored, ce);
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
    auto i = range.first;
    while (i != range.second) {
      if (i->d_qtype == qtype || qtype == 0xffff) {
        i = idx.erase(i);
        count++;
        --shard.d_entriesCount;
      }
      else {
        ++i;
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
    for (auto& mc : d_maps) {
      auto map = mc.lock();
      map->d_cachecachevalid = false;
      auto& idx = map->d_map.get<OrderedTag>();
      for (auto i = idx.lower_bound(name); i != idx.end();) {
        if (!i->d_qname.isPartOf(name))
          break;
        if (i->d_qtype == qtype || qtype == 0xffff) {
          count++;
          i = idx.erase(i);
          --mc.d_entriesCount;
        }
        else {
          ++i;
        }
      }
      auto& ecsIdx = map->d_ecsIndex.get<OrderedTag>();
      for (auto i = ecsIdx.lower_bound(name); i != ecsIdx.end();) {
        if (!i->d_qname.isPartOf(name))
          break;
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

  CacheEntry ce = *iter;
  if (ce.d_ttd < now) {
    return false; // would be dead anyhow
  }

  uint32_t maxTTL = static_cast<uint32_t>(ce.d_ttd - now);
  if (maxTTL > newTTL) {
    lockedShard->d_cachecachevalid = false;

    time_t newTTD = now + newTTL;

    if (ce.d_ttd > newTTD) {
      ce.d_ttd = newTTD;
      lockedShard->d_map.replace(iter, ce);
    }
    return true;
  }
  return false;
}

bool MemRecursorCache::updateValidationStatus(time_t now, const DNSName& qname, const QType qt, const ComboAddress& who, const OptTag& routingTag, bool requireAuth, vState newState, boost::optional<time_t> capTTD)
{
  uint16_t qtype = qt.getCode();
  if (qtype == QType::ANY) {
    throw std::runtime_error("Trying to update the DNSSEC validation status of all (via ANY) records for " + qname.toLogString());
  }
  if (qtype == QType::ADDR) {
    throw std::runtime_error("Trying to update the DNSSEC validation status of several (via ADDR) records for " + qname.toLogString());
  }

  auto& mc = getMap(qname);
  auto map = mc.lock();

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

  auto entries = getEntries(*map, qname, qt, routingTag);

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

uint64_t MemRecursorCache::doDump(int fd, size_t maxCacheEntries)
{
  int newfd = dup(fd);
  if (newfd == -1) {
    return 0;
  }
  auto fp = std::unique_ptr<FILE, int (*)(FILE*)>(fdopen(newfd, "w"), fclose);
  if (!fp) { // dup probably failed
    close(newfd);
    return 0;
  }

  fprintf(fp.get(), "; main record cache dump follows\n;\n");
  uint64_t count = 0;
  size_t shardNumber = 0;
  size_t min = std::numeric_limits<size_t>::max();
  size_t max = 0;
  for (auto& shard : d_maps) {
    auto lockedShard = shard.lock();
    const auto shardSize = lockedShard->d_map.size();
    fprintf(fp.get(), "; record cache shard %zu; size %zu\n", shardNumber, shardSize);
    min = std::min(min, shardSize);
    max = std::max(max, shardSize);
    shardNumber++;
    const auto& sidx = lockedShard->d_map.get<SequencedTag>();
    time_t now = time(nullptr);
    for (const auto& i : sidx) {
      for (const auto& j : i.d_records) {
        count++;
        try {
          fprintf(fp.get(), "%s %" PRIu32 " %" PRId64 " IN %s %s ; (%s) auth=%i zone=%s from=%s nm=%s rtag=%s ss=%hd\n", i.d_qname.toString().c_str(), i.d_orig_ttl, static_cast<int64_t>(i.d_ttd - now), i.d_qtype.toString().c_str(), j->getZoneRepresentation().c_str(), vStateToString(i.d_state).c_str(), i.d_auth, i.d_authZone.toLogString().c_str(), i.d_from.toString().c_str(), i.d_netmask.empty() ? "" : i.d_netmask.toString().c_str(), !i.d_rtag ? "" : i.d_rtag.get().c_str(), i.d_servedStale);
        }
        catch (...) {
          fprintf(fp.get(), "; error printing '%s'\n", i.d_qname.empty() ? "EMPTY" : i.d_qname.toString().c_str());
        }
      }
      for (const auto& sig : i.d_signatures) {
        count++;
        try {
          fprintf(fp.get(), "%s %" PRIu32 " %" PRId64 " IN RRSIG %s ; %s\n", i.d_qname.toString().c_str(), i.d_orig_ttl, static_cast<int64_t>(i.d_ttd - now), sig->getZoneRepresentation().c_str(), i.d_netmask.empty() ? "" : i.d_netmask.toString().c_str());
        }
        catch (...) {
          fprintf(fp.get(), "; error printing '%s'\n", i.d_qname.empty() ? "EMPTY" : i.d_qname.toString().c_str());
        }
      }
    }
  }
  fprintf(fp.get(), "; main record cache size: %zu/%zu shards: %zu min/max shard size: %zu/%zu\n", size(), maxCacheEntries, d_maps.size(), min, max);
  return count;
}

void MemRecursorCache::doPrune(size_t keep)
{
  size_t cacheSize = size();
  pruneMutexCollectionsVector<SequencedTag>(*this, d_maps, keep, cacheSize);
}

namespace boost
{
size_t hash_value(const MemRecursorCache::OptTag& rtag)
{
  return rtag ? hash_value(rtag.get()) : 0xcafebaaf;
}
}
