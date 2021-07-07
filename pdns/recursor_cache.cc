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

MemRecursorCache::MemRecursorCache(size_t mapsCount) : d_maps(mapsCount)
{
}

size_t MemRecursorCache::size()
{
  size_t count = 0;
  for (auto& lockGuardedMap : d_maps) {
    auto map = lock(lockGuardedMap);
    count += map->d_entriesCount;
  }
  return count;
}

pair<uint64_t,uint64_t> MemRecursorCache::stats()
{
  uint64_t c = 0, a = 0;
  for (auto& lockGuardedMap : d_maps) {
    auto map = lock(lockGuardedMap);
    c += map->d_contended_count;
    a += map->d_acquired_count;
  }
  return pair<uint64_t,uint64_t>(c, a);
}

size_t MemRecursorCache::ecsIndexSize()
{
  // XXX!
  size_t count = 0;
  for (auto& map : d_maps) {
    auto m = lock(map);
    count += m->d_ecsIndex.size();
  }
  return count;
}

// this function is too slow to poll!
size_t MemRecursorCache::bytes()
{
  size_t ret = 0;
  for (auto& map : d_maps) {
    auto m = lock(map);
    for (const auto& i : m->d_map) {
      ret += sizeof(struct CacheEntry);
      ret += i.d_qname.toString().length();
      for (const auto& record : i.d_records) {
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

time_t MemRecursorCache::handleHit(MapCombo& map, MemRecursorCache::OrderedTagIterator_t& entry, const DNSName& qname, uint32_t& origTTL, vector<DNSRecord>* res, vector<std::shared_ptr<RRSIGRecordContent>>* signatures, std::vector<std::shared_ptr<DNSRecord>>* authorityRecs, bool* variable, boost::optional<vState>& state, bool* wasAuth, DNSName* fromAuthZone)
{
  // MUTEX SHOULD BE ACQUIRED
  time_t ttd = entry->d_ttd;
  origTTL = entry->d_orig_ttl;

  if (variable && (!entry->d_netmask.empty() || entry->d_rtag)) {
    *variable = true;
  }

  if (res) {
    res->reserve(res->size() + entry->d_records.size());

    for(const auto& k : entry->d_records) {
      DNSRecord dr;
      dr.d_name = qname;
      dr.d_type = entry->d_qtype;
      dr.d_class = QClass::IN;
      dr.d_content = k;
      dr.d_ttl = static_cast<uint32_t>(entry->d_ttd); // XXX truncation
      dr.d_place = DNSResourceRecord::ANSWER;
      res->push_back(std::move(dr));
    }
  }

  if (signatures) {
    signatures->insert(signatures->end(), entry->d_signatures.begin(), entry->d_signatures.end());
  }

  if (authorityRecs) {
    authorityRecs->insert(authorityRecs->end(), entry->d_authorityRecs.begin(), entry->d_authorityRecs.end());
  }

  updateDNSSECValidationStateFromCache(state, entry->d_state);

  if (wasAuth) {
    *wasAuth = *wasAuth && entry->d_auth;
  }

  if (fromAuthZone) {
    *fromAuthZone = entry->d_authZone;
  }

  moveCacheItemToBack<SequencedTag>(map.d_map, entry);

  return ttd;
}

MemRecursorCache::cache_t::const_iterator MemRecursorCache::getEntryUsingECSIndex(MapCombo& map, time_t now, const DNSName &qname, const QType qtype, bool requireAuth, const ComboAddress& who)
{
  // MUTEX SHOULD BE ACQUIRED
  auto ecsIndexKey = tie(qname, qtype);
  auto ecsIndex = map.d_ecsIndex.find(ecsIndexKey);
  if (ecsIndex != map.d_ecsIndex.end() && !ecsIndex->isEmpty()) {
    /* we have netmask-specific entries, let's see if we match one */
    while (true) {
      const Netmask best = ecsIndex->lookupBestMatch(who);
      if (best.empty()) {
        /* we have nothing more specific for you */
        break;
      }
      auto key = boost::make_tuple(qname, qtype, boost::none, best);
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
        ecsIndex->removeNetmask(best);
        if (ecsIndex->isEmpty()) {
          map.d_ecsIndex.erase(ecsIndex);
          break;
        }
      }
    }
  }

  /* we have nothing specific, let's see if we have a generic one */
  auto key = boost::make_tuple(qname, qtype, boost::none, Netmask());
  auto entry = map.d_map.find(key);
  if (entry != map.d_map.end()) {
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

MemRecursorCache::Entries MemRecursorCache::getEntries(MapCombo& map, const DNSName &qname, const QType qt, const OptTag& rtag )
{
  // MUTEX SHOULD BE ACQUIRED
  if (!map.d_cachecachevalid || map.d_cachedqname != qname || map.d_cachedrtag != rtag) {
    map.d_cachedqname = qname;
    map.d_cachedrtag = rtag;
    const auto& idx = map.d_map.get<NameAndRTagOnlyHashedTag>();
    map.d_cachecache = idx.equal_range(tie(qname, rtag));
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

  bool match = (entry->d_qtype == qt || qt == QType::ANY ||
                (qt == QType::ADDR && (entry->d_qtype == QType::A || entry->d_qtype == QType::AAAA)))
    && (entry->d_netmask.empty() || entry->d_netmask.match(who));
  return match;
}

// Fake a cache miss if more than refreshTTLPerc of the original TTL has passed
time_t MemRecursorCache::fakeTTD(MemRecursorCache::OrderedTagIterator_t& entry, const DNSName& qname, QType qtype, time_t ret, time_t now, uint32_t origTTL, bool refresh)
{
  time_t ttl = ret - now;
  if (ttl > 0 && SyncRes::s_refresh_ttlperc > 0) {
    const uint32_t deadline = origTTL * SyncRes::s_refresh_ttlperc / 100;
    const bool almostExpired = static_cast<uint32_t>(ttl) <= deadline;
    if (almostExpired && qname != g_rootdnsname) {
      if (refresh) {
        return -1;
      } else {
        if (!entry->d_submitted) {
          pushTask(qname, qtype, entry->d_ttd);
          entry->d_submitted = true;
        }
      }
    }
  }
  return ttl;
}
// returns -1 for no hits
time_t MemRecursorCache::get(time_t now, const DNSName &qname, const QType qt, bool requireAuth, vector<DNSRecord>* res, const ComboAddress& who, bool refresh, const OptTag& routingTag, vector<std::shared_ptr<RRSIGRecordContent>>* signatures, std::vector<std::shared_ptr<DNSRecord>>* authorityRecs, bool* variable, vState* state, bool* wasAuth, DNSName* fromAuthZone)
{
  boost::optional<vState> cachedState{boost::none};
  uint32_t origTTL;

  if(res) {
    res->clear();
  }
  const uint16_t qtype = qt.getCode();
  if (wasAuth) {
    // we might retrieve more than one entry, we need to set that to true
    // so it will be set to false if at least one entry is not auth
    *wasAuth = true;
  }

  auto& lockGuardedMap = getMap(qname);
  auto map = lock(lockGuardedMap);

  /* If we don't have any netmask-specific entries at all, let's just skip this
     to be able to use the nice d_cachecache hack. */
  if (qtype != QType::ANY && !map->d_ecsIndex.empty() && !routingTag) {
    if (qtype == QType::ADDR) {
      time_t ret = -1;

      auto entryA = getEntryUsingECSIndex(*map, now, qname, QType::A, requireAuth, who);
      if (entryA != map->d_map.end()) {
        ret = handleHit(*map, entryA, qname, origTTL, res, signatures, authorityRecs, variable, cachedState, wasAuth, fromAuthZone);
      }
      auto entryAAAA = getEntryUsingECSIndex(*map, now, qname, QType::AAAA, requireAuth, who);
      if (entryAAAA != map->d_map.end()) {
        time_t ttdAAAA = handleHit(*map, entryAAAA, qname, origTTL, res, signatures, authorityRecs, variable, cachedState, wasAuth, fromAuthZone);
        if (ret > 0) {
          ret = std::min(ret, ttdAAAA);
        } else {
          ret = ttdAAAA;
        }
      }

      if (state && cachedState) {
        *state = *cachedState;
      }

      return ret > 0 ? (ret - now) : ret;
    }
    else {
      auto entry = getEntryUsingECSIndex(*map, now, qname, qtype, requireAuth, who);
      if (entry != map->d_map.end()) {
        time_t ret = handleHit(*map, entry, qname, origTTL, res, signatures, authorityRecs, variable, cachedState, wasAuth, fromAuthZone);
        if (state && cachedState) {
          *state = *cachedState;
        }
        return fakeTTD(entry, qname, qtype, ret, now, origTTL, refresh);
      }
      return -1;
    }
  }

  if (routingTag) {
    auto entries = getEntries(*map, qname, qt, routingTag);
    bool found = false;
    time_t ttd;

    if (entries.first != entries.second) {
      OrderedTagIterator_t firstIndexIterator;
      for (auto i=entries.first; i != entries.second; ++i) {
        firstIndexIterator = map->d_map.project<OrderedTag>(i);

        if (i->d_ttd <= now) {
          moveCacheItemToFront<SequencedTag>(map->d_map, firstIndexIterator);
          continue;
        }

        if (!entryMatches(firstIndexIterator, qtype, requireAuth, who)) {
          continue;
        }
        found = true;
        ttd = handleHit(*map, firstIndexIterator, qname, origTTL, res, signatures, authorityRecs, variable, cachedState, wasAuth, fromAuthZone);

        if (qt != QType::ANY && qt != QType::ADDR) { // normally if we have a hit, we are done
          break;
        }
      }
      if (found) {
        if (state && cachedState) {
          *state = *cachedState;
        }
        return fakeTTD(firstIndexIterator, qname, qtype, ttd, now, origTTL, refresh);
      } else {
        return -1;
      }
    }
  }
  // Try (again) without tag
  auto entries = getEntries(*map, qname, qt, boost::none);

  if (entries.first != entries.second) {
    OrderedTagIterator_t firstIndexIterator;
    bool found = false;
    time_t ttd;

    for (auto i=entries.first; i != entries.second; ++i) {
      firstIndexIterator = map->d_map.project<OrderedTag>(i);

      if (i->d_ttd <= now) {
        moveCacheItemToFront<SequencedTag>(map->d_map, firstIndexIterator);
        continue;
      }

      if (!entryMatches(firstIndexIterator, qtype, requireAuth, who)) {
        continue;
      }

      found = true;
      ttd = handleHit(*map, firstIndexIterator, qname, origTTL, res, signatures, authorityRecs, variable, cachedState, wasAuth, fromAuthZone);

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

void MemRecursorCache::replace(time_t now, const DNSName &qname, const QType qt, const vector<DNSRecord>& content, const vector<shared_ptr<RRSIGRecordContent>>& signatures, const std::vector<std::shared_ptr<DNSRecord>>& authorityRecs, bool auth, const DNSName& authZone, boost::optional<Netmask> ednsmask, const OptTag& routingTag, vState state, boost::optional<ComboAddress> from)
{
  auto& lockGuardedMap = getMap(qname);
  auto map = lock(lockGuardedMap);

  map->d_cachecachevalid = false;
  if (ednsmask) {
    ednsmask = ednsmask->getNormalized();
  }

  // We only store with a tag if we have an ednsmask and the tag is available
  // We only store an ednsmask if we do not have a tag and we do have a mask.
  auto key = boost::make_tuple(qname, qt.getCode(), ednsmask ? routingTag : boost::none, (ednsmask && !routingTag) ? *ednsmask : Netmask());
  bool isNew = false;
  cache_t::iterator stored = map->d_map.find(key);
  if (stored == map->d_map.end()) {
    stored = map->d_map.insert(CacheEntry(key, auth)).first;
    map->d_entriesCount++;
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
      auto ecsIndexKey = boost::make_tuple(qname, qt.getCode());
      auto ecsIndex = map->d_ecsIndex.find(ecsIndexKey);
      if (ecsIndex == map->d_ecsIndex.end()) {
        ecsIndex = map->d_ecsIndex.insert(ECSIndexEntry(qname, qt.getCode())).first;
      }
      ecsIndex->addMask(*ednsmask);
    }
  }

  time_t maxTTD=std::numeric_limits<time_t>::max();
  CacheEntry ce=*stored; // this is a COPY
  ce.d_qtype=qt.getCode();

  if(!auth && ce.d_auth) {  // unauth data came in, we have some auth data, but is it fresh?
    if(ce.d_ttd > now) { // we still have valid data, ignore unauth data
      return;
    }
    else {
      ce.d_auth = false;  // new data won't be auth
    }
  }

  if (auth) {
    /* we don't want to keep a non-auth entry while we have an auth one */
    if (vStateIsBogus(state) && (!vStateIsBogus(ce.d_state) && ce.d_state != vState::Indeterminate) && ce.d_ttd > now) {
      /* the new entry is Bogus, the existing one is not and is still valid, let's keep the existing one */
      return;
    }
  }

  ce.d_state = state;

  // refuse any attempt to *raise* the TTL of auth NS records, as it would make it possible
  // for an auth to keep a "ghost" zone alive forever, even after the delegation is gone from
  // the parent
  // BUT make sure that we CAN refresh the root
  if (ce.d_auth && auth && qt == QType::NS && !isNew && !qname.isRoot()) {
    //    cerr<<"\tLimiting TTL of auth->auth NS set replace to "<<ce.d_ttd<<endl;
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
  } else {
    ce.d_from = ComboAddress();
  }

  for (const auto& i : content) {
    /* Yes, we have altered the d_ttl value by adding time(nullptr) to it
       prior to calling this function, so the TTL actually holds a TTD. */
    ce.d_ttd = min(maxTTD, static_cast<time_t>(i.d_ttl));   // XXX this does weird things if TTLs differ in the set
    ce.d_orig_ttl = ce.d_ttd - now;
    ce.d_records.push_back(i.d_content);
  }

  if (!isNew) {
    moveCacheItemToBack<SequencedTag>(map->d_map, stored);
  }
  ce.d_submitted = false;
  map->d_map.replace(stored, ce);
}

size_t MemRecursorCache::doWipeCache(const DNSName& name, bool sub, const QType qtype)
{
  size_t count = 0;

  if (!sub) {
    auto& lockGuardedMap = getMap(name);
    auto map = lock(lockGuardedMap);
    map->d_cachecachevalid = false;
    auto& idx = map->d_map.get<OrderedTag>();
    auto range = idx.equal_range(name);
    auto i = range.first;
    while (i != range.second) {
      if (i->d_qtype == qtype || qtype == 0xffff) {
        i = idx.erase(i);
        count++;
        map->d_entriesCount--;
      } else {
        ++i;
      }
    }

    if (qtype == 0xffff) {
      auto& ecsIdx = map->d_ecsIndex.get<OrderedTag>();
      auto ecsIndexRange = ecsIdx.equal_range(name);
      ecsIdx.erase(ecsIndexRange.first, ecsIndexRange.second);
    }
    else {
      auto& ecsIdx = map->d_ecsIndex.get<HashedTag>();
      auto ecsIndexRange = ecsIdx.equal_range(tie(name, qtype));
      ecsIdx.erase(ecsIndexRange.first, ecsIndexRange.second);
    }
  }
  else {
    for (auto& lockGuardedMap : d_maps) {
      auto map = lock(lockGuardedMap);
      map->d_cachecachevalid = false;
      auto& idx = map->d_map.get<OrderedTag>();
      for (auto i = idx.lower_bound(name); i != idx.end(); ) {
        if (!i->d_qname.isPartOf(name))
          break;
        if (i->d_qtype == qtype || qtype == 0xffff) {
          count++;
          i = idx.erase(i);
          map->d_entriesCount--;
        } else {
          ++i;
        }
      }
      auto& ecsIdx = map->d_ecsIndex.get<OrderedTag>();
      for (auto i = ecsIdx.lower_bound(name); i != ecsIdx.end(); ) {
        if (!i->d_qname.isPartOf(name))
          break;
        if (i->d_qtype == qtype || qtype == 0xffff) {
          i = ecsIdx.erase(i);
        } else {
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
  auto& lockGuardedMap = getMap(name);
  auto map = lock(lockGuardedMap);
  cache_t::iterator iter = map->d_map.find(tie(name, qtype));
  if (iter == map->d_map.end()) {
    return false;
  }

  CacheEntry ce = *iter;
  if (ce.d_ttd < now)
    return false;  // would be dead anyhow

  uint32_t maxTTL = static_cast<uint32_t>(ce.d_ttd - now);
  if (maxTTL > newTTL) {
    map->d_cachecachevalid = false;

    time_t newTTD = now + newTTL;

    if (ce.d_ttd > newTTD) {
      ce.d_ttd = newTTD;
      map->d_map.replace(iter, ce);
    }
    return true;
  }
  return false;
}

bool MemRecursorCache::updateValidationStatus(time_t now, const DNSName &qname, const QType qt, const ComboAddress& who, const OptTag& routingTag, bool requireAuth, vState newState, boost::optional<time_t> capTTD)
{
  uint16_t qtype = qt.getCode();
  if (qtype == QType::ANY) {
    throw std::runtime_error("Trying to update the DNSSEC validation status of all (via ANY) records for " + qname.toLogString());
  }
  if (qtype == QType::ADDR) {
    throw std::runtime_error("Trying to update the DNSSEC validation status of several (via ADDR) records for " + qname.toLogString());
  }

  auto& lockGuardedMap = getMap(qname);
  auto map = lock(lockGuardedMap);

  bool updated = false;
  if (!map->d_ecsIndex.empty() && !routingTag) {
    auto entry = getEntryUsingECSIndex(*map, now, qname, qtype, requireAuth, who);
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

  for(auto i = entries.first; i != entries.second; ++i) {
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

uint64_t MemRecursorCache::doDump(int fd)
{
  int newfd = dup(fd);
  if (newfd == -1) {
    return 0;
  }
  auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fdopen(newfd, "w"), fclose);
  if(!fp) { // dup probably failed
    close(newfd);
    return 0;
  }

  fprintf(fp.get(), "; main record cache dump follows\n;\n");
  uint64_t count = 0;

  for (auto& lockGuardedMap : d_maps) {
    auto map = lock(lockGuardedMap);
    const auto& sidx = map->d_map.get<SequencedTag>();

    time_t now = time(nullptr);
    for (const auto& i : sidx) {
      for (const auto& j : i.d_records) {
        count++;
        try {
          fprintf(fp.get(), "%s %" PRIu32 " %" PRId64 " IN %s %s ; (%s) auth=%i zone=%s from=%s %s %s\n", i.d_qname.toString().c_str(), i.d_orig_ttl, static_cast<int64_t>(i.d_ttd - now), i.d_qtype.toString().c_str(), j->getZoneRepresentation().c_str(), vStateToString(i.d_state).c_str(), i.d_auth, i.d_authZone.toLogString().c_str(), i.d_from.toString().c_str(), i.d_netmask.empty() ? "" : i.d_netmask.toString().c_str(), !i.d_rtag ? "" : i.d_rtag.get().c_str());
        }
        catch(...) {
          fprintf(fp.get(), "; error printing '%s'\n", i.d_qname.empty() ? "EMPTY" : i.d_qname.toString().c_str());
        }
      }
      for (const auto &sig : i.d_signatures) {
        count++;
        try {
          fprintf(fp.get(), "%s %" PRIu32 " %" PRId64 " IN RRSIG %s ; %s\n", i.d_qname.toString().c_str(), i.d_orig_ttl, static_cast<int64_t>(i.d_ttd - now), sig->getZoneRepresentation().c_str(), i.d_netmask.empty() ? "" : i.d_netmask.toString().c_str());
        }
        catch(...) {
          fprintf(fp.get(), "; error printing '%s'\n", i.d_qname.empty() ? "EMPTY" : i.d_qname.toString().c_str());
        }
      }
    }
  }
  return count;
}

void MemRecursorCache::doPrune(size_t keep)
{
  //size_t maxCached = d_maxEntries;
  size_t cacheSize = size();
  pruneMutexCollectionsVector<SequencedTag>(*this, d_maps, keep, cacheSize);
}

namespace boost {
  size_t hash_value(const MemRecursorCache::OptTag& o)
  {
    return o ? hash_value(o.get()) : 0xcafebaaf;
  }
}
